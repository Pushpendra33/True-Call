use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Approved,
    Rejected,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Approved => write!(f, "APPROVED"),
            Decision::Rejected => write!(f, "REJECTED"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedApproval {
    pub request_id: String,
    pub request_hash_hex: String,
    pub decision: Decision,
    pub approver_pubkey_hex: String,
    pub signature_hex: String,
    pub signed_at: u64,
}

impl SignedApproval {
    /// Compute the message digest to be signed: tagged hash over request_hash + decision
    pub fn approval_digest(request_hash: &[u8; 32], decision: Decision) -> [u8; 32] {
        let tag = "TrueCall/approval/v1";
        let mut h_tag = Sha256::new();
        h_tag.update(tag.as_bytes());
        let tag_digest = h_tag.finalize();

        let mut hasher = Sha256::new();
        hasher.update(&tag_digest);
        hasher.update(&tag_digest);
        hasher.update(request_hash);
        match decision {
            Decision::Approved => hasher.update(b"\x01APPROVED"),
            Decision::Rejected => hasher.update(b"\x00REJECTED"),
        }
        let res = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res);
        out
    }

    /// Sign on Passport Prime with enrolled hardware key
    pub fn sign(
        request_id: String,
        request_hash: &[u8; 32],
        decision: Decision,
        signing_key: &SigningKey,
        signed_at: u64,
    ) -> Self {
        let digest = Self::approval_digest(request_hash, decision);
        let mut aux = [0u8; 32];
        getrandom::getrandom(&mut aux).expect("hardware RNG failure");
        let sig = signing_key.sign_raw(&digest, &aux).expect("signing failed");
        let vk = signing_key.verifying_key();

        Self {
            request_id,
            request_hash_hex: hex::encode(request_hash),
            decision,
            approver_pubkey_hex: hex::encode(vk.to_bytes()),
            signature_hex: hex::encode(sig.to_bytes()),
            signed_at,
        }
    }

    /// Verify signature on Finance Verifier
    pub fn verify(&self) -> Result<(), &'static str> {
        let req_hash_bytes = hex::decode(&self.request_hash_hex).map_err(|_| "Invalid request hash hex")?;
        if req_hash_bytes.len() != 32 {
            return Err("Request hash length must be 32 bytes");
        }
        let mut req_hash = [0u8; 32];
        req_hash.copy_from_slice(&req_hash_bytes);

        let digest = Self::approval_digest(&req_hash, self.decision);
        let pub_bytes = hex::decode(&self.approver_pubkey_hex).map_err(|_| "Invalid approver pubkey hex")?;
        let vk = VerifyingKey::from_bytes(&pub_bytes).map_err(|_| "Invalid verifying key")?;
        let sig_bytes = hex::decode(&self.signature_hex).map_err(|_| "Invalid signature hex")?;
        let sig = Signature::try_from(sig_bytes.as_slice()).map_err(|_| "Malformed Schnorr signature")?;

        vk.verify_raw(&digest, &sig).map_err(|_| "BIP340 Schnorr signature verification failed")?;
        Ok(())
    }

    /// Convert to compact QR string: TRUECALL1:<req_id>:<req_hash>:<pubkey>:<decision>:<sig>:<timestamp>
    pub fn to_qr_string(&self) -> String {
        format!(
            "TRUECALL1:{}:{}:{}:{}:{}:{}",
            self.request_id,
            self.request_hash_hex,
            self.approver_pubkey_hex,
            self.decision,
            self.signature_hex,
            self.signed_at
        )
    }

    /// Parse compact QR string
    pub fn from_qr_string(qr: &str) -> Result<Self, &'static str> {
        let parts: Vec<&str> = qr.split(':').collect();
        if parts.len() != 7 || parts[0] != "TRUECALL1" {
            return Err("Invalid TrueCall QR format");
        }
        let decision = match parts[4] {
            "APPROVED" => Decision::Approved,
            "REJECTED" => Decision::Rejected,
            _ => return Err("Invalid decision in QR"),
        };
        let signed_at = parts[6].parse::<u64>().map_err(|_| "Invalid timestamp in QR")?;

        Ok(Self {
            request_id: parts[1].to_string(),
            request_hash_hex: parts[2].to_string(),
            approver_pubkey_hex: parts[3].to_string(),
            decision,
            signature_hex: parts[5].to_string(),
            signed_at,
        })
    }
}

