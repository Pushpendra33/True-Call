use k256::schnorr::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolledApprover {
    pub name: String,
    pub role: String,
    pub pubkey_hex: String,
    pub max_single_limit_cents: u64, // e.g. $1,000,000.00
    pub requires_dual_above_cents: u64, // e.g. payments > $200,000 need 2 signers
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverDirectory {
    pub company_id: String,
    pub admin_pubkey_hex: String,
    pub approvers: Vec<EnrolledApprover>,
    pub admin_sig_hex: String,
}

impl ApproverDirectory {
    pub fn new(company_id: String, admin_pubkey_hex: String) -> Self {
        Self {
            company_id,
            admin_pubkey_hex,
            approvers: Vec::new(),
            admin_sig_hex: String::new(),
        }
    }

    pub fn add_approver(&mut self, approver: EnrolledApprover) {
        self.approvers.push(approver);
    }

    pub fn directory_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"TRUECALL-DIRECTORY-V1\n");
        out.extend_from_slice(self.company_id.as_bytes());
        out.push(b'\n');
        for a in &self.approvers {
            out.extend_from_slice(a.name.as_bytes());
            out.push(b':');
            out.extend_from_slice(a.role.as_bytes());
            out.push(b':');
            out.extend_from_slice(a.pubkey_hex.to_lowercase().as_bytes());
            out.push(b':');
            out.extend_from_slice(a.max_single_limit_cents.to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(a.requires_dual_above_cents.to_string().as_bytes());
            out.push(b'\n');
        }
        out
    }

    pub fn directory_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.directory_bytes());
        let res = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res);
        out
    }

    pub fn is_enrolled(&self, pubkey_hex: &str) -> bool {
        let target = pubkey_hex.to_lowercase();
        self.approvers.iter().any(|a| a.pubkey_hex.to_lowercase() == target)
    }

    pub fn get_approver(&self, pubkey_hex: &str) -> Option<&EnrolledApprover> {
        let target = pubkey_hex.to_lowercase();
        self.approvers.iter().find(|a| a.pubkey_hex.to_lowercase() == target)
    }

    pub fn verify_admin_signature(&self) -> Result<(), &'static str> {
        if self.admin_sig_hex.is_empty() {
            return Err("Missing admin signature on directory");
        }
        let pub_bytes = hex::decode(&self.admin_pubkey_hex).map_err(|_| "Invalid admin pubkey hex")?;
        let vk = VerifyingKey::from_bytes(&pub_bytes).map_err(|_| "Invalid admin verifying key")?;
        let sig_bytes = hex::decode(&self.admin_sig_hex).map_err(|_| "Invalid admin sig hex")?;
        let sig = Signature::try_from(sig_bytes.as_slice()).map_err(|_| "Malformed admin signature")?;

        let digest = self.directory_hash();
        vk.verify_raw(&digest, &sig).map_err(|_| "Admin signature verification failed")?;
        Ok(())
    }
}

