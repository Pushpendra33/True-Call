use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub sequence: u64,
    pub request_id: String,
    pub amount_cents: u64,
    pub beneficiary: String,
    pub approver_pubkey_hex: String,
    pub action: String, // "APPROVED", "REJECTED", "ATTACK_BLOCKED"
    pub status: String,
    pub prev_hash_hex: String,
    pub timestamp: u64,
    pub device_sig_hex: String,
}

impl LogEntry {
    pub fn entry_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"TRUECALL-LOG-ENTRY-V1\n");
        out.extend_from_slice(self.sequence.to_string().as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.request_id.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.amount_cents.to_string().as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.beneficiary.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.approver_pubkey_hex.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.action.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.status.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.prev_hash_hex.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.timestamp.to_string().as_bytes());
        out
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.entry_bytes());
        let res = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res);
        out
    }

    pub fn sign_entry(&mut self, device_key: &SigningKey) {
        let digest = self.compute_hash();
        let mut aux = [0u8; 32];
        getrandom::getrandom(&mut aux).expect("hardware RNG failure");
        let sig = device_key.sign_raw(&digest, &aux).expect("signing failed");
        self.device_sig_hex = hex::encode(sig.to_bytes());
    }

    pub fn verify_entry(&self, device_vk: &VerifyingKey) -> Result<(), &'static str> {
        let digest = self.compute_hash();
        let sig_bytes = hex::decode(&self.device_sig_hex).map_err(|_| "Invalid sig hex")?;
        let sig = Signature::try_from(sig_bytes.as_slice()).map_err(|_| "Malformed log signature")?;
        device_vk.verify_raw(&digest, &sig).map_err(|_| "Log entry signature mismatch")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub entries: Vec<LogEntry>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn append(
        &mut self,
        request_id: String,
        amount_cents: u64,
        beneficiary: String,
        approver_pubkey_hex: String,
        action: String,
        status: String,
        timestamp: u64,
        device_key: &SigningKey,
    ) -> &LogEntry {
        let prev_hash_hex = if let Some(last) = self.entries.last() {
            hex::encode(last.compute_hash())
        } else {
            "00".repeat(32)
        };

        let mut entry = LogEntry {
            sequence: self.entries.len() as u64,
            request_id,
            amount_cents,
            beneficiary,
            approver_pubkey_hex,
            action,
            status,
            prev_hash_hex,
            timestamp,
            device_sig_hex: String::new(),
        };

        entry.sign_entry(device_key);
        self.entries.push(entry);
        self.entries.last().unwrap()
    }

    pub fn verify_chain(&self, device_vk: &VerifyingKey) -> Result<(), &'static str> {
        let mut expected_prev = "00".repeat(32);
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.sequence != i as u64 {
                return Err("Log sequence out of order");
            }
            if entry.prev_hash_hex != expected_prev {
                return Err("Log hash chain broken / tampered");
            }
            entry.verify_entry(device_vk)?;
            expected_prev = hex::encode(entry.compute_hash());
        }
        Ok(())
    }
}

