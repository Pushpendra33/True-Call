use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

/// Canonical payment request presented on Passport Prime trusted screen
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentRequest {
    pub request_id: String,
    pub amount_cents: u64,
    pub currency: String,
    pub beneficiary_name: String,
    pub beneficiary_account: String,
    pub reference: String,
    pub requested_by: String,
    pub nonce: String,
    pub expires_at: u64,
}

impl PaymentRequest {
    /// Format amount for display, e.g. 25000000 -> "$250,000.00"
    pub fn formatted_amount(&self) -> String {
        let dollars = self.amount_cents / 100;
        let cents = self.amount_cents % 100;
        let s = dollars.to_string();
        let mut formatted_dollars = String::new();
        let chars: Vec<char> = s.chars().collect();
        let len = chars.len();
        for (i, c) in chars.into_iter().enumerate() {
            if i > 0 && (len - i) % 3 == 0 {
                formatted_dollars.push(',');
            }
            formatted_dollars.push(c);
        }
        format!("{} {}.{:02}", self.currency, formatted_dollars, cents)
    }

    /// Canonical bytes encoding: binds every single field
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"TRUECALL-PAYMENT-V1\n");
        out.extend_from_slice(self.request_id.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.amount_cents.to_string().as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.currency.to_uppercase().as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.beneficiary_name.trim().as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.beneficiary_account.trim().as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.reference.trim().as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.requested_by.trim().as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.nonce.trim().as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.expires_at.to_string().as_bytes());
        out
    }

    /// BIP340-style tagged hash: sha256(sha256(tag) || sha256(tag) || msg)
    pub fn request_hash(&self) -> [u8; 32] {
        let tag = "TrueCall/request/v1";
        let mut h_tag = Sha256::new();
        h_tag.update(tag.as_bytes());
        let tag_digest = h_tag.finalize();

        let mut hasher = Sha256::new();
        hasher.update(&tag_digest);
        hasher.update(&tag_digest);
        hasher.update(&self.canonical_bytes());
        let res = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res);
        out
    }

    pub fn request_hash_hex(&self) -> String {
        hex::encode(self.request_hash())
    }

    /// Encode request as QR payload
    pub fn to_qr_payload(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

