use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VendorStatus {
    /// Account matches known vendor in registry (Green)
    VerifiedKnown { vendor_name: String },
    /// Vendor name exists, but bank account has changed! (CRITICAL RED ALERT: Invoice fraud)
    AccountSwapped {
        vendor_name: String,
        expected_account: String,
        claimed_account: String,
    },
    /// Vendor is completely unrecognized / first-time payee (Amber/Red warning)
    UnregisteredVendor { claimed_name: String, claimed_account: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorRegistry {
    /// Maps normalized vendor name -> verified bank account / IBAN
    vendors: HashMap<String, String>,
}

impl VendorRegistry {
    pub fn new() -> Self {
        Self {
            vendors: HashMap::new(),
        }
    }

    pub fn register(&mut self, name: &str, account: &str) {
        self.vendors.insert(name.trim().to_lowercase(), account.trim().to_uppercase());
    }

    /// Check a requested payment against the trusted vendor registry
    pub fn verify_beneficiary(&self, name: &str, account: &str) -> VendorStatus {
        let norm_name = name.trim().to_lowercase();
        let norm_account = account.trim().to_uppercase();

        if let Some(expected) = self.vendors.get(&norm_name) {
            if expected == &norm_account {
                VendorStatus::VerifiedKnown {
                    vendor_name: name.trim().to_string(),
                }
            } else {
                VendorStatus::AccountSwapped {
                    vendor_name: name.trim().to_string(),
                    expected_account: expected.clone(),
                    claimed_account: norm_account,
                }
            }
        } else {
            VendorStatus::UnregisteredVendor {
                claimed_name: name.trim().to_string(),
                claimed_account: norm_account,
            }
        }
    }
}

