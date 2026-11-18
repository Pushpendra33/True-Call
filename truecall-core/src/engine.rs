use crate::approval::{Decision, SignedApproval};
use crate::directory::ApproverDirectory;
use crate::log::AuditLog;
use crate::request::PaymentRequest;
use crate::vendors::{VendorRegistry, VendorStatus};
use k256::schnorr::SigningKey;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub success: bool,
    pub title: String,
    pub details: String,
    pub vendor_status: VendorStatus,
}

pub struct TrueCallEngine {
    pub directory: ApproverDirectory,
    pub vendors: VendorRegistry,
    pub audit_log: AuditLog,
    pub device_key: SigningKey,
    pub used_nonces: HashSet<String>,
}

impl TrueCallEngine {
    pub fn new(directory: ApproverDirectory, vendors: VendorRegistry, device_key: SigningKey) -> Self {
        Self {
            directory,
            vendors,
            audit_log: AuditLog::new(),
            device_key,
            used_nonces: HashSet::new(),
        }
    }

    /// Step 1: Prime inspects payment request & validates beneficiary against vendor database
    pub fn inspect_request(&self, request: &PaymentRequest) -> VendorStatus {
        self.vendors.verify_beneficiary(&request.beneficiary_name, &request.beneficiary_account)
    }

    /// Step 2: Approver reviews and signs on Passport Prime
    pub fn sign_decision(
        &mut self,
        request: &PaymentRequest,
        decision: Decision,
        approver_key: &SigningKey,
        timestamp: u64,
    ) -> SignedApproval {
        let req_hash = request.request_hash();
        let approval = SignedApproval::sign(
            request.request_id.clone(),
            &req_hash,
            decision,
            approver_key,
            timestamp,
        );

        let action = format!("DEVICE_{}", decision);
        let status = match decision {
            Decision::Approved => "USER_CONFIRMED".to_string(),
            Decision::Rejected => "USER_REJECTED".to_string(),
        };

        self.audit_log.append(
            request.request_id.clone(),
            request.amount_cents,
            request.beneficiary_name.clone(),
            approval.approver_pubkey_hex.clone(),
            action,
            status,
            timestamp,
            &self.device_key,
        );

        approval
    }

    /// Step 3: Finance verifier checks signature, directory enrolment, fields, and policy
    pub fn verify_and_release(
        &mut self,
        request: &PaymentRequest,
        approvals: &[SignedApproval],
        current_time: u64,
    ) -> VerificationResult {
        let vendor_status = self.vendors.verify_beneficiary(&request.beneficiary_name, &request.beneficiary_account);

        // Check 1: Expiry
        if current_time > request.expires_at {
            self.audit_log.append(
                request.request_id.clone(),
                request.amount_cents,
                request.beneficiary_name.clone(),
                "none".to_string(),
                "VERIFY_FAILED".to_string(),
                "EXPIRED_REQUEST".to_string(),
                current_time,
                &self.device_key,
            );
            return VerificationResult {
                success: false,
                title: "REJECTED: Request Expired".to_string(),
                details: format!("Payment request expired at timestamp {}. Current time is {}.", request.expires_at, current_time),
                vendor_status,
            };
        }

        // Check 2: Nonce reuse (replay attack)
        if self.used_nonces.contains(&request.nonce) {
            self.audit_log.append(
                request.request_id.clone(),
                request.amount_cents,
                request.beneficiary_name.clone(),
                "none".to_string(),
                "VERIFY_FAILED".to_string(),
                "REPLAY_NONCE_REUSED".to_string(),
                current_time,
                &self.device_key,
            );
            return VerificationResult {
                success: false,
                title: "REJECTED: Replay Attack (Nonce Reused)".to_string(),
                details: format!("Nonce '{}' has already been used for a previous payment.", request.nonce),
                vendor_status,
            };
        }

        // Check 3: At least one approval provided
        if approvals.is_empty() {
            return VerificationResult {
                success: false,
                title: "REJECTED: No Approvals".to_string(),
                details: "Payment requires at least one enrolled approver signature.".to_string(),
                vendor_status,
            };
        }

        let expected_hash_hex = request.request_hash_hex();
        let mut valid_approvers = Vec::new();

        for app in approvals {
            // Check cryptographic Schnorr signature
            if let Err(e) = app.verify() {
                self.audit_log.append(
                    request.request_id.clone(),
                    request.amount_cents,
                    request.beneficiary_name.clone(),
                    app.approver_pubkey_hex.clone(),
                    "VERIFY_FAILED".to_string(),
                    format!("INVALID_SIGNATURE: {}", e),
                    current_time,
                    &self.device_key,
                );
                return VerificationResult {
                    success: false,
                    title: "REJECTED: Cryptographic Signature Invalid".to_string(),
                    details: format!("BIP340 Schnorr signature failed verification: {}", e),
                    vendor_status,
                };
            }

            // Check field hash match (What You See Is What You Sign)
            if app.request_hash_hex != expected_hash_hex {
                self.audit_log.append(
                    request.request_id.clone(),
                    request.amount_cents,
                    request.beneficiary_name.clone(),
                    app.approver_pubkey_hex.clone(),
                    "VERIFY_FAILED".to_string(),
                    "HASH_MISMATCH_TAMPERED_FIELDS".to_string(),
                    current_time,
                    &self.device_key,
                );
                return VerificationResult {
                    success: false,
                    title: "REJECTED: Payment Fields Tampered".to_string(),
                    details: "The signature was made for a different amount, account, or currency than what is being released!".to_string(),
                    vendor_status,
                };
            }

            // Check decision
            if app.decision != Decision::Approved {
                self.audit_log.append(
                    request.request_id.clone(),
                    request.amount_cents,
                    request.beneficiary_name.clone(),
                    app.approver_pubkey_hex.clone(),
                    "VERIFY_FAILED".to_string(),
                    "APPROVER_EXPLICITLY_REJECTED".to_string(),
                    current_time,
                    &self.device_key,
                );
                return VerificationResult {
                    success: false,
                    title: "REJECTED: Approver Declined Payment".to_string(),
                    details: format!("Approver with pubkey {} explicitly clicked REJECT on Passport Prime.", &app.approver_pubkey_hex[..8]),
                    vendor_status,
                };
            }

            // Check directory enrolment
            let Some(enrolled) = self.directory.get_approver(&app.approver_pubkey_hex) else {
                self.audit_log.append(
                    request.request_id.clone(),
                    request.amount_cents,
                    request.beneficiary_name.clone(),
                    app.approver_pubkey_hex.clone(),
                    "VERIFY_FAILED".to_string(),
                    "UNENROLLED_KEY_ATTACK".to_string(),
                    current_time,
                    &self.device_key,
                );
                return VerificationResult {
                    success: false,
                    title: "REJECTED: Key Not Enrolled in Company Directory".to_string(),
                    details: format!("Signer {} is not in the signed approver directory! Deepfake impersonation prevented.", &app.approver_pubkey_hex[..8]),
                    vendor_status,
                };
            };

            valid_approvers.push(enrolled.clone());
        }

        // Check 4: Policy Limits
        // Single approver limit check
        for approver in &valid_approvers {
            if request.amount_cents > approver.max_single_limit_cents && valid_approvers.len() < 2 {
                return VerificationResult {
                    success: false,
                    title: "REJECTED: Exceeds Single Approver Limit".to_string(),
                    details: format!("Amount {} exceeds {}'s single authority limit of ${}. Dual approval required.",
                        request.formatted_amount(), approver.name, approver.max_single_limit_cents / 100),
                    vendor_status,
                };
            }
        }

        // Dual approval threshold check (e.g. > $200k requires 2 signers)
        if request.amount_cents > 20_000_000 && valid_approvers.len() < 2 {
            return VerificationResult {
                success: false,
                title: "REJECTED: High-Value Dual Approval Policy".to_string(),
                details: format!("Payments over $200,000.00 require at least two distinct enrolled approvers. Got {}.", valid_approvers.len()),
                vendor_status,
            };
        }

        // Success! Record nonce and log release
        self.used_nonces.insert(request.nonce.clone());

        self.audit_log.append(
            request.request_id.clone(),
            request.amount_cents,
            request.beneficiary_name.clone(),
            valid_approvers[0].pubkey_hex.clone(),
            "PAYMENT_RELEASED".to_string(),
            format!("APPROVED_BY_{}_SIGNERS", valid_approvers.len()),
            current_time,
            &self.device_key,
        );

        VerificationResult {
            success: true,
            title: "✅ PAYMENT RELEASED".to_string(),
            details: format!(
                "Successfully verified {} to {} (Account {}). Cryptographic signatures valid across {} enrolled officer(s).",
                request.formatted_amount(),
                request.beneficiary_name,
                request.beneficiary_account,
                valid_approvers.len()
            ),
            vendor_status,
        }
    }
}

