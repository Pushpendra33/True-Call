use k256::schnorr::SigningKey;
use truecall_core::{
    approval::{Decision, SignedApproval},
    directory::{ApproverDirectory, EnrolledApprover},
    engine::TrueCallEngine,
    request::PaymentRequest,
    vendors::{VendorRegistry, VendorStatus},
};

fn gen_key() -> (SigningKey, String) {
    let mut s = [0u8; 32];
    getrandom::getrandom(&mut s).unwrap();
    let sk = SigningKey::from_bytes(&s).unwrap();
    let pk = hex::encode(sk.verifying_key().to_bytes());
    (sk, pk)
}

#[test]
fn test_canonical_request_hash_deterministic() {
    let r1 = PaymentRequest {
        request_id: "REQ-01".to_string(),
        amount_cents: 100000,
        currency: "USD".to_string(),
        beneficiary_name: "Acme Corp".to_string(),
        beneficiary_account: "US123456789".to_string(),
        reference: "INV-1".to_string(),
        requested_by: "Alice".to_string(),
        nonce: "NONCE-1".to_string(),
        expires_at: 1800000000,
    };
    let r2 = r1.clone();
    assert_eq!(r1.request_hash(), r2.request_hash());

    let mut r3 = r1.clone();
    r3.amount_cents = 100001; // Change by 1 cent!
    assert_ne!(r1.request_hash(), r3.request_hash());
}

#[test]
fn test_schnorr_approval_signing_and_verification() {
    let (sk, pk) = gen_key();
    let req = PaymentRequest {
        request_id: "REQ-01".to_string(),
        amount_cents: 50000,
        currency: "USD".to_string(),
        beneficiary_name: "Acme".to_string(),
        beneficiary_account: "US999".to_string(),
        reference: "REF".to_string(),
        requested_by: "Bob".to_string(),
        nonce: "N1".to_string(),
        expires_at: 2000000000,
    };

    let app = SignedApproval::sign(req.request_id.clone(), &req.request_hash(), Decision::Approved, &sk, 1700000000);
    assert_eq!(app.approver_pubkey_hex, pk);
    assert!(app.verify().is_ok());

    // Tampering test: edit request hash
    let mut bad_app = app.clone();
    bad_app.request_hash_hex = "00".repeat(32);
    assert!(bad_app.verify().is_err());
}

#[test]
fn test_vendor_swapped_account_detection() {
    let mut reg = VendorRegistry::new();
    reg.register("Crown Steel", "HK12345");

    // Exact match
    let res_ok = reg.verify_beneficiary("Crown Steel", "HK12345");
    assert!(matches!(res_ok, VendorStatus::VerifiedKnown { .. }));

    // Swapped bank account (Invoice fraud attempt!)
    let res_swapped = reg.verify_beneficiary("Crown Steel", "HK99999");
    match res_swapped {
        VendorStatus::AccountSwapped { vendor_name, expected_account, claimed_account } => {
            assert_eq!(vendor_name, "Crown Steel");
            assert_eq!(expected_account, "HK12345");
            assert_eq!(claimed_account, "HK99999");
        }
        _ => panic!("Expected AccountSwapped"),
    }
}

#[test]
fn test_full_engine_arup_attack_lab() {
    let (admin_sk, admin_pk) = gen_key();
    let (cfo_sk, cfo_pk) = gen_key();
    let (attacker_sk, _attacker_pk) = gen_key();
    let (dev_sk, _dev_pk) = gen_key();
    let dev_vk = *dev_sk.verifying_key();

    let mut dir = ApproverDirectory::new("Arup".to_string(), admin_pk);
    dir.add_approver(EnrolledApprover {
        name: "CFO".to_string(),
        role: "CFO".to_string(),
        pubkey_hex: cfo_pk.clone(),
        max_single_limit_cents: 100_000_000,
        requires_dual_above_cents: 20_000_000,
    });
    let mut aux = [0u8; 32];
    getrandom::getrandom(&mut aux).unwrap();
    let sig = admin_sk.sign_raw(&dir.directory_hash(), &aux).unwrap();
    dir.admin_sig_hex = hex::encode(sig.to_bytes());

    let mut reg = VendorRegistry::new();
    reg.register("Supplier A", "ACC-111");

    let mut engine = TrueCallEngine::new(dir, reg, dev_sk);
    let now = 1700000000u64;

    let req = PaymentRequest {
        request_id: "REQ-1".to_string(),
        amount_cents: 5_000_000,
        currency: "USD".to_string(),
        beneficiary_name: "Supplier A".to_string(),
        beneficiary_account: "ACC-111".to_string(),
        reference: "INV-1".to_string(),
        requested_by: "Desk".to_string(),
        nonce: "NONCE-1".to_string(),
        expires_at: now + 3600,
    };

    // Attack 1: Unenrolled Attacker Key
    let att1_app = engine.sign_decision(&req, Decision::Approved, &attacker_sk, now);
    let att1_res = engine.verify_and_release(&req, &[att1_app], now);
    assert!(!att1_res.success);
    assert!(att1_res.details.contains("not in the signed approver directory"));

    // Attack 2: Replay Attack (Nonce reuse)
    let good_app = engine.sign_decision(&req, Decision::Approved, &cfo_sk, now);
    let good_res = engine.verify_and_release(&req, &[good_app.clone()], now);
    assert!(good_res.success);

    // Try to reuse nonce
    let replay_res = engine.verify_and_release(&req, &[good_app], now);
    assert!(!replay_res.success);
    assert!(replay_res.title.contains("Replay Attack"));

    // Verify audit log integrity
    assert!(engine.audit_log.verify_chain(&dev_vk).is_ok());
}
