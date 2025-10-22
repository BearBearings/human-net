use std::collections::HashMap;

use anyhow::Result;
use hn_cli::identity::{BuiltinVerifier, IdentityVault, VerificationRequest};

#[test]
fn mock_entra_roundtrip_persists_and_reloads() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let vault = IdentityVault::new(temp.path().to_path_buf())?;
    let record = vault.create_identity("alice", Vec::new(), HashMap::new())?;
    let mut mutable = vault.load_identity(&record.profile.alias)?;

    let verifier = BuiltinVerifier::MockEntra.build();
    let request =
        VerificationRequest::new(mutable.profile.alias.clone(), mutable.profile.id.clone());
    let result = verifier.verify(&request)?;
    assert!(result.refreshed, "expected initial verification to refresh");
    vault.record_verification(&mut mutable, result.entry.clone(), result.proof.clone())?;

    let reloaded = vault.load_identity(&mutable.profile.alias)?;
    let stored = reloaded
        .profile
        .verification
        .entry("mock-entra")
        .expect("verification entry stored");
    assert_eq!(stored.provider, "mock-entra");
    assert_eq!(stored.issuer, "https://entra.mock/human-net");
    assert!(stored.proof_id.starts_with("proof:mock-entra"));
    let proofs = vault.list_proofs_for(&mutable.profile.alias)?;
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].id, stored.proof_id);
    assert!(reloaded.profile.verification.last_refreshed_at.is_some());
    Ok(())
}

#[test]
fn force_refresh_bypass_cache() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let vault = IdentityVault::new(temp.path().to_path_buf())?;
    let record = vault.create_identity("bob", Vec::new(), HashMap::new())?;
    let mut mutable = vault.load_identity(&record.profile.alias)?;

    let verifier = BuiltinVerifier::MockEntra.build();
    let request =
        VerificationRequest::new(mutable.profile.alias.clone(), mutable.profile.id.clone());
    let result = verifier.verify(&request)?;
    vault.record_verification(&mut mutable, result.entry.clone(), result.proof.clone())?;

    let cached = mutable
        .profile
        .verification
        .entry("mock-entra")
        .cloned()
        .expect("cached entry");

    let verifier = BuiltinVerifier::MockEntra.build();
    let cached_request =
        VerificationRequest::new(mutable.profile.alias.clone(), mutable.profile.id.clone())
            .with_existing(Some(cached.clone()));
    let cached_result = verifier.verify(&cached_request)?;
    assert!(
        !cached_result.refreshed,
        "expected cached verification to reuse entry"
    );

    let verifier = BuiltinVerifier::MockEntra.build();
    let forced_request =
        VerificationRequest::new(mutable.profile.alias.clone(), mutable.profile.id.clone())
            .with_existing(Some(cached))
            .force_refresh(true);
    let forced_result = verifier.verify(&forced_request)?;
    assert!(
        forced_result.refreshed,
        "expected force refresh to produce new entry"
    );
    assert!(
        forced_result.proof.is_some(),
        "force refresh should produce a new proof artifact"
    );
    vault.record_verification(
        &mut mutable,
        forced_result.entry.clone(),
        forced_result.proof.clone(),
    )?;
    let updated_proofs = vault.list_proofs_for(&mutable.profile.alias)?;
    assert!(updated_proofs.len() >= 1);
    Ok(())
}
