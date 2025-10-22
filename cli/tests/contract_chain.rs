use std::path::PathBuf;

use anyhow::Result;
use hn_cli::contract::{Contract, ContractState, Offer};
use time::OffsetDateTime;

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

#[test]
fn alice_bob_sample_contract_validates() -> Result<()> {
    let offer = Offer::from_path(&fixture("../samples/contracts/offer-alice-bob.json"))?;
    assert!(offer.digest_matches()?);

    let contract = Contract::from_path(&fixture("../samples/contracts/contract-alice-bob.json"))?;
    let report = contract.verify_against(&offer);
    assert!(report.success());
    Ok(())
}

#[test]
fn fulfilment_produces_shard() -> Result<()> {
    let mut contract =
        Contract::from_path(&fixture("../samples/contracts/contract-alice-bob.json"))?;
    contract.state = ContractState::Accepted;
    contract.state_history.truncate(1);
    if let Some(entry) = contract.state_history.first_mut() {
        entry.state = ContractState::Accepted;
    }
    let payload = b"sample payload";
    let timestamp = OffsetDateTime::now_utc();
    let (fulfilled, shard) = contract.fulfill(payload, &contract.issuer.did, timestamp)?;

    assert_eq!(fulfilled.state, ContractState::Fulfilled);
    let envelope = fulfilled
        .encrypted_payload
        .expect("encrypted payload present");
    assert_eq!(envelope.cid, shard.payload_cid);
    assert_eq!(envelope.hpke_suite, "X25519HkdfSha256+ChaCha20Poly1305");
    assert!(envelope.ciphertext.len() > 32);
    assert!(envelope.enc.len() > 16);
    assert_eq!(shard.contract_id, contract.id);
    assert!(shard.ciphertext.len() > 32);
    assert!(shard.enc.len() > 16);
    Ok(())
}
