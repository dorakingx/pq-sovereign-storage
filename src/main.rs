use pqsp_core::{CommitmentSubmission, MockOnChainVerifier, OnChainVerifier, VerifierInput};
use pqsp_crypto::{
    EncryptionKey, MockZkProver, Shake256Committer, XChaCha20Poly1305Encryptor,
};
use pqsp_storage_client::{StorageClient, ZeroGStorageConfig, ZeroGStorageService};
use rand_core::OsRng;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let encryption_key = EncryptionKey::generate(&mut OsRng);
    let encryptor = XChaCha20Poly1305Encryptor::new(encryption_key);
    let committer = Shake256Committer::default();
    let prover = MockZkProver;

    let storage = ZeroGStorageService::new(
        ZeroGStorageConfig::dry_run("galileo-testnet"),
        committer,
        encryptor,
    );

    let plaintext =
        b"Post-quantum sovereign privacy storage bootstrap payload for 0G APAC Hackathon.";
    let aad = b"app=hackathon-demo;tenant=0g-apac-track5";

    let (prepared, upload_receipt) = storage.store(plaintext, aad, &prover).await?;

    let submission = CommitmentSubmission {
        application_id: "pqsp-demo".to_string(),
        verifier_input: VerifierInput {
            proof_statement: prepared.proof_statement.clone(),
            proof: prepared.proof.clone(),
            storage: upload_receipt.storage.clone(),
        },
        submitter: Some("demo-runner".to_string()),
        memo: Some("bootstrap dry-run execution".to_string()),
    };

    let verifier = MockOnChainVerifier::default();
    let verifier_receipt = verifier.submit(&submission).await?;

    println!("Upload payload summary:");
    println!(
        "{}",
        serde_json::to_string_pretty(&prepared.upload_payload.summary())?
    );
    println!();

    println!("Upload receipt:");
    println!("{}", serde_json::to_string_pretty(&upload_receipt)?);
    println!();

    println!("Verifier receipt:");
    println!("{}", serde_json::to_string_pretty(&verifier_receipt)?);

    Ok(())
}
