# Post-Quantum Sovereign Privacy Storage

[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange?logo=rust)](https://www.rust-lang.org/)
[![Smart Contracts](https://img.shields.io/badge/Smart%20Contracts-Solidity-363636?logo=solidity)](https://soliditylang.org/)
[![0G Storage](https://img.shields.io/badge/Storage-0G%20Network-00D1FF)](https://0g.ai/)
[![Hackathon](https://img.shields.io/badge/0G%20APAC%20Hackathon-Track%205:%20Privacy%20%26%20Sovereign%20Infrastructure-purple)](https://0g.ai/)

Post-Quantum Sovereign Privacy Storage is a hackathon prototype for a future-proof private data layer on 0G. It combines post-quantum-friendly hash commitments, encrypted storage payloads, 0G Storage uploads, and an on-chain verifier registry for auditable activity on 0G Chain.

The project targets the 0G APAC Hackathon Track 5: Privacy & Sovereign Infrastructure.

## What It Does

- Encrypts local files before upload.
- Generates a SHAKE256-based state commitment over the encrypted payload.
- Produces a mock ZK proof bundle for the current demo flow.
- Uploads the final payload to 0G Storage when 0G credentials are configured.
- Downloads encrypted payloads back from 0G Storage by Merkle root.
- Decrypts downloaded payloads with the user-held encryption key.
- Falls back to deterministic dry-run mode when credentials are missing.
- Saves a verification artifact JSON that can be replayed locally.
- Provides a Solidity verifier contract that records accepted commitments on chain.
- Includes an ethers-rs verifier adapter for submitting commitments to the deployed contract.

## Repository Layout

```text
.
├── .env.example                # Safe env template (copy to `.env`, which is gitignored)
├── Cargo.toml                  # Rust workspace and root CLI package
├── core/                       # Verifier-facing protocol types and verifier adapters
├── crypto/                     # Commitments, encryption, and mock ZK traits
├── storage_client/             # 0G Storage upload pipeline and SDK adapter
├── src/main.rs                 # Judge-friendly CLI
└── contracts/                  # Foundry project for PqspVerifier.sol
```

## Architecture

```mermaid
flowchart LR
    User([User])
    CLI["PQSP CLI<br/>Encrypt + PQ Commit + ZK Mock Prove"]
    Storage["0G Storage Network<br/>Encrypted Payload + Merkle Root"]
    Chain["0G Chain<br/>PqspVerifier Registry"]
    Contract["PqspVerifier.sol<br/>Commitment + Storage Root"]
    Recover["PQSP CLI<br/>Download from 0G + Decrypt with Local Key"]
    Plaintext([Recovered Plaintext])

    User -->|"upload FILE"| CLI
    CLI -->|"uploads encrypted payload"| Storage
    Storage -->|"returns storage receipt + Merkle root"| CLI
    CLI -->|"verify receipt"| Chain
    Chain -->|"submitCommitment(...)"| Contract
    User -->|"download MERKLE_ROOT"| Recover
    Storage -->|"encrypted payload"| Recover
    User -->|"KEY_HEX stays local"| Recover
    Recover --> Plaintext
```

The Solidity contract currently mocks ZK verification for demo purposes. It still provides real on-chain verifiable activity by registering state commitments against 0G Storage Merkle roots.

## Prerequisites

- Rust toolchain with `cargo`
- Foundry, if you want to build or deploy the Solidity contract
- A local `.env` file (from `.env.example`) for live 0G uploads, downloads, and on-chain verification

## Environment Setup & Contract Deployment

Judges and contributors should **never** commit real private keys. The repository only contains `.env.example` as a safe template; your real values live in `.env`, which Git ignores at the repository root and under `contracts/`.

### 1. Create your local `.env`

From the repository root:

```bash
cp .env.example .env
```

Edit `.env` on your machine only (do not paste keys into issues, chats, or commits).

### 2. Fund a dedicated testnet wallet and set `0G_PRIVATE_KEY`

1. Create or pick a **hackathon-only** wallet that you do **not** use on mainnet or for real funds.
2. Request **0G testnet** tokens from the official faucet: [0G Testnet Faucet](https://faucet.0g.ai/). For network context, see the [0G testnet overview](https://docs.0g.ai/developer-hub/testnet/testnet-overview).
3. In `.env`, set `0G_PRIVATE_KEY` to the wallet’s hex private key (`0x…` or raw hex). This key signs CLI transactions and Foundry deployments — treat it like a password and keep it out of Git.

### 3. Deploy `PqspVerifier` to 0G testnet (Foundry)

The deploy script reads `0G_PRIVATE_KEY` from the **process environment**. Foundry does not automatically load `.env`, so export variables from your root `.env` in the same shell before running `forge` (the snippet below does that safely from the repo root).

After a successful broadcast, copy the **deployed contract address** from the Foundry output or block explorer and set `PQSP_VERIFIER_CONTRACT_ADDRESS` in your root `.env`. The PQSP CLI’s `verify` command uses that value together with `0G_CHAIN_RPC_URL` and `0G_PRIVATE_KEY` for on-chain verification.

```bash
set -a && source .env && set +a && cd contracts && forge script script/DeployPqspVerifier.s.sol:DeployPqspVerifier --rpc-url https://evmrpc-testnet.0g.ai --broadcast
```

### 4. Behavior without a full `.env`

If required variables are missing, the CLI falls back to dry-run storage and mock verification where applicable. The `download` command needs `0G_STORAGE_NODE_URL`. On-chain `verify` needs `PQSP_VERIFIER_CONTRACT_ADDRESS` plus chain RPC and private key.

### Variable reference

| Variable | Purpose |
| --- | --- |
| `0G_CHAIN_RPC_URL` | 0G Chain EVM JSON-RPC (live uploads, verification, deploy scripts). |
| `0G_PRIVATE_KEY` | Signer for transactions (testnet-only wallet; never mainnet). |
| `0G_STORAGE_NODE_URL` | 0G Storage node for upload and `download`. |
| `PQSP_VERIFIER_CONTRACT_ADDRESS` | Deployed `PqspVerifier` on 0G testnet (paste after deploy). |

## Rust CLI Usage

Build the project:

```bash
cargo build
```

### Seamless Judge Demo Flow

The CLI exposes four commands that form a complete privacy-preserving storage lifecycle:

- `upload`: encrypts a local file, creates a post-quantum state commitment, generates a mock ZK proof bundle, and uploads the encrypted payload to 0G Storage when configured.
- `verify`: replays the saved receipt artifact and submits the commitment plus 0G Storage Merkle root to `PqspVerifier` when EVM configuration is present.
- `download`: fetches the encrypted payload back from a 0G Storage node by Merkle root.
- `decrypt`: recovers plaintext locally with the user-held encryption key.

1. Prepare a sample file:

```bash
echo "sovereign post-quantum storage demo" > example.txt
```

2. Upload the file to create the encrypted storage payload and receipt:

```bash
cargo run -- upload ./example.txt
```

This command:

- reads `example.txt`
- encrypts it
- creates a state commitment
- produces a mock proof
- uploads to 0G Storage if live env vars are present
- otherwise creates a dry-run storage receipt
- writes a verification artifact next to the source file
- prints an encryption key that must be saved for decryption

By default, the artifact path is:

```text
example.txt.pqsp-receipt.json
```

Save two values from this step:

- `KEY_HEX`: printed as `IMPORTANT: Save this encryption key to decrypt your data`
- `MERKLE_ROOT`: found in the upload receipt artifact under `artifact.upload_receipt.storage.merkle_root`

You can choose a custom artifact path:

```bash
cargo run -- upload ./example.txt --out ./receipt.json
```

3. Verify the saved artifact on 0G Chain or in local mock mode:

```bash
cargo run -- verify ./example.txt.pqsp-receipt.json
```

If `0G_CHAIN_RPC_URL`, `0G_PRIVATE_KEY`, and `PQSP_VERIFIER_CONTRACT_ADDRESS` are present, verification submits to the deployed EVM contract. Otherwise it falls back to local mock mode.

4. Download the encrypted payload from 0G Storage:

```bash
cargo run -- download <MERKLE_ROOT>
```

This saves `<MERKLE_ROOT>.json` by default. You can choose a custom output path:

```bash
cargo run -- download <MERKLE_ROOT> --out ./downloaded-payload.json
```

5. Decrypt the downloaded payload with the local key from step 2:

```bash
cargo run -- decrypt <DOWNLOADED_FILE> <KEY_HEX>
```

For example:

```bash
cargo run -- decrypt ./downloaded-payload.json <KEY_HEX> --out ./recovered-example.txt
```

The decrypt command supports both the current 0G upload payload JSON and raw encrypted payload envelope bytes.

6. Confirm the recovered plaintext matches the original file:

```bash
diff ./example.txt ./recovered-example.txt
```

The result is an end-to-end flow where encrypted data lives on 0G Storage, verifiable commitments live on 0G Chain, and the decryption key stays under user control.

## 0G Hackathon Integration Proof

Use this section as the final submission checklist after deploying the verifier and running the live demo flow.

- Deployed `PqspVerifier` contract address: `[INSERT CONTRACT ADDRESS HERE]`
- 0G Chain explorer transaction or contract link: `[INSERT EXPLORER LINK HERE]`
- 0G Storage Merkle root from demo upload: `[INSERT STORAGE MERKLE ROOT HERE]`
- Verification transaction hash: `[INSERT VERIFICATION TX HASH HERE]`

## Rust Crates

### `crypto`

The `crypto` crate contains:

- `Shake256Committer` for domain-separated SHAKE256 commitments
- `XChaCha20Poly1305Encryptor` for authenticated encryption
- `ZkProver` and `ZkVerifier` traits
- `MockZkProver` and `MockZkVerifier` for demo proof flow

SHAKE256 is used because hash-based commitments retain strong post-quantum security assumptions and are simple to audit.

### `storage_client`

The `storage_client` crate owns the file-to-storage pipeline:

- encrypt raw data
- commit to the encrypted envelope
- generate a proof statement
- create an upload payload
- submit through the official 0G Rust storage SDK or dry-run path

### `core`

The `core` crate defines verifier-facing protocol types:

- `CommitmentSubmission`
- `VerifierInput`
- `VerificationReceipt`
- `OnChainVerifier`
- `MockOnChainVerifier`
- `EvmOnChainVerifier`

`EvmOnChainVerifier` uses ethers-rs to call:

```solidity
submitCommitment(bytes32 stateCommitment, bytes32 storageMerkleRoot, bytes proofContext)
```

on a deployed `PqspVerifier` contract.

## Solidity Contract

The Foundry project lives in `contracts/`.

Build contracts:

```bash
cd contracts
forge build
```

Deploy the verifier using the exact command and `.env` loading steps in **Environment Setup & Contract Deployment** above.

The contract is located at:

```text
contracts/src/PqspVerifier.sol
```

It exposes:

```solidity
mapping(bytes32 => bool) public verifiedState;

function submitCommitment(
    bytes32 stateCommitment,
    bytes32 storageMerkleRoot,
    bytes calldata proofContext
) external;
```

and emits:

```solidity
event CommitmentVerified(bytes32 indexed stateCommitment, address indexed submitter);
```

## Demo Flow

1. Upload a file with the Rust CLI and save the printed key.
2. Save the generated `*.pqsp-receipt.json` artifact and copy the storage Merkle root.
3. Verify the artifact locally or on chain depending on verifier env vars.
4. Download the encrypted payload from 0G Storage with `download <MERKLE_ROOT>`.
5. Decrypt the downloaded payload with `decrypt <DOWNLOADED_FILE> <KEY_HEX>`.
6. Optionally deploy `PqspVerifier.sol` to 0G Chain and set `PQSP_VERIFIER_CONTRACT_ADDRESS` for real on-chain verification.

## Security Notes

This repository is a hackathon prototype.

- ZK verification is mocked in the Solidity contract.
- The Rust proof system is trait-based and currently uses deterministic mock proofs.
- The encryption key is generated per CLI upload and printed once. Store it securely.
- Do not commit real private keys or `.env` files.
- The on-chain verifier acts as a sovereign registry for commitments and storage roots, not as a production proof verifier yet.

## License

Apache-2.0
