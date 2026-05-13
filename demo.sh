#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
Post-Quantum Sovereign Privacy Storage Demo Guide
=================================================

This script is a copy-paste guide for judges and demo recording.
It does not execute the lifecycle automatically.

1. Configure .env
-----------------
Create a .env file at the repository root:

0G_CHAIN_RPC_URL=https://your-0g-chain-rpc
0G_PRIVATE_KEY=0xyour_private_key
0G_STORAGE_NODE_URL=https://your-0g-storage-node
PQSP_VERIFIER_CONTRACT_ADDRESS=0xyour_deployed_pqsp_verifier

2. Prepare a sample file
------------------------
echo "sovereign post-quantum storage demo" > example.txt

3. Upload and save the printed KEY_HEX
--------------------------------------
cargo run -- upload ./example.txt

Copy:
- KEY_HEX from the "IMPORTANT: Save this encryption key..." line
- MERKLE_ROOT from example.txt.pqsp-receipt.json:
  artifact.upload_receipt.storage.merkle_root

4. Verify the receipt artifact
------------------------------
cargo run -- verify ./example.txt.pqsp-receipt.json

5. Download the encrypted payload from 0G Storage
------------------------------------------------
cargo run -- download <MERKLE_ROOT> --out ./downloaded-payload.json

6. Decrypt the downloaded payload
---------------------------------
cargo run -- decrypt ./downloaded-payload.json <KEY_HEX> --out ./recovered-example.txt

7. Confirm recovery
-------------------
diff ./example.txt ./recovered-example.txt

EOF
