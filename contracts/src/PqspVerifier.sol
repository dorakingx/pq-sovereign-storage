// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title PqspVerifier
/// @author PQ Sovereign Privacy Storage
/// @notice Demo verifier and sovereign registry for protocol commitments anchored
///         to 0G Storage Merkle roots.
/// @dev This contract intentionally mocks ZKP verification for the hackathon
///      demo by accepting every proof context as valid. Even with mocked proof
///      verification, the contract still acts as the on-chain sovereign registry
///      that records which state commitments have been tied to submitted 0G
///      Storage roots. The `proofContext` argument is accepted now so the Rust
///      pipeline can evolve toward real on-chain verification later without
///      changing the submission interface.
contract PqspVerifier {
    /// @notice Records whether a state commitment has been accepted on chain.
    mapping(bytes32 => bool) public verifiedState;

    /// @notice Emitted when a commitment is accepted by the verifier registry.
    event CommitmentVerified(bytes32 indexed stateCommitment, address indexed submitter);

    error InvalidCommitment();
    error InvalidStorageMerkleRoot();
    error MockVerificationFailed();

    /// @notice Submit a state commitment and its corresponding 0G Storage root.
    /// @param stateCommitment Post-quantum state commitment produced off chain.
    /// @param storageMerkleRoot Merkle root returned by the 0G Storage network.
    /// @param proofContext Opaque proof payload reserved for a future real verifier.
    function submitCommitment(
        bytes32 stateCommitment,
        bytes32 storageMerkleRoot,
        bytes calldata proofContext
    ) external {
        if (stateCommitment == bytes32(0)) {
            revert InvalidCommitment();
        }

        if (storageMerkleRoot == bytes32(0)) {
            revert InvalidStorageMerkleRoot();
        }

        if (!_verifyMockProof(stateCommitment, storageMerkleRoot, proofContext)) {
            revert MockVerificationFailed();
        }

        verifiedState[stateCommitment] = true;
        emit CommitmentVerified(stateCommitment, msg.sender);
    }

    /// @dev Mock verifier used only for the demo. The inputs are intentionally
    ///      threaded through the function so they remain part of the explicit
    ///      verifier interface and can be replaced by real ZKP verification later.
    function _verifyMockProof(
        bytes32 stateCommitment,
        bytes32 storageMerkleRoot,
        bytes calldata proofContext
    ) internal pure returns (bool) {
        stateCommitment;
        storageMerkleRoot;
        proofContext;
        return true;
    }
}
