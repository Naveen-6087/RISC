// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @notice Interface for RISC Zero verifier contract
interface IRiscZeroVerifier {
    /// @notice Verify a RISC Zero receipt
    /// @param seal The encoded cryptographic proof (SNARK)
    /// @param imageId The identifier for the zkVM program that was executed
    /// @param journalDigest The SHA-256 digest of the journal bytes
    function verify(
        bytes calldata seal,
        bytes32 imageId,
        bytes32 journalDigest
    ) external view;
}
