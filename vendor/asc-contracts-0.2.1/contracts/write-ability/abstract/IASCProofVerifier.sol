// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BlockProverTypes} from "../common/BlockProverTypes.sol";

interface IASCProofVerifier {
    /// @notice Verifies transaction inclusion and chain continuity for a source chain.
    function verifyProofs(
        bytes32 chainKey,
        uint64 blockHeight,
        BlockProverTypes.InclusionProof calldata inclusionProof,
        BlockProverTypes.ContinuityProof calldata continuityProof
    ) external returns (bytes memory encodedTransaction);

    /// @notice Returns the transaction index implied by a BinaryMerkle inclusion proof.
    function calculateTxIndex(
        BlockProverTypes.InclusionProof calldata inclusionProof
    ) external view returns (uint64);
}
