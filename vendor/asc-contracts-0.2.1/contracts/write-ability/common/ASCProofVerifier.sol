// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IASCProofVerifier} from "../abstract/IASCProofVerifier.sol";
import {BlockProverTypes} from "./BlockProverTypes.sol";
import {INativeQueryVerifier, NativeQueryVerifierLib} from "./INativeQueryVerifier.sol";
import {QueryProofVerificationLib} from "./QueryProofVerificationLib.sol";

/// @title ASCProofVerifier
/// @notice Single ASC entry point for CC3 query proof verification via native precompile `0xFD2`.
/// @dev Used by bridge inbound, loan readability, and other ASC-compatible contracts.
contract ASCProofVerifier is IASCProofVerifier {
    /// @dev Emitted only on successful verification
    event ProofVerified(
        bytes32 indexed chainKey,
        uint64 blockHeight,
        BlockProverTypes.ProofKind kind,
        address precompileUsed
    );

    error ProofInvalid(bytes32 chainKey, uint64 blockHeight);
    error UnsupportedProofKind(BlockProverTypes.ProofKind kind);
    error NonCanonicalChainKey(bytes32 chainKey);

    function verifyProofs(
        bytes32 chainKey,
        uint64 blockHeight,
        BlockProverTypes.InclusionProof calldata inclusionProof,
        BlockProverTypes.ContinuityProof calldata continuityProof
    ) external returns (bytes memory) {
        if (uint256(chainKey) > type(uint64).max) {
            revert NonCanonicalChainKey(chainKey);
        }
        if (inclusionProof.kind != BlockProverTypes.ProofKind.BinaryMerkle) {
            revert ProofInvalid(chainKey, blockHeight);
        }
        return _verifyBinaryMerkle(
            chainKey,
            blockHeight,
            inclusionProof,
            continuityProof
        );
    }

    function calculateTxIndex(
        BlockProverTypes.InclusionProof calldata inclusionProof
    ) external view returns (uint64) {
        if (inclusionProof.kind != BlockProverTypes.ProofKind.BinaryMerkle) {
            revert UnsupportedProofKind(inclusionProof.kind);
        }
        INativeQueryVerifier.MerkleProof memory merkleProof = _nativeMerkleProof(inclusionProof);
        return NativeQueryVerifierLib.getVerifier().calculateTxIndex(merkleProof);
    }

    function _verifyBinaryMerkle(
        bytes32 chainKey,
        uint64 blockHeight,
        BlockProverTypes.InclusionProof calldata inclusionProof,
        BlockProverTypes.ContinuityProof calldata continuityProof
    ) internal returns (bytes memory txBytes) {
        BlockProverTypes.MerkleProofEntry[] memory siblings;
        (txBytes, siblings) = QueryProofVerificationLib.decodeBinaryMerklePayload(
            inclusionProof.data
        );
        if (txBytes.length == 0) {
            revert ProofInvalid(chainKey, blockHeight);
        }

        if (!NativeQueryVerifierLib.hasPrecompile()) {
            revert ProofInvalid(chainKey, blockHeight);
        }

        bool ok = _verifyViaNativeQueryPrecompile(
            chainKey,
            blockHeight,
            txBytes,
            _toNativeMerkleProof(inclusionProof.root, siblings),
            continuityProof
        );
        if (!ok) revert ProofInvalid(chainKey, blockHeight);
        emit ProofVerified(
            chainKey,
            blockHeight,
            inclusionProof.kind,
            address(NativeQueryVerifierLib.getVerifier())
        );
    }

    function _verifyViaNativeQueryPrecompile(
        bytes32 chainKey,
        uint64 blockHeight,
        bytes memory txBytes,
        INativeQueryVerifier.MerkleProof memory merkleProof,
        BlockProverTypes.ContinuityProof calldata continuityProof
    ) internal returns (bool) {
        INativeQueryVerifier.ContinuityProof memory nativeContinuity = INativeQueryVerifier
            .ContinuityProof({
            lowerEndpointDigest: continuityProof.lowerEndpointDigest,
            roots: continuityProof.roots
        });

        return
            NativeQueryVerifierLib.getVerifier().verifyAndEmit(
                uint64(uint256(chainKey)),
                blockHeight,
                txBytes,
                merkleProof,
                nativeContinuity
            );
    }

    function _nativeMerkleProof(
        BlockProverTypes.InclusionProof calldata inclusionProof
    ) internal pure returns (INativeQueryVerifier.MerkleProof memory merkleProof) {
        (, BlockProverTypes.MerkleProofEntry[] memory siblings) = QueryProofVerificationLib
            .decodeBinaryMerklePayload(inclusionProof.data);
        return _toNativeMerkleProof(inclusionProof.root, siblings);
    }

    function _toNativeMerkleProof(
        bytes32 root,
        BlockProverTypes.MerkleProofEntry[] memory siblings
    ) internal pure returns (INativeQueryVerifier.MerkleProof memory merkleProof) {
        uint256 length = siblings.length;
        INativeQueryVerifier.MerkleProofEntry[] memory nativeSiblings =
            new INativeQueryVerifier.MerkleProofEntry[](length);
        for (uint256 i = 0; i < length; ++i) {
            nativeSiblings[i] = INativeQueryVerifier.MerkleProofEntry({
                hash: siblings[i].sibling,
                isLeft: siblings[i].isLeft
            });
        }
        merkleProof = INativeQueryVerifier.MerkleProof({
            root: root,
            siblings: nativeSiblings
        });
    }
}
