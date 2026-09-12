// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title INativeQueryVerifier
/// @notice Interface for the Native Query Verifier precompile at address `0xFD2` (4050).
/// @dev Validates Merkle inclusion and continuity chains for proved source transactions.
interface INativeQueryVerifier {
    struct MerkleProofEntry {
        bytes32 hash;
        bool isLeft;
    }

    struct MerkleProof {
        bytes32 root;
        MerkleProofEntry[] siblings;
    }

    struct ContinuityProof {
        bytes32 lowerEndpointDigest;
        bytes32[] roots;
    }

    event TransactionVerified(
        uint64 indexed chainKey,
        uint64 indexed height,
        uint64 transactionIndex
    );

    function verifyAndEmit(
        uint64 chainKey,
        uint64 height,
        bytes calldata encodedTransaction,
        MerkleProof calldata merkleProof,
        ContinuityProof calldata continuityProof
    ) external returns (bool);

    function verifyAndEmit(
        uint64 chainKey,
        uint64[] calldata heights,
        bytes[] calldata encodedTransactions,
        MerkleProof[] calldata merkleProofs,
        ContinuityProof calldata sharedContinuityProof
    ) external returns (bool);

    function verify(
        uint64 chainKey,
        uint64 height,
        bytes calldata encodedTransaction,
        MerkleProof calldata merkleProof,
        ContinuityProof calldata continuityProof
    ) external view returns (bool);

    function verify(
        uint64 chainKey,
        uint64[] calldata heights,
        bytes[] calldata encodedTransactions,
        MerkleProof[] calldata merkleProofs,
        ContinuityProof calldata sharedContinuityProof
    ) external view returns (bool);

    function calculateTxIndex(
        MerkleProof calldata merkleProof
    ) external view returns (uint64);
}

/// @title NativeQueryVerifierLib
/// @notice Helpers for the Native Query Verifier precompile at `0xFD2`.
library NativeQueryVerifierLib {
    address internal constant PRECOMPILE =
        0x0000000000000000000000000000000000000FD2;

    function getVerifier() internal pure returns (INativeQueryVerifier) {
        return INativeQueryVerifier(PRECOMPILE);
    }

    function isCreditcoinChainId(
        uint256 chainId
    ) internal pure returns (bool) {
        return
            chainId == 102030 ||
            chainId == 102031 ||
            chainId == 102032;
    }

    /// @dev Native precompiles have no contract bytecode (`extcodesize == 0`) but still accept calls.
    function hasPrecompile() internal view returns (bool) {
        if (isCreditcoinChainId(block.chainid)) {
            return true;
        }
        return PRECOMPILE.code.length > 0;
    }
}
