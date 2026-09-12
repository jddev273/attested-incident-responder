// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Decodes ASC-SDK / prover `txBytes` = abi.encode(uint8 txType, bytes[] chunks).
///      Layout mirrors CCNext `scripts/common/utils.js` (`decode_proof_tx_bytes`).
///      Protected legacy transactions derive their chain ID from EIP-155 `v`.
library ASCSdkV1TxBytesLib {
    struct AccessListEntry {
        address addr;
        bytes32[] storageKeys;
    }

    /// @notice Flat decode aligned with CCNext `decodeAttestedProof.js` print fields.
    struct ProofTx {
        uint8 txType;
        uint64 nonce;
        uint64 gasLimit;
        address from;
        bool toIsNull;
        address to;
        uint256 value;
        bytes data;
        uint64 chainId;
        uint256 gasPrice;
        uint256 maxPriorityFeePerGas;
        uint256 maxFeePerGas;
    }

    error UnsupportedTxType(uint8 txType);
    error InvalidChunkCount(uint8 txType, uint256 count);
    error LegacyChainIdOverflow(uint256 chainId);

    function decode(bytes calldata txBytes) internal pure returns (ProofTx memory proofTx) {
        return decodeMemory(txBytes);
    }

    /// @notice Same as `decode` but accepts `bytes memory` (e.g. from inclusion-proof extraction).
    function decodeMemory(bytes memory txBytes) internal pure returns (ProofTx memory proofTx) {
        (uint8 txType, bytes[] memory chunks) = abi.decode(txBytes, (uint8, bytes[]));

        uint256 expected = expectedChunkCount(txType);
        if (expected == 0) {
            revert UnsupportedTxType(txType);
        }
        if (chunks.length != expected) {
            revert InvalidChunkCount(txType, chunks.length);
        }

        (
            uint64 nonce,
            uint64 gasLimit,
            address from,
            bool toIsNull,
            address to,
            uint256 value,
            bytes memory data
        ) = abi.decode(
            chunks[0],
            (uint64, uint64, address, bool, address, uint256, bytes)
        );

        if (from == address(0)) {
            revert InvalidChunkCount(txType, 0);
        }

        proofTx.txType = txType;
        proofTx.nonce = nonce;
        proofTx.gasLimit = gasLimit;
        proofTx.from = from;
        proofTx.toIsNull = toIsNull;
        proofTx.to = to;
        proofTx.value = value;
        proofTx.data = data;

        _decodeMiddleFields(txType, chunks, proofTx);
    }

    function expectedChunkCount(uint8 txType) internal pure returns (uint256) {
        if (txType <= 2) {
            return 3;
        }
        if (txType == 3 || txType == 4) {
            return 4;
        }
        return 0;
    }

    function _decodeMiddleFields(
        uint8 txType,
        bytes[] memory chunks,
        ProofTx memory proofTx
    ) internal pure {
        if (txType == 0) {
            (uint128 gasPrice, uint256 v, bytes32 unused1, bytes32 unused2) = abi
                .decode(chunks[1], (uint128, uint256, bytes32, bytes32));
            unused1;
            unused2;
            proofTx.gasPrice = gasPrice;
            if (v >= 35) {
                uint256 chainId = (v - 35) / 2;
                if (chainId > type(uint64).max) {
                    revert LegacyChainIdOverflow(chainId);
                }
                proofTx.chainId = uint64(chainId);
            }
            return;
        }

        if (txType == 1) {
            (
                uint64 chainId,
                uint128 gasPrice,
                AccessListEntry[] memory accessList,
                uint8 yParity,
                bytes32 r,
                bytes32 s
            ) = abi.decode(
                chunks[1],
                (uint64, uint128, AccessListEntry[], uint8, bytes32, bytes32)
            );
            accessList;
            yParity;
            r;
            s;
            proofTx.chainId = chainId;
            proofTx.gasPrice = gasPrice;
            return;
        }

        if (txType == 2) {
            (
                uint64 chainId,
                uint128 maxPriorityFeePerGas,
                uint128 maxFeePerGas,
                AccessListEntry[] memory accessList,
                uint8 yParity,
                bytes32 r,
                bytes32 s
            ) = abi.decode(
                chunks[1],
                (uint64, uint128, uint128, AccessListEntry[], uint8, bytes32, bytes32)
            );
            accessList;
            yParity;
            r;
            s;
            proofTx.chainId = chainId;
            proofTx.maxPriorityFeePerGas = maxPriorityFeePerGas;
            proofTx.maxFeePerGas = maxFeePerGas;
            return;
        }

        if (txType == 3 || txType == 4) {
            (
                uint64 chainId,
                uint128 maxPriorityFeePerGas,
                uint128 maxFeePerGas,
                AccessListEntry[] memory accessList
            ) = abi.decode(chunks[1], (uint64, uint128, uint128, AccessListEntry[]));
            accessList;
            proofTx.chainId = chainId;
            proofTx.maxPriorityFeePerGas = maxPriorityFeePerGas;
            proofTx.maxFeePerGas = maxFeePerGas;
        }
    }
}
