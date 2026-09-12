// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;


library BlockProverTypes {
    /// @notice Discriminator for the inclusion proof format.
    enum ProofKind {
        /// Binary Merkle tree; `data` is `abi.encode(bytes txBytes, MerkleProofEntry[] siblings)`.
        BinaryMerkle
    }

    /// @notice A single node in a binary Merkle inclusion proof.
    /// @param sibling Hash of the sibling node at this level.
    /// @param isLeft  True if the sibling is on the left (i.e. the current node is the right child).
    struct MerkleProofEntry {
        bytes32 sibling;
        bool isLeft;
    }

    /// @notice Self-describing transaction-inclusion proof.
    /// @param kind ProofKind discriminator selecting how `data` is interpreted.
    /// @param root Merkle/commitment root of the transaction trie for the target block.
    /// @param data `abi.encode(bytes txBytes, MerkleProofEntry[] siblings)`.
    struct InclusionProof {
        ProofKind kind;
        bytes32 root;
        bytes data;
    }

    /// @notice Continuity chain from CC3 prover API (`continuityProof` field).
    /// @dev Links query block Merkle roots back to a known attestation checkpoint:
    ///      `digest[i] = keccak256(abi.encodePacked(blockHeight + i, roots[i], digest[i-1]))`
    ///      with `digest[-1] = lowerEndpointDigest`.
    /// @param lowerEndpointDigest Digest of the block before the queried height (checkpoint anchor).
    /// @param roots               Merkle roots from query height through the attestation chain.
    struct ContinuityProof {
        bytes32 lowerEndpointDigest;
        bytes32[] roots;
    }
}
