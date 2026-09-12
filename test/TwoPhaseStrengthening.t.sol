// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AirResponderCore, IAirChainInfo, IAirContainmentTarget} from "../src/AttestedIncidentResponder.sol";
import {IASCProofVerifier} from "@gluwa/asc-contracts/contracts/write-ability/abstract/IASCProofVerifier.sol";
import {BlockProverTypes} from "@gluwa/asc-contracts/contracts/write-ability/common/BlockProverTypes.sol";
import {EvmV1Decoder} from "@gluwa/asc-contracts/contracts/common/EvmV1Decoder.sol";

interface Vm2P {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
}

contract TwoPhaseVerifier is IASCProofVerifier {
    bytes internal txBytes;
    uint64 internal index;

    function configure(bytes memory txBytes_, uint64 index_) external {
        txBytes = txBytes_;
        index = index_;
    }

    function verifyProofs(
        bytes32,
        uint64,
        BlockProverTypes.InclusionProof calldata,
        BlockProverTypes.ContinuityProof calldata
    ) external returns (bytes memory) {
        return txBytes;
    }

    function calculateTxIndex(BlockProverTypes.InclusionProof calldata) external view returns (uint64) {
        return index;
    }
}

contract TwoPhaseChainInfo is IAirChainInfo {
    function get_latest_attestation_height_and_hash(uint64)
        external
        pure
        returns (uint64 height, bytes32 blockHash, bool isAttestation, bool exists)
    {
        return (150, bytes32(uint256(150)), true, true);
    }
}

contract TwoPhaseTarget is IAirContainmentTarget {
    uint8 public mode;
    uint256 public calls;
    bool public reject;

    function setReject(bool reject_) external {
        reject = reject_;
    }

    function applyMode(uint8 mode_) external {
        require(!reject, "target-reject");
        mode = mode_;
        ++calls;
    }
}

contract TwoPhaseStrengtheningTest {
    Vm2P constant vm = Vm2P(address(uint160(uint256(keccak256("hevm cheat code")))));

    bytes32 constant DEPLOY = keccak256("air-deployment");
    uint64 constant CHAIN_KEY = 1;
    uint64 constant SOURCE_CHAIN = 11_155_111;
    address constant EMITTER = address(0xBEEF);
    uint256 constant SIGNER_KEY = 0xA11CE;
    uint256 constant WRONG_KEY = 0xB0B;
    uint64 constant SOURCE_HEIGHT = 120;

    function testUnsignedProofFirstCannotVetoLaterAuthenticStrengthening() public {
        (AirResponderCore c, TwoPhaseVerifier verifier, TwoPhaseTarget target) = _deploy();
        bytes32 incidentId = keccak256("front-run");
        _configureWarning(verifier, c, incidentId, 7);

        (, AirResponderCore.Mode floorMode, bool fallbackUsed) =
            c.processIncident(CHAIN_KEY, SOURCE_HEIGHT, _inc(), _cont(), bytes(""));
        require(fallbackUsed && floorMode == AirResponderCore.Mode.LIMITED, "phase1 not deterministic LIMITED");
        require(target.mode() == uint8(AirResponderCore.Mode.LIMITED), "target not LIMITED");

        AirResponderCore.Mode effective = c.strengthenIncident(incidentId, _signedFrozen(c, incidentId, 7, SIGNER_KEY));
        require(effective == AirResponderCore.Mode.FROZEN, "post-proof strengthen failed");
        require(target.mode() == uint8(AirResponderCore.Mode.FROZEN), "target not FROZEN");
        require(c.limitedCount() == 0 && c.frozenCount() == 1, "counts not atomically upgraded");
    }

    function testWrongSignerCannotStrengthenOrMutateState() public {
        (AirResponderCore c, TwoPhaseVerifier verifier, TwoPhaseTarget target) = _deploy();
        bytes32 incidentId = keccak256("wrong-signer");
        _configureWarning(verifier, c, incidentId, 8);
        c.processIncident(CHAIN_KEY, SOURCE_HEIGHT, _inc(), _cont(), bytes(""));

        (bool ok,) = address(c)
            .call(
                abi.encodeWithSelector(
                    c.strengthenIncident.selector, incidentId, _signedFrozen(c, incidentId, 8, WRONG_KEY)
                )
            );
        require(!ok, "wrong signer strengthened");
        require(target.mode() == uint8(AirResponderCore.Mode.LIMITED), "invalid auth changed target");
        require(c.limitedCount() == 1 && c.frozenCount() == 0, "invalid auth changed counts");
    }

    function testStrengtheningTargetFailureDoesNotBurnAuthorization() public {
        (AirResponderCore c, TwoPhaseVerifier verifier, TwoPhaseTarget target) = _deploy();
        bytes32 incidentId = keccak256("target-retry");
        _configureWarning(verifier, c, incidentId, 9);
        c.processIncident(CHAIN_KEY, SOURCE_HEIGHT, _inc(), _cont(), bytes(""));
        bytes memory auth = _signedFrozen(c, incidentId, 9, SIGNER_KEY);

        target.setReject(true);
        (bool ok,) = address(c).call(abi.encodeWithSelector(c.strengthenIncident.selector, incidentId, auth));
        require(!ok, "rejecting target unexpectedly succeeded");
        require(c.limitedCount() == 1 && c.frozenCount() == 0, "failed target burned state");

        target.setReject(false);
        AirResponderCore.Mode effective = c.strengthenIncident(incidentId, auth);
        require(effective == AirResponderCore.Mode.FROZEN, "retry did not succeed");
        require(target.mode() == uint8(AirResponderCore.Mode.FROZEN), "retry target not FROZEN");
    }

    function testProvedRecoveryRemovesAIUpgradability() public {
        (AirResponderCore c, TwoPhaseVerifier verifier, TwoPhaseTarget target) = _deploy();
        bytes32 incidentId = keccak256("resolved");
        _configureWarning(verifier, c, incidentId, 10);
        c.processIncident(CHAIN_KEY, SOURCE_HEIGHT, _inc(), _cont(), bytes(""));
        bytes memory auth = _signedFrozen(c, incidentId, 10, SIGNER_KEY);

        _configureResolution(verifier, c, incidentId, 11);
        c.processResolution(CHAIN_KEY, SOURCE_HEIGHT + 1, _inc(), _cont());
        require(target.mode() == uint8(AirResponderCore.Mode.NORMAL), "recovery not NORMAL");

        (bool ok,) = address(c).call(abi.encodeWithSelector(c.strengthenIncident.selector, incidentId, auth));
        require(!ok, "resolved incident strengthened");
        require(target.mode() == uint8(AirResponderCore.Mode.NORMAL), "post-recovery auth changed target");
    }

    function _deploy() internal returns (AirResponderCore c, TwoPhaseVerifier verifier, TwoPhaseTarget target) {
        verifier = new TwoPhaseVerifier();
        TwoPhaseChainInfo info = new TwoPhaseChainInfo();
        target = new TwoPhaseTarget();
        c = new AirResponderCore(verifier, info, target, vm.addr(SIGNER_KEY), _policy());
    }

    function _policy() internal pure returns (AirResponderCore.Policy memory) {
        return AirResponderCore.Policy(DEPLOY, CHAIN_KEY, SOURCE_CHAIN, EMITTER, 100, 200, 50, 100);
    }

    function _configureWarning(TwoPhaseVerifier verifier, AirResponderCore c, bytes32 incidentId, uint64 index)
        internal
    {
        bytes memory data = abi.encodeWithSelector(c.RAISE_SELECTOR(), incidentId, DEPLOY, uint8(1), c.policyHash());
        verifier.configure(_encoded(data, SOURCE_CHAIN, EMITTER, 1), index);
    }

    function _configureResolution(TwoPhaseVerifier verifier, AirResponderCore c, bytes32 incidentId, uint64 index)
        internal
    {
        bytes memory data = abi.encodeWithSelector(c.RESOLVE_SELECTOR(), incidentId, DEPLOY, c.policyHash());
        verifier.configure(_encoded(data, SOURCE_CHAIN, EMITTER, 1), index);
    }

    function _signedFrozen(AirResponderCore c, bytes32 incidentId, uint64 txIndex, uint256 key)
        internal
        returns (bytes memory)
    {
        bytes32 locator = c.proofLocatorId(CHAIN_KEY, SOURCE_HEIGHT, txIndex);
        bytes32 fingerprint = c.recommendationFingerprint(locator, incidentId, 1);
        bytes32 rationaleHash = keccak256("two-phase-rationale");
        uint64 validUntil = type(uint64).max;
        bytes32 digest = c.recommendationDigest(fingerprint, AirResponderCore.Mode.FROZEN, rationaleHash, validUntil);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encode(fingerprint, uint8(AirResponderCore.Mode.FROZEN), rationaleHash, validUntil, r, s, v);
    }

    function _encoded(bytes memory data, uint64 chainId, address to, uint8 receiptStatus)
        internal
        pure
        returns (bytes memory)
    {
        bytes[] memory chunks = new bytes[](3);
        chunks[0] = abi.encode(uint64(1), uint64(200_000), address(0xA11CE), false, to, uint256(0), data);
        EvmV1Decoder.AccessListEntryBytes32[] memory accessList = new EvmV1Decoder.AccessListEntryBytes32[](0);
        chunks[1] = abi.encode(chainId, uint128(1), uint128(2), accessList, uint8(0), bytes32(0), bytes32(0));
        EvmV1Decoder.LogEntryTuple[] memory logs = new EvmV1Decoder.LogEntryTuple[](0);
        chunks[2] = abi.encode(receiptStatus, uint64(120_000), logs, bytes(""));
        return abi.encode(uint8(2), chunks);
    }

    function _inc() internal pure returns (BlockProverTypes.InclusionProof memory p) {
        p.kind = BlockProverTypes.ProofKind.BinaryMerkle;
        p.root = bytes32(uint256(1));
        p.data = bytes("fixture");
    }

    function _cont() internal pure returns (BlockProverTypes.ContinuityProof memory p) {
        p.lowerEndpointDigest = bytes32(uint256(1));
        p.roots = new bytes32[](0);
    }

    function testTrustedWrongFingerprintCannotStrengthenOrMutateState() public {
        (AirResponderCore c, TwoPhaseVerifier verifier, TwoPhaseTarget target) = _deploy();
        bytes32 incidentId = keccak256("trusted-wrong-fingerprint");
        _configureWarning(verifier, c, incidentId, 20);
        c.processIncident(CHAIN_KEY, SOURCE_HEIGHT, _inc(), _cont(), bytes(""));

        bytes32 wrongFingerprint = keccak256("wrong-stored-fingerprint");
        bytes memory auth = _signedFrozenForFingerprint(c, wrongFingerprint, type(uint64).max);
        _requireStrengthenRejected(c, incidentId, auth, "trusted wrong fingerprint strengthened");

        require(target.mode() == uint8(AirResponderCore.Mode.LIMITED), "wrong fingerprint changed target");
        require(target.calls() == 1, "wrong fingerprint called target");
        require(c.limitedCount() == 1 && c.frozenCount() == 0, "wrong fingerprint changed counts");
        require(c.effectiveMode() == AirResponderCore.Mode.LIMITED, "wrong fingerprint changed effective mode");
    }

    function testSuccessfulStrengtheningCannotReplayOrDoubleCount() public {
        (AirResponderCore c, TwoPhaseVerifier verifier, TwoPhaseTarget target) = _deploy();
        bytes32 incidentId = keccak256("strengthen-replay");
        _configureWarning(verifier, c, incidentId, 21);
        c.processIncident(CHAIN_KEY, SOURCE_HEIGHT, _inc(), _cont(), bytes(""));
        bytes memory auth = _signedFrozen(c, incidentId, 21, SIGNER_KEY);

        c.strengthenIncident(incidentId, auth);
        require(target.calls() == 2, "initial strengthen did not call target once");
        _requireStrengthenRejected(c, incidentId, auth, "strengthening authorization replayed");

        require(target.calls() == 2, "replay called target");
        require(c.limitedCount() == 0 && c.frozenCount() == 1, "replay changed counts");
        require(c.effectiveMode() == AirResponderCore.Mode.FROZEN, "replay changed effective mode");
    }

    function testExpiredStrengtheningAuthorizationCannotMutateState() public {
        (AirResponderCore c, TwoPhaseVerifier verifier, TwoPhaseTarget target) = _deploy();
        bytes32 incidentId = keccak256("strengthen-expired");
        _configureWarning(verifier, c, incidentId, 22);
        c.processIncident(CHAIN_KEY, SOURCE_HEIGHT, _inc(), _cont(), bytes(""));

        bytes32 fingerprint = c.recommendationFingerprint(c.proofLocatorId(CHAIN_KEY, SOURCE_HEIGHT, 22), incidentId, 1);
        bytes memory expired = _signedFrozenForFingerprint(c, fingerprint, 0);
        _requireStrengthenRejected(c, incidentId, expired, "expired strengthening succeeded");

        require(target.calls() == 1, "expired authorization called target");
        require(c.limitedCount() == 1 && c.frozenCount() == 0, "expired authorization changed counts");
    }

    function testCrossResponderStrengtheningSignatureCannotReplay() public {
        (AirResponderCore victim, TwoPhaseVerifier verifier, TwoPhaseTarget target) = _deploy();
        (AirResponderCore other,,) = _deploy();
        bytes32 incidentId = keccak256("strengthen-cross-responder");
        _configureWarning(verifier, victim, incidentId, 23);
        victim.processIncident(CHAIN_KEY, SOURCE_HEIGHT, _inc(), _cont(), bytes(""));

        bytes32 fingerprint =
            victim.recommendationFingerprint(victim.proofLocatorId(CHAIN_KEY, SOURCE_HEIGHT, 23), incidentId, 1);
        bytes memory otherDomainAuth = _signedFrozenForFingerprint(other, fingerprint, type(uint64).max);
        _requireStrengthenRejected(victim, incidentId, otherDomainAuth, "cross-responder strengthening replayed");

        require(target.calls() == 1, "cross-responder replay called target");
        require(victim.limitedCount() == 1 && victim.frozenCount() == 0, "cross-responder replay changed counts");
    }

    function testHighSStrengtheningSignatureCannotMutateState() public {
        (AirResponderCore c, TwoPhaseVerifier verifier, TwoPhaseTarget target) = _deploy();
        bytes32 incidentId = keccak256("strengthen-high-s");
        _configureWarning(verifier, c, incidentId, 24);
        c.processIncident(CHAIN_KEY, SOURCE_HEIGHT, _inc(), _cont(), bytes(""));

        bytes memory original = _signedFrozen(c, incidentId, 24, SIGNER_KEY);
        (bytes32 fp, uint8 mode, bytes32 rationale, uint64 until, bytes32 r, bytes32 s, uint8 sigV) =
            abi.decode(original, (bytes32, uint8, bytes32, uint64, bytes32, bytes32, uint8));
        uint256 secp256k1N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
        bytes32 highS = bytes32(secp256k1N - uint256(s));
        uint8 alternateV = sigV == 27 ? 28 : 27;
        bytes memory malleable = abi.encode(fp, mode, rationale, until, r, highS, alternateV);
        _requireStrengthenRejected(c, incidentId, malleable, "high-s strengthening succeeded");

        require(target.calls() == 1, "high-s authorization called target");
        require(c.limitedCount() == 1 && c.frozenCount() == 0, "high-s authorization changed counts");
    }

    function testOverlappingIncidentsPreserveEffectiveModeAcrossStrengthenAndRecovery() public {
        (AirResponderCore c, TwoPhaseVerifier verifier, TwoPhaseTarget target) = _deploy();
        bytes32 first = keccak256("overlap-first");
        bytes32 second = keccak256("overlap-second");

        _configureWarning(verifier, c, first, 25);
        c.processIncident(CHAIN_KEY, SOURCE_HEIGHT, _inc(), _cont(), bytes(""));
        _configureWarning(verifier, c, second, 26);
        c.processIncident(CHAIN_KEY, SOURCE_HEIGHT, _inc(), _cont(), bytes(""));
        require(c.limitedCount() == 2 && c.frozenCount() == 0, "two LIMITED incidents not counted");

        c.strengthenIncident(first, _signedFrozen(c, first, 25, SIGNER_KEY));
        require(c.limitedCount() == 1 && c.frozenCount() == 1, "strengthen counts wrong under overlap");
        require(c.effectiveMode() == AirResponderCore.Mode.FROZEN, "overlap did not preserve FROZEN effective mode");
        require(target.mode() == uint8(AirResponderCore.Mode.FROZEN), "target not FROZEN under overlap");

        _configureResolution(verifier, c, first, 27);
        c.processResolution(CHAIN_KEY, SOURCE_HEIGHT + 1, _inc(), _cont());
        require(c.limitedCount() == 1 && c.frozenCount() == 0, "recovery counts wrong under overlap");
        require(c.effectiveMode() == AirResponderCore.Mode.LIMITED, "recovery ignored remaining LIMITED incident");
        require(target.mode() == uint8(AirResponderCore.Mode.LIMITED), "target did not step down to LIMITED");
        require(target.calls() == 4, "unexpected target call count under overlap");
    }

    function testAlreadyFrozenCriticalIncidentCannotUseStrengtheningPath() public {
        (AirResponderCore c, TwoPhaseVerifier verifier, TwoPhaseTarget target) = _deploy();
        bytes32 incidentId = keccak256("critical-no-strengthen");
        bytes memory data = abi.encodeWithSelector(c.RAISE_SELECTOR(), incidentId, DEPLOY, uint8(2), c.policyHash());
        verifier.configure(_encoded(data, SOURCE_CHAIN, EMITTER, 1), 28);
        c.processIncident(CHAIN_KEY, SOURCE_HEIGHT, _inc(), _cont(), bytes(""));
        require(c.effectiveMode() == AirResponderCore.Mode.FROZEN, "critical incident not FROZEN");

        _requireStrengthenRejected(c, incidentId, bytes(""), "already-FROZEN incident accepted strengthening path");
        require(target.calls() == 1, "already-FROZEN strengthening called target");
        require(c.limitedCount() == 0 && c.frozenCount() == 1, "already-FROZEN strengthening changed counts");
    }

    function _signedFrozenForFingerprint(AirResponderCore c, bytes32 fingerprint, uint64 validUntil)
        internal
        returns (bytes memory)
    {
        bytes32 rationaleHash = keccak256("two-phase-adversarial-rationale");
        bytes32 digest = c.recommendationDigest(fingerprint, AirResponderCore.Mode.FROZEN, rationaleHash, validUntil);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, digest);
        return abi.encode(fingerprint, uint8(AirResponderCore.Mode.FROZEN), rationaleHash, validUntil, r, s, v);
    }

    function _requireStrengthenRejected(AirResponderCore c, bytes32 incidentId, bytes memory auth, string memory why)
        internal
    {
        (bool ok,) = address(c).call(abi.encodeWithSelector(c.strengthenIncident.selector, incidentId, auth));
        require(!ok, why);
    }
}
