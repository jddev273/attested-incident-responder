// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {
    AirResponderCore,
    AttestedIncidentResponder,
    IAirChainInfo,
    IAirContainmentTarget,
    SentryVault,
    SourceIncidentEmitter
} from "../src/AttestedIncidentResponder.sol";
import {IASCProofVerifier} from "@gluwa/asc-contracts/contracts/write-ability/abstract/IASCProofVerifier.sol";
import {BlockProverTypes} from "@gluwa/asc-contracts/contracts/write-ability/common/BlockProverTypes.sol";
import {EvmV1Decoder} from "@gluwa/asc-contracts/contracts/common/EvmV1Decoder.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address sender) external;
    function chainId(uint256 newChainId) external;
}

contract MockVerifier is IASCProofVerifier {
    bytes internal txBytes;
    uint64 internal index;
    bool internal reject;

    function configure(bytes memory txBytes_, uint64 index_) external {
        txBytes = txBytes_;
        index = index_;
    }

    function setReject(bool value) external {
        reject = value;
    }

    function verifyProofs(
        bytes32,
        uint64,
        BlockProverTypes.InclusionProof calldata,
        BlockProverTypes.ContinuityProof calldata
    ) external returns (bytes memory) {
        require(!reject, "proof rejected");
        return txBytes;
    }

    function calculateTxIndex(BlockProverTypes.InclusionProof calldata) external view returns (uint64) {
        return index;
    }
}

contract MockChainInfo is IAirChainInfo {
    uint64 public latestHeight = 200;
    bool public exists = true;

    function setLatest(uint64 height, bool exists_) external {
        latestHeight = height;
        exists = exists_;
    }

    function get_latest_attestation_height_and_hash(uint64)
        external
        view
        returns (uint64 height, bytes32 hash, bool isAttestation, bool exists_)
    {
        return (latestHeight, bytes32(uint256(latestHeight)), true, exists);
    }
}

contract MockTarget is IAirContainmentTarget {
    uint8 public mode;
    uint256 public calls;
    bool public reject;

    function setReject(bool value) external {
        reject = value;
    }

    function applyMode(uint8 mode_) external {
        require(!reject, "target rejected");
        mode = mode_;
        ++calls;
    }
}

contract PaymentSink {
    receive() external payable {}
}

contract SourceTreasury {
    receive() external payable {}

    function pay(address payable recipient, uint256 amount) external {
        (bool ok,) = recipient.call{value: amount}("");
        require(ok, "source treasury payment failed");
    }
}

contract UnauthorizedVaultCaller {
    function tryPayment(SentryVault vault, address payable recipient, uint256 amount) external returns (bool ok) {
        (ok,) = address(vault).call(abi.encodeWithSelector(SentryVault.executePayment.selector, recipient, amount));
    }
}

contract AirResponderTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 constant DEPLOY = keccak256("air-deployment");
    uint64 constant CHAIN_KEY = 1;
    uint64 constant SOURCE_CHAIN = 11_155_111;
    address constant EMITTER = address(0xBEEF);
    uint256 constant RECOMMENDER_PK = 0xA11CE;
    uint256 constant ATTACKER_PK = 0xB0B;
    uint256 constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function testValidWarningRecommendationAppliesLimited() public {
        (AirResponderCore c, MockVerifier v, MockTarget t) = _deploy();
        bytes32 id = keccak256("valid-warning");
        _incidentTx(v, c, id, 1, 7, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        (, AirResponderCore.Mode applied, bool fallbackUsed) = c.processIncident(
            CHAIN_KEY, 120, _inc(), _cont(), _recommend(c, id, 1, 120, 7, AirResponderCore.Mode.LIMITED)
        );
        _eq(uint8(applied), 1, "expected LIMITED");
        require(!fallbackUsed, "valid signed recommendation fell back");
        _eq(t.mode(), 1, "target not LIMITED");
    }

    function testMalformedAndHugeAIUseObjectiveWarningFloorWithoutBlockingContainment() public {
        (AirResponderCore c1, MockVerifier v1, MockTarget t1) = _deploy();
        bytes32 id1 = keccak256("garbage-ai");
        _incidentTx(v1, c1, id1, 1, 8, SOURCE_CHAIN, EMITTER, 1, c1.policyHash());
        (, AirResponderCore.Mode m1, bool f1) =
            c1.processIncident(CHAIN_KEY, 121, _inc(), _cont(), bytes("unknown model mode with trailing authority"));
        require(f1 && uint8(m1) == 1 && t1.mode() == 1, "garbage AI changed WARNING floor");

        (AirResponderCore c2, MockVerifier v2, MockTarget t2) = _deploy();
        bytes32 id2 = keccak256("huge-ai");
        _incidentTx(v2, c2, id2, 1, 9, SOURCE_CHAIN, EMITTER, 1, c2.policyHash());
        bytes memory huge = new bytes(32_768);
        for (uint256 i; i < huge.length; ++i) {
            huge[i] = bytes1(uint8(i));
        }
        (, AirResponderCore.Mode m2, bool f2) = c2.processIncident(CHAIN_KEY, 122, _inc(), _cont(), huge);
        require(f2 && uint8(m2) == 1 && t2.mode() == 1, "huge AI changed WARNING floor");
    }

    function testWrongBindingAndTooWeakCriticalCannotChooseContainment() public {
        (AirResponderCore c1, MockVerifier v1, MockTarget t1) = _deploy();
        bytes32 id1 = keccak256("wrong-binding");
        _incidentTx(v1, c1, id1, 1, 10, SOURCE_CHAIN, EMITTER, 1, c1.policyHash());
        bytes memory wrong = abi.encode(
            bytes32(uint256(0xBAD)),
            uint8(2),
            keccak256("rationale"),
            type(uint64).max,
            bytes32(uint256(1)),
            bytes32(uint256(1)),
            uint8(27)
        );
        (, AirResponderCore.Mode m1, bool f1) = c1.processIncident(CHAIN_KEY, 123, _inc(), _cont(), wrong);
        require(f1 && uint8(m1) == 1 && t1.mode() == 1, "wrong binding selected WARNING containment");

        (AirResponderCore c2, MockVerifier v2, MockTarget t2) = _deploy();
        bytes32 id2 = keccak256("critical");
        _incidentTx(v2, c2, id2, 2, 11, SOURCE_CHAIN, EMITTER, 1, c2.policyHash());
        (, AirResponderCore.Mode m2, bool f2) = c2.processIncident(
            CHAIN_KEY, 124, _inc(), _cont(), _recommend(c2, id2, 2, 124, 11, AirResponderCore.Mode.LIMITED)
        );
        require(f2 && uint8(m2) == 2 && t2.mode() == 2, "AI weakened critical containment");
    }

    function testForgedSignerCannotEscalateWarning() public {
        (AirResponderCore c, MockVerifier verifier, MockTarget target_) = _deploy();
        bytes32 id = keccak256("forged-signer");
        _incidentTx(verifier, c, id, 1, 12, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        bytes memory forged =
            _recommendWithKey(c, id, 1, 125, 12, AirResponderCore.Mode.FROZEN, ATTACKER_PK, type(uint64).max);
        (, AirResponderCore.Mode applied, bool fallbackUsed) =
            c.processIncident(CHAIN_KEY, 125, _inc(), _cont(), forged);
        require(fallbackUsed && uint8(applied) == 1 && target_.mode() == 1, "forged signer escalated WARNING");
    }

    function testTrustedSignedWarningCanStrengthenToFrozenThroughPermissionlessRelay() public {
        (AirResponderCore c, MockVerifier verifier, MockTarget target_) = _deploy();
        bytes32 id = keccak256("trusted-strengthen");
        _incidentTx(verifier, c, id, 1, 13, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        bytes memory signed = _recommend(c, id, 1, 126, 13, AirResponderCore.Mode.FROZEN);
        vm.prank(address(0xCAFE));
        (, AirResponderCore.Mode applied, bool fallbackUsed) =
            c.processIncident(CHAIN_KEY, 126, _inc(), _cont(), signed);
        require(!fallbackUsed && uint8(applied) == 2 && target_.mode() == 2, "trusted strengthening was not applied");
    }

    function testExpiredSignedRecommendationCannotEscalateWarning() public {
        (AirResponderCore c, MockVerifier verifier, MockTarget target_) = _deploy();
        bytes32 id = keccak256("expired-recommendation");
        _incidentTx(verifier, c, id, 1, 14, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        bytes memory expired = _recommendWithKey(c, id, 1, 127, 14, AirResponderCore.Mode.FROZEN, RECOMMENDER_PK, 0);
        (, AirResponderCore.Mode applied, bool fallbackUsed) =
            c.processIncident(CHAIN_KEY, 127, _inc(), _cont(), expired);
        require(fallbackUsed && uint8(applied) == 1 && target_.mode() == 1, "expired recommendation escalated WARNING");
    }

    function testSignedModeSubstitutionCannotEscalateWarning() public {
        (AirResponderCore c, MockVerifier verifier, MockTarget target_) = _deploy();
        bytes32 id = keccak256("mode-substitution");
        _incidentTx(verifier, c, id, 1, 15, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        bytes memory original = _recommend(c, id, 1, 128, 15, AirResponderCore.Mode.LIMITED);
        (bytes32 fp, uint8 ignoredMode, bytes32 rationale, uint64 until, bytes32 r, bytes32 s, uint8 sigV) =
            abi.decode(original, (bytes32, uint8, bytes32, uint64, bytes32, bytes32, uint8));
        ignoredMode;
        bytes memory tampered = abi.encode(fp, uint8(AirResponderCore.Mode.FROZEN), rationale, until, r, s, sigV);
        (, AirResponderCore.Mode applied, bool fallbackUsed) =
            c.processIncident(CHAIN_KEY, 128, _inc(), _cont(), tampered);
        require(fallbackUsed && uint8(applied) == 1 && target_.mode() == 1, "mode substitution escalated WARNING");
    }

    function testHighSSignatureMalleabilityIsRejected() public {
        (AirResponderCore c, MockVerifier verifier, MockTarget target_) = _deploy();
        bytes32 id = keccak256("high-s");
        _incidentTx(verifier, c, id, 1, 16, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        bytes memory original = _recommend(c, id, 1, 129, 16, AirResponderCore.Mode.FROZEN);
        (bytes32 fp, uint8 mode, bytes32 rationale, uint64 until, bytes32 r, bytes32 s, uint8 sigV) =
            abi.decode(original, (bytes32, uint8, bytes32, uint64, bytes32, bytes32, uint8));
        bytes32 highS = bytes32(SECP256K1_N - uint256(s));
        uint8 alternateV = sigV == 27 ? 28 : 27;
        bytes memory malleable = abi.encode(fp, mode, rationale, until, r, highS, alternateV);
        (, AirResponderCore.Mode applied, bool fallbackUsed) =
            c.processIncident(CHAIN_KEY, 129, _inc(), _cont(), malleable);
        require(fallbackUsed && uint8(applied) == 1 && target_.mode() == 1, "high-s signature escalated WARNING");
    }

    function testSignedRecommendationCannotReplayAcrossResponderInstance() public {
        (AirResponderCore victim, MockVerifier verifier, MockTarget target_) = _deploy();
        (AirResponderCore other,,) = _deploy();
        bytes32 id = keccak256("cross-responder-replay");
        _incidentTx(verifier, victim, id, 1, 17, SOURCE_CHAIN, EMITTER, 1, victim.policyHash());
        bytes memory otherDomain = _recommend(other, id, 1, 130, 17, AirResponderCore.Mode.FROZEN);
        (, AirResponderCore.Mode applied, bool fallbackUsed) =
            victim.processIncident(CHAIN_KEY, 130, _inc(), _cont(), otherDomain);
        require(fallbackUsed && uint8(applied) == 1 && target_.mode() == 1, "cross-responder recommendation replayed");
    }

    function testSignedRecommendationCannotReplayAcrossChainDomain() public {
        (AirResponderCore c, MockVerifier verifier, MockTarget target_) = _deploy();
        bytes32 id = keccak256("cross-chain-replay");
        _incidentTx(verifier, c, id, 1, 18, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        bytes memory signedOnOriginalChain = _recommend(c, id, 1, 131, 18, AirResponderCore.Mode.FROZEN);

        vm.chainId(block.chainid + 1);
        (, AirResponderCore.Mode applied, bool fallbackUsed) =
            c.processIncident(CHAIN_KEY, 131, _inc(), _cont(), signedOnOriginalChain);
        require(fallbackUsed && uint8(applied) == 1 && target_.mode() == 1, "cross-chain recommendation replayed");
    }

    function testSignedRationaleSubstitutionCannotReuseAuthority() public {
        (AirResponderCore c, MockVerifier verifier, MockTarget target_) = _deploy();
        bytes32 id = keccak256("rationale-substitution");
        _incidentTx(verifier, c, id, 1, 19, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        bytes memory original = _recommend(c, id, 1, 132, 19, AirResponderCore.Mode.FROZEN);
        (bytes32 fp, uint8 mode, bytes32 ignoredRationale, uint64 until, bytes32 r, bytes32 sigS, uint8 sigV) =
            abi.decode(original, (bytes32, uint8, bytes32, uint64, bytes32, bytes32, uint8));
        ignoredRationale;
        bytes memory tampered = abi.encode(fp, mode, keccak256("substituted-rationale"), until, r, sigS, sigV);

        (, AirResponderCore.Mode applied, bool fallbackUsed) =
            c.processIncident(CHAIN_KEY, 132, _inc(), _cont(), tampered);
        require(
            fallbackUsed && uint8(applied) == 1 && target_.mode() == 1, "rationale substitution reused signed authority"
        );
    }

    function testWrongChainReceiptEmitterAndPolicyRejectWithoutBurning() public {
        _assertRejectedSource(keccak256("wrong-chain"), 125, 12, 1, EMITTER, 1, bytes32(0), 1);
        _assertRejectedSource(keccak256("failed-receipt"), 126, 13, SOURCE_CHAIN, EMITTER, 0, bytes32(0), 2);
        _assertRejectedSource(keccak256("wrong-emitter"), 127, 14, SOURCE_CHAIN, address(0xDEAD), 1, bytes32(0), 3);
        _assertRejectedSource(keccak256("wrong-policy"), 128, 15, SOURCE_CHAIN, EMITTER, 1, bytes32(uint256(0xBAD)), 4);
    }

    function testVerifierFailureCreatesNoContainmentState() public {
        (AirResponderCore c, MockVerifier v, MockTarget t) = _deploy();
        bytes32 id = keccak256("bad-proof");
        _incidentTx(v, c, id, 1, 16, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        v.setReject(true);
        _expectIncidentRevert(c, 129, bytes("garbage"));
        require(!c.consumedProofLocator(c.proofLocatorId(CHAIN_KEY, 129, 16)), "failed proof consumed locator");
        require(!c.incidentEverSeen(id), "failed proof burned incident");
        _eq(t.calls(), 0, "failed proof called target");
    }

    function testContainmentFailureCannotBurnValidProofAndRetrySucceeds() public {
        (AirResponderCore c, MockVerifier v, MockTarget t) = _deploy();
        bytes32 id = keccak256("atomic-target-failure");
        _incidentTx(v, c, id, 1, 17, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        bytes32 qid = c.proofLocatorId(CHAIN_KEY, 130, 17);
        t.setReject(true);
        _expectIncidentRevert(c, 130, bytes("bad ai"));
        require(!c.consumedProofLocator(qid) && !c.incidentEverSeen(id), "failed target burned proof/event");
        _eq(uint8(c.effectiveMode()), 0, "failed target left containment state");
        t.setReject(false);
        c.processIncident(CHAIN_KEY, 130, _inc(), _cont(), bytes("bad ai"));
        require(c.consumedProofLocator(qid) && c.incidentEverSeen(id), "retry did not commit exactly once");
        _eq(t.mode(), 1, "retry did not apply objective WARNING floor");
    }

    function testExactProofLocatorReplayRejected() public {
        (AirResponderCore c, MockVerifier v,) = _deploy();
        bytes32 id = keccak256("replay");
        _incidentTx(v, c, id, 1, 18, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processIncident(CHAIN_KEY, 131, _inc(), _cont(), bytes("bad ai"));
        _expectIncidentRevert(c, 131, bytes("bad ai"));
        require(c.consumedProofLocator(c.proofLocatorId(CHAIN_KEY, 131, 18)), "accepted proof lost tombstone");
    }

    function testFreshVerifiedCausalRecoveryRestoresNormal() public {
        (AirResponderCore c, MockVerifier v, MockTarget t) = _deploy();
        bytes32 id = keccak256("causal-recovery");
        _incidentTx(v, c, id, 1, 20, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processIncident(CHAIN_KEY, 140, _inc(), _cont(), _recommend(c, id, 1, 140, 20, AirResponderCore.Mode.LIMITED));
        _eq(t.mode(), 1, "incident not LIMITED");
        _resolutionTx(v, c, id, 21, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        (, AirResponderCore.Mode next) = c.processResolution(CHAIN_KEY, 141, _inc(), _cont());
        require(uint8(next) == 0 && t.mode() == 0, "verified recovery did not restore NORMAL");
    }

    function testSameBlockEarlierRecoveryCannotRelaxContainment() public {
        (AirResponderCore c, MockVerifier v, MockTarget t) = _deploy();
        bytes32 id = keccak256("out-of-order");
        _incidentTx(v, c, id, 1, 22, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processIncident(CHAIN_KEY, 145, _inc(), _cont(), bytes("bad ai"));
        _resolutionTx(v, c, id, 21, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        _expectResolutionRevert(c, 145);
        _eq(t.mode(), 1, "non-causal recovery relaxed WARNING containment");
        (bool active,,,,) = c.incidents(id);
        require(active, "rejected recovery removed incident");
    }

    function testSameBlockLaterRecoveryIsCausal() public {
        (AirResponderCore c, MockVerifier v, MockTarget t) = _deploy();
        bytes32 id = keccak256("same-block-later");
        _incidentTx(v, c, id, 1, 22, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processIncident(CHAIN_KEY, 145, _inc(), _cont(), bytes("bad ai"));
        _resolutionTx(v, c, id, 23, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        (, AirResponderCore.Mode next) = c.processResolution(CHAIN_KEY, 145, _inc(), _cont());
        require(uint8(next) == 0 && t.mode() == 0, "later same-block recovery did not restore NORMAL");
        (bool active,,,,) = c.incidents(id);
        require(!active, "causal same-block recovery left incident active");
    }

    function testStrictestCompositionAndLocalRecovery() public {
        (AirResponderCore c, MockVerifier v, MockTarget t) = _deploy();
        bytes32 warning = keccak256("warning");
        bytes32 critical = keccak256("critical");
        _incidentTx(v, c, warning, 1, 30, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processIncident(
            CHAIN_KEY, 150, _inc(), _cont(), _recommend(c, warning, 1, 150, 30, AirResponderCore.Mode.LIMITED)
        );
        _incidentTx(v, c, critical, 2, 31, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processIncident(CHAIN_KEY, 151, _inc(), _cont(), bytes("bad ai"));
        _eq(t.mode(), 2, "critical did not dominate warning");
        _resolutionTx(v, c, warning, 32, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processResolution(CHAIN_KEY, 152, _inc(), _cont());
        _eq(t.mode(), 2, "recovering warning cleared active critical incident");
        _resolutionTx(v, c, critical, 33, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processResolution(CHAIN_KEY, 153, _inc(), _cont());
        _eq(t.mode(), 0, "all recovered did not restore NORMAL");
    }

    function testIncidentIdCannotBeReusedAfterRecovery() public {
        (AirResponderCore c, MockVerifier v,) = _deploy();
        bytes32 id = keccak256("never-reuse");
        _incidentTx(v, c, id, 1, 40, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processIncident(CHAIN_KEY, 160, _inc(), _cont(), bytes("bad ai"));
        _resolutionTx(v, c, id, 41, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processResolution(CHAIN_KEY, 161, _inc(), _cont());
        _incidentTx(v, c, id, 1, 42, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        _expectIncidentRevert(c, 162, bytes("bad ai"));
        require(c.incidentEverSeen(id), "incident tombstone removed after recovery");
    }

    function testIncidentAdmissionClosesButFreshLateActiveRecoveryRemainsAvailable() public {
        (AirResponderCore c, MockVerifier v, MockTarget t, MockChainInfo info) = _deployWithChainInfo();
        bytes32 staleId = keccak256("stale-incident");
        _incidentTx(v, c, staleId, 1, 43, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        _expectIncidentRevert(c, 99, bytes("bad ai"));
        require(!c.consumedProofLocator(c.proofLocatorId(CHAIN_KEY, 99, 43)), "stale incident consumed proof locator");
        require(!c.incidentEverSeen(staleId), "stale incident burned id");
        require(t.calls() == 0, "stale incident reached target");

        bytes32 futureId = keccak256("future-incident");
        _incidentTx(v, c, futureId, 1, 44, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        _expectIncidentRevert(c, 201, bytes("bad ai"));
        require(!c.consumedProofLocator(c.proofLocatorId(CHAIN_KEY, 201, 44)), "future incident consumed proof locator");
        require(!c.incidentEverSeen(futureId), "future incident burned id");

        bytes32 activeId = keccak256("late-recovery");
        _incidentTx(v, c, activeId, 1, 45, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processIncident(CHAIN_KEY, 190, _inc(), _cont(), bytes("bad ai"));
        _eq(t.mode(), 1, "active WARNING did not apply objective floor before late recovery attempt");
        _resolutionTx(v, c, activeId, 46, SOURCE_CHAIN, EMITTER, 1, c.policyHash());

        // 251 is beyond validUntil(200) + legacy recoveryGrace(50), but freshness remains mandatory.
        info.setLatest(352, true);
        _expectResolutionRevert(c, 251);
        require(
            !c.consumedProofLocator(c.proofLocatorId(CHAIN_KEY, 251, 46)), "stale late recovery consumed proof locator"
        );
        _eq(t.mode(), 1, "stale late recovery relaxed WARNING containment");
        (bool activeBeforeFreshRetry,,,,) = c.incidents(activeId);
        require(activeBeforeFreshRetry, "stale late recovery removed active incident");

        // Once the same authenticated recovery position is within the native freshness bound, it can close the
        // already-active incident even though the new-incident admission epoch has ended.
        info.setLatest(251, true);
        c.processResolution(CHAIN_KEY, 251, _inc(), _cont());
        require(
            c.consumedProofLocator(c.proofLocatorId(CHAIN_KEY, 251, 46)), "fresh late recovery missed proof locator"
        );
        _eq(t.mode(), 0, "fresh late recovery did not restore NORMAL");
        (bool activeAfterFreshRetry,,,,) = c.incidents(activeId);
        require(!activeAfterFreshRetry, "fresh late recovery left incident active");
    }

    function testNativeChainInfoFreshnessRejectsStaleFutureAndUnavailableEvidenceWithoutBurning() public {
        (AirResponderCore c, MockVerifier v, MockTarget t, MockChainInfo info) = _deployWithChainInfo();

        bytes32 staleId = keccak256("native-stale");
        info.setLatest(220, true);
        _incidentTx(v, c, staleId, 1, 48, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        _expectIncidentRevert(c, 119, bytes("bad ai")); // 101 blocks behind, policy max is 100.
        require(!c.consumedProofLocator(c.proofLocatorId(CHAIN_KEY, 119, 48)), "native stale evidence burned locator");
        require(!c.incidentEverSeen(staleId) && t.calls() == 0, "native stale evidence mutated state");

        bytes32 futureId = keccak256("native-not-yet-attested");
        info.setLatest(179, true);
        _incidentTx(v, c, futureId, 1, 49, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        _expectIncidentRevert(c, 180, bytes("bad ai"));
        require(
            !c.consumedProofLocator(c.proofLocatorId(CHAIN_KEY, 180, 49)), "unattested future evidence burned locator"
        );
        require(!c.incidentEverSeen(futureId) && t.calls() == 0, "unattested future evidence mutated state");

        bytes32 unavailableId = keccak256("native-head-unavailable");
        info.setLatest(180, false);
        _incidentTx(v, c, unavailableId, 1, 50, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        _expectIncidentRevert(c, 180, bytes("bad ai"));
        require(!c.consumedProofLocator(c.proofLocatorId(CHAIN_KEY, 180, 50)), "unavailable ChainInfo burned locator");
        require(!c.incidentEverSeen(unavailableId) && t.calls() == 0, "unavailable ChainInfo mutated state");

        bytes32 boundaryId = keccak256("native-lag-boundary");
        info.setLatest(200, true);
        _incidentTx(v, c, boundaryId, 1, 51, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processIncident(CHAIN_KEY, 100, _inc(), _cont(), bytes("bad ai"));
        require(c.consumedProofLocator(c.proofLocatorId(CHAIN_KEY, 100, 51)), "inclusive max-lag boundary rejected");
        require(c.incidentEverSeen(boundaryId) && t.calls() == 1, "max-lag boundary did not contain");
    }

    function testFreshCriticalObservationCanContainAfterUnrelayedProofGoesStale() public {
        (AirResponderCore c, MockVerifier v, MockTarget t, MockChainInfo info) = _deployWithChainInfo();
        bytes32 id = keccak256("critical-refresh");
        info.setLatest(200, true);
        _incidentTx(v, c, id, 2, 60, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        info.setLatest(301, true);
        _expectIncidentRevert(c, 200, bytes("bad ai"));
        require(!c.incidentEverSeen(id) && t.calls() == 0, "stale unrelayed critical mutated destination");

        info.setLatest(200, true);
        _incidentTx(v, c, id, 2, 61, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processIncident(CHAIN_KEY, 190, _inc(), _cont(), bytes("bad ai"));
        _eq(t.mode(), 2, "fresh critical observation did not freeze");
        _eq(c.frozenCount(), 1, "fresh observation double-counted freeze");
        require(c.incidentEverSeen(id), "fresh observation missed incident id");
    }

    function testSameIncidentCriticalObservationStrengthensWithoutASecondCount() public {
        (AirResponderCore c, MockVerifier v, MockTarget t) = _deploy();
        bytes32 id = keccak256("one-incident");
        _incidentTx(v, c, id, 1, 62, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processIncident(CHAIN_KEY, 150, _inc(), _cont(), bytes("bad ai"));
        _eq(t.mode(), 1, "warning observation did not apply LIMITED");
        _incidentTx(v, c, id, 2, 63, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processIncident(CHAIN_KEY, 151, _inc(), _cont(), bytes("bad ai"));
        _eq(t.mode(), 2, "same-id critical observation did not freeze");
        _eq(c.limitedCount(), 0, "escalation left a LIMITED count");
        _eq(c.frozenCount(), 1, "escalation counted a second incident");
        _resolutionTx(v, c, id, 64, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processResolution(CHAIN_KEY, 152, _inc(), _cont());
        _eq(t.mode(), 0, "single logical incident needed two recoveries");
    }

    function testActiveIncidentRefreshCannotWeakenAndMustBeCausal() public {
        (AirResponderCore c, MockVerifier v, MockTarget t) = _deploy();
        bytes32 id = keccak256("no-weaken");
        _incidentTx(v, c, id, 1, 65, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processIncident(
            CHAIN_KEY, 150, _inc(), _cont(), _recommend(c, id, 1, 150, 65, AirResponderCore.Mode.FROZEN)
        );
        _eq(t.mode(), 2, "signed warning did not freeze");
        _incidentTx(v, c, id, 1, 66, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        _expectIncidentRevert(c, 149, bytes("bad ai"));
        c.processIncident(CHAIN_KEY, 151, _inc(), _cont(), bytes("bad ai"));
        _eq(t.mode(), 2, "later unsigned warning weakened freeze");
        _eq(c.frozenCount(), 1, "refresh altered freeze occupancy");
    }

    function testSourceEmitterDerivesSeverityFromTreasuryStateAndBlocksEarlyRecovery() public {
        SourceTreasury treasury = new SourceTreasury();
        PaymentSink sink = new PaymentSink();
        SourceIncidentEmitter emitter = new SourceIncidentEmitter(address(this), address(treasury), 200 wei, 100 wei);
        (bool funded,) = address(treasury).call{value: 250 wei}("");
        require(funded && emitter.currentSeverity() == 0, "healthy treasury setup failed");

        bytes32 warningId = keccak256("objective-warning");
        (bool healthyRaise,) = address(emitter)
            .call(
                abi.encodeWithSelector(emitter.raiseIncident.selector, warningId, DEPLOY, uint8(1), bytes32(uint256(1)))
            );
        require(!healthyRaise, "healthy treasury emitted incident");

        treasury.pay(payable(address(sink)), 75 wei); // 175 => warning.
        require(emitter.currentSeverity() == 1, "warning threshold not derived");
        (bool inventedCritical,) = address(emitter)
            .call(
                abi.encodeWithSelector(emitter.raiseIncident.selector, warningId, DEPLOY, uint8(2), bytes32(uint256(1)))
            );
        require(!inventedCritical, "guardian invented critical severity");
        emitter.raiseIncident(warningId, DEPLOY, 1, bytes32(uint256(1)));
        emitter.raiseIncident(warningId, DEPLOY, 1, bytes32(uint256(1)));
        require(emitter.lastRaisedIncidentId() == warningId, "refresh moved the logical incident");
        (bool duplicateWarning,) = address(emitter)
            .call(
                abi.encodeWithSelector(
                    emitter.raiseIncident.selector,
                    keccak256("duplicate-warning"),
                    DEPLOY,
                    uint8(1),
                    bytes32(uint256(1))
                )
            );
        require(!duplicateWarning, "same-severity raise with a new incident id was accepted");

        treasury.pay(payable(address(sink)), 100 wei); // 75 => critical.
        require(emitter.currentSeverity() == 2, "critical threshold not derived");
        bytes32 criticalId = keccak256("objective-critical");
        emitter.raiseIncident(criticalId, DEPLOY, 2, bytes32(uint256(1)));
        (bool earlyRecovery,) = address(emitter)
            .call(abi.encodeWithSelector(emitter.resolveIncident.selector, criticalId, DEPLOY, bytes32(uint256(1))));
        require(!earlyRecovery, "source emitted recovery while objective risk remained");

        (bool replenished,) = address(treasury).call{value: 200 wei}(""); // 275 => healthy.
        require(replenished && emitter.currentSeverity() == 0, "treasury recovery setup failed");
        emitter.resolveIncident(criticalId, DEPLOY, bytes32(uint256(1)));
        emitter.resolveIncident(warningId, DEPLOY, bytes32(uint256(1)));
        require(emitter.lastRaisedSeverity() == 0, "objective recovery did not reset escalation state");
    }

    function testWrongChainKeyRejectedBeforeProofAndWithoutStateChange() public {
        (AirResponderCore c, MockVerifier v, MockTarget t) = _deploy();
        bytes32 id = keccak256("wrong-chain-key");
        _incidentTx(v, c, id, 1, 47, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        uint64 wrongKey = 2;
        try c.processIncident(wrongKey, 180, _inc(), _cont(), bytes("bad ai")) returns (
            bytes32, AirResponderCore.Mode, bool
        ) {
            revert("expected wrong chain key rejection");
        } catch {}
        require(!c.consumedProofLocator(c.proofLocatorId(wrongKey, 180, 47)), "wrong chain key consumed proof locator");
        require(!c.incidentEverSeen(id), "wrong chain key burned incident");
        require(t.calls() == 0 && uint8(c.effectiveMode()) == 0, "wrong chain key mutated state");
    }

    function testGuardedVaultProofToEconomicActionAndProductionVerifierOwnership() public {
        MockVerifier v = new MockVerifier();
        SentryVault vault = new SentryVault(address(this), 100 wei);
        MockChainInfo info = new MockChainInfo();
        AirResponderCore c = new AirResponderCore(v, info, vault, vm.addr(RECOMMENDER_PK), _policy());
        vault.bindResponder(address(c));
        PaymentSink sink = new PaymentSink();
        UnauthorizedVaultCaller attacker = new UnauthorizedVaultCaller();

        // Fund the only value-bearing target. In NORMAL the designated operator can pay normally.
        (bool funded,) = address(vault).call{value: 500 wei}("");
        require(funded, "vault funding failed");
        vault.executePayment(payable(address(sink)), 200 wei);
        _eq(address(sink).balance, 200 wei, "normal payment did not execute");

        // Neither arbitrary callers nor the owner-facing containment function can bypass roles.
        require(!attacker.tryPayment(vault, payable(address(sink)), 1 wei), "non-operator executed payment");
        (bool unauthorizedMode,) = address(vault).call(abi.encodeWithSelector(vault.applyMode.selector, uint8(2)));
        require(!unauthorizedMode, "non-responder changed vault mode");

        bytes32 warning = keccak256("vault-warning");
        _incidentTx(v, c, warning, 1, 50, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processIncident(
            CHAIN_KEY, 170, _inc(), _cont(), _recommend(c, warning, 1, 170, 50, AirResponderCore.Mode.LIMITED)
        );
        _eq(uint8(vault.mode()), 1, "verified warning did not LIMIT treasury");

        // LIMITED is a cumulative incident budget, so splitting calls cannot exceed it.
        vault.executePayment(payable(address(sink)), 60 wei);
        vault.executePayment(payable(address(sink)), 40 wei);
        _eq(vault.limitedSpent(), 100 wei, "limited cumulative spend wrong");
        (bool splitBypass,) = address(vault)
            .call(abi.encodeWithSelector(SentryVault.executePayment.selector, payable(address(sink)), 1 wei));
        require(!splitBypass, "split payments bypassed LIMITED budget");

        // A concurrent critical incident escalates to FROZEN: even one wei is stopped.
        bytes32 critical = keccak256("vault-critical");
        _incidentTx(v, c, critical, 2, 51, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processIncident(CHAIN_KEY, 171, _inc(), _cont(), bytes("malformed-ai"));
        _eq(uint8(vault.mode()), 2, "verified critical incident did not freeze treasury");
        (bool frozenBypass,) = address(vault)
            .call(abi.encodeWithSelector(SentryVault.executePayment.selector, payable(address(sink)), 1 wei));
        require(!frozenBypass, "FROZEN treasury paid value");

        // Recovering only the critical incident returns to LIMITED without resetting the already-spent budget.
        _resolutionTx(v, c, critical, 52, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processResolution(CHAIN_KEY, 172, _inc(), _cont());
        _eq(uint8(vault.mode()), 1, "critical recovery should reveal active warning");
        _eq(vault.limitedSpent(), 100 wei, "LIMITED budget reset through FROZEN transition");
        (bool transitionResetBypass,) = address(vault)
            .call(abi.encodeWithSelector(SentryVault.executePayment.selector, payable(address(sink)), 1 wei));
        require(!transitionResetBypass, "FROZEN-to-LIMITED transition reset quota");

        // Only verified recovery of the final active incident returns NORMAL and starts a fresh budget.
        _resolutionTx(v, c, warning, 53, SOURCE_CHAIN, EMITTER, 1, c.policyHash());
        c.processResolution(CHAIN_KEY, 173, _inc(), _cont());
        _eq(uint8(vault.mode()), 0, "final verified recovery did not restore NORMAL");
        _eq(vault.limitedSpent(), 0, "NORMAL recovery did not reset budget");
        vault.executePayment(payable(address(sink)), 1 wei);
        _eq(address(sink).balance, 301 wei, "post-recovery payment did not resume");

        MockTarget t = new MockTarget();
        address signer = vm.addr(RECOMMENDER_PK);
        AttestedIncidentResponder production = new AttestedIncidentResponder(t, signer, _policy());
        address verifierAddress = address(production.verifier());
        require(verifierAddress != address(0) && verifierAddress.code.length > 0, "production ASC verifier missing");
        require(verifierAddress != address(t), "verifier aliases target");
        require(address(production.chainInfo()) == address(uint160(0xFD3)), "production ChainInfo is not native 0xFD3");
        require(production.recommenderSigner() == signer, "production recommender signer mismatch");
    }

    function _assertRejectedSource(
        bytes32 id,
        uint64 height,
        uint64 index,
        uint64 chainId,
        address emitter,
        uint8 receipt,
        bytes32 policyOverride,
        uint8 kind
    ) internal {
        (AirResponderCore c, MockVerifier v, MockTarget t) = _deploy();
        bytes32 p = kind == 4 ? policyOverride : c.policyHash();
        _incidentTx(v, c, id, 1, index, chainId, emitter, receipt, p);
        _expectIncidentRevert(c, height, bytes("bad ai"));
        require(
            !c.consumedProofLocator(c.proofLocatorId(CHAIN_KEY, height, index)),
            "rejected source consumed proof locator"
        );
        require(!c.incidentEverSeen(id), "rejected source burned incident");
        require(t.calls() == 0 && uint8(c.effectiveMode()) == 0, "rejected source mutated containment");
    }

    function _deploy() internal returns (AirResponderCore c, MockVerifier v, MockTarget t) {
        MockChainInfo info;
        (c, v, t, info) = _deployWithChainInfo();
    }

    function _deployWithChainInfo()
        internal
        returns (AirResponderCore c, MockVerifier v, MockTarget t, MockChainInfo info)
    {
        v = new MockVerifier();
        t = new MockTarget();
        info = new MockChainInfo();
        c = new AirResponderCore(v, info, t, vm.addr(RECOMMENDER_PK), _policy());
    }

    function _policy() internal pure returns (AirResponderCore.Policy memory) {
        return AirResponderCore.Policy(DEPLOY, CHAIN_KEY, SOURCE_CHAIN, EMITTER, 100, 200, 50, 100);
    }

    function _incidentTx(
        MockVerifier v,
        AirResponderCore c,
        bytes32 id,
        uint8 severity,
        uint64 index,
        uint64 chainId,
        address emitter,
        uint8 receipt,
        bytes32 sourcePolicy
    ) internal {
        bytes memory data = abi.encodeWithSelector(c.RAISE_SELECTOR(), id, DEPLOY, severity, sourcePolicy);
        v.configure(_encoded(data, chainId, emitter, receipt), index);
    }

    function _resolutionTx(
        MockVerifier v,
        AirResponderCore c,
        bytes32 id,
        uint64 index,
        uint64 chainId,
        address emitter,
        uint8 receipt,
        bytes32 sourcePolicy
    ) internal {
        bytes memory data = abi.encodeWithSelector(c.RESOLVE_SELECTOR(), id, DEPLOY, sourcePolicy);
        v.configure(_encoded(data, chainId, emitter, receipt), index);
    }

    function _recommend(
        AirResponderCore c,
        bytes32 id,
        uint8 severity,
        uint64 height,
        uint64 index,
        AirResponderCore.Mode mode
    ) internal returns (bytes memory) {
        return _recommendWithKey(c, id, severity, height, index, mode, RECOMMENDER_PK, type(uint64).max);
    }

    function _recommendWithKey(
        AirResponderCore c,
        bytes32 id,
        uint8 severity,
        uint64 height,
        uint64 index,
        AirResponderCore.Mode mode,
        uint256 privateKey,
        uint64 validUntil
    ) internal returns (bytes memory) {
        bytes32 qid = c.proofLocatorId(CHAIN_KEY, height, index);
        bytes32 fingerprint = c.recommendationFingerprint(qid, id, severity);
        bytes32 rationaleHash = keccak256("bounded-rationale");
        bytes32 digest = c.recommendationDigest(fingerprint, mode, rationaleHash, validUntil);
        (uint8 sigV, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encode(fingerprint, uint8(mode), rationaleHash, validUntil, r, s, sigV);
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

    function _expectIncidentRevert(AirResponderCore c, uint64 height, bytes memory ai) internal {
        (bool ok,) =
            address(c).call(abi.encodeWithSelector(c.processIncident.selector, CHAIN_KEY, height, _inc(), _cont(), ai));
        require(!ok, "expected incident reject");
    }

    function _expectResolutionRevert(AirResponderCore c, uint64 height) internal {
        (bool ok,) =
            address(c).call(abi.encodeWithSelector(c.processResolution.selector, CHAIN_KEY, height, _inc(), _cont()));
        require(!ok, "expected resolution reject");
    }

    function _eq(uint256 actual, uint256 expected, string memory message) internal pure {
        require(actual == expected, message);
    }
}
