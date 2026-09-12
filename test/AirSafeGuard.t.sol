// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AirResponderCore, IAirContainmentTarget} from "../src/AttestedIncidentResponder.sol";
import {AirSafeGuard} from "../src/AirSafeGuard.sol";
import {PauseTarget} from "../src/PauseTarget.sol";
import {BlockProverTypes} from "@gluwa/asc-contracts/contracts/write-ability/common/BlockProverTypes.sol";
import {EvmV1Decoder} from "@gluwa/asc-contracts/contracts/common/EvmV1Decoder.sol";
import {MockVerifier, MockChainInfo} from "./AirResponder.t.sol";

interface VmGuard {
    function addr(uint256 privateKey) external returns (address);
}

contract MockSafe {
    function exec(
        AirSafeGuard guard,
        address to,
        uint256 value,
        bytes memory data,
        uint8 operation,
        uint256 gasPrice
    ) external {
        guard.checkTransaction(
            to, value, data, operation, 0, 0, gasPrice, address(0), payable(address(0)), "", address(this)
        );
        guard.checkAfterExecution(bytes32(0), true);
    }

    function execFailed(AirSafeGuard guard, address to, uint256 value) external {
        guard.checkTransaction(to, value, bytes(""), 0, 0, 0, 0, address(0), payable(address(0)), "", address(this));
        guard.checkAfterExecution(bytes32(0), false);
    }

    function execModule(AirSafeGuard guard, address to, uint256 value, bytes memory data, uint8 operation) external {
        bytes32 hash_ = guard.checkModuleTransaction(to, value, data, operation, address(this));
        guard.checkAfterModuleExecution(hash_, true);
    }
}

contract AirSafeGuardTest {
    VmGuard constant vm = VmGuard(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 constant DEPLOY = keccak256("air-deployment");
    uint64 constant CHAIN_KEY = 1;
    uint64 constant SOURCE_CHAIN = 11_155_111;
    address constant EMITTER = address(0xBEEF);
    uint256 constant RECOMMENDER_PK = 0xA11CE;

    function testExistingSafePaymentStopsWhenAirFreezesAndResumesAfterRecovery() public {
        MockSafe safe = new MockSafe();
        AirSafeGuard guard = new AirSafeGuard(address(safe), 1 ether);
        (AirResponderCore c, MockVerifier v) = _bind(guard);
        address to = address(0x1111);

        safe.exec(guard, to, 0.01 ether, bytes(""), 0, 0);

        bytes32 id = keccak256("safe-critical");
        _incidentTx(v, c, id, 2, 70, 120);
        c.processIncident(CHAIN_KEY, 120, _inc(), _cont(), bytes(""));
        require(uint8(guard.mode()) == 2, "AIR did not freeze the Safe guard");
        (bool frozenOk,) = address(safe).call(abi.encodeWithSelector(safe.exec.selector, guard, to, 0.01 ether, bytes(""), uint8(0), uint256(0)));
        require(!frozenOk, "frozen Safe still executed");

        _resolutionTx(v, c, id, 71, 121);
        c.processResolution(CHAIN_KEY, 121, _inc(), _cont());
        require(uint8(guard.mode()) == 0, "recovery did not restore Safe");
        safe.exec(guard, to, 0.01 ether, bytes(""), 0, 0);
    }

    function testLimitedSafeSpendIsCappedAndDelegateCallIsRejected() public {
        MockSafe safe = new MockSafe();
        AirSafeGuard guard = new AirSafeGuard(address(safe), 0.02 ether);
        (AirResponderCore c, MockVerifier v) = _bind(guard);
        bytes32 id = keccak256("safe-warning");
        _incidentTx(v, c, id, 1, 72, 130);
        c.processIncident(CHAIN_KEY, 130, _inc(), _cont(), bytes(""));
        safe.exec(guard, address(0x1111), 0.01 ether, bytes(""), 0, 0);
        safe.exec(guard, address(0x1111), 0.01 ether, bytes(""), 0, 0);
        (bool over,) = address(safe).call(
            abi.encodeWithSelector(safe.exec.selector, guard, address(0x1111), uint256(1), bytes(""), uint8(0), uint256(0))
        );
        require(!over, "LIMITED Safe exceeded native budget");
        (bool delegated,) = address(safe).call(
            abi.encodeWithSelector(safe.exec.selector, guard, address(0x1111), uint256(0), bytes(""), uint8(1), uint256(0))
        );
        require(!delegated, "LIMITED Safe allowed delegatecall");
        (bool calldataMove,) = address(safe).call(
            abi.encodeWithSelector(safe.exec.selector, guard, address(0x1111), uint256(0), bytes("0xdead"), uint8(0), uint256(0))
        );
        require(!calldataMove, "LIMITED Safe allowed calldata");
        (bool refund,) = address(safe).call(
            abi.encodeWithSelector(safe.exec.selector, guard, address(0x1111), uint256(0), bytes(""), uint8(0), uint256(1))
        );
        require(!refund, "LIMITED Safe allowed native gas refund");
    }

    function testModulePathIsFrozenAndLimitedLikeExecTransaction() public {
        MockSafe safe = new MockSafe();
        AirSafeGuard guard = new AirSafeGuard(address(safe), 0.01 ether);
        (AirResponderCore c, MockVerifier v) = _bind(guard);
        bytes32 id = keccak256("safe-module");
        _incidentTx(v, c, id, 1, 75, 132);
        c.processIncident(CHAIN_KEY, 132, _inc(), _cont(), bytes(""));
        safe.execModule(guard, address(0x1111), 0.01 ether, bytes(""), 0);
        (bool over,) = address(safe).call(
            abi.encodeWithSelector(safe.execModule.selector, guard, address(0x1111), uint256(1), bytes(""), uint8(0))
        );
        require(!over, "LIMITED module exceeded native budget");
        _incidentTx(v, c, id, 2, 76, 133);
        c.processIncident(CHAIN_KEY, 133, _inc(), _cont(), bytes(""));
        (bool frozenMod,) = address(safe).call(
            abi.encodeWithSelector(safe.execModule.selector, guard, address(0x1111), uint256(0), bytes(""), uint8(0))
        );
        require(!frozenMod, "FROZEN module still executed");
    }

    function testUnsuccessfulSafeExecutionDoesNotKeepLimitedSpend() public {
        MockSafe safe = new MockSafe();
        AirSafeGuard guard = new AirSafeGuard(address(safe), 1 ether);
        (AirResponderCore c, MockVerifier v) = _bind(guard);
        bytes32 id = keccak256("safe-fail");
        _incidentTx(v, c, id, 1, 77, 134);
        c.processIncident(CHAIN_KEY, 134, _inc(), _cont(), bytes(""));
        (bool failed,) = address(safe).call(abi.encodeWithSelector(safe.execFailed.selector, guard, address(0x1111), uint256(0.5 ether)));
        require(!failed, "failed inner execution did not revert the guard");
        require(guard.limitedSpent() == 0, "failed execution consumed LIMITED budget");
        safe.exec(guard, address(0x1111), 0.5 ether, bytes(""), 0, 0);
        require(guard.limitedSpent() == 0.5 ether, "successful spend was not counted");
    }

    function testPauseTargetIsASecondContainmentSinkForTheSameResponderShape() public {
        PauseTarget pause = new PauseTarget(1);
        (AirResponderCore c, MockVerifier v) = _bindPause(pause);
        pause.act();
        bytes32 id = keccak256("pause-critical");
        _incidentTx(v, c, id, 2, 73, 140);
        c.processIncident(CHAIN_KEY, 140, _inc(), _cont(), bytes(""));
        (bool paused,) = address(pause).call(abi.encodeWithSelector(pause.act.selector));
        require(!paused, "FROZEN PauseTarget still ran");
        _resolutionTx(v, c, id, 74, 141);
        c.processResolution(CHAIN_KEY, 141, _inc(), _cont());
        pause.act();
    }

    function _bind(AirSafeGuard guard) internal returns (AirResponderCore c, MockVerifier v) {
        v = new MockVerifier();
        MockChainInfo info = new MockChainInfo();
        c = new AirResponderCore(v, info, IAirContainmentTarget(address(guard)), vm.addr(RECOMMENDER_PK), _policy());
        guard.bindResponder(address(c));
    }

    function _bindPause(PauseTarget pause) internal returns (AirResponderCore c, MockVerifier v) {
        v = new MockVerifier();
        MockChainInfo info = new MockChainInfo();
        c = new AirResponderCore(v, info, IAirContainmentTarget(address(pause)), vm.addr(RECOMMENDER_PK), _policy());
        pause.bindResponder(address(c));
    }

    function _policy() internal pure returns (AirResponderCore.Policy memory) {
        return AirResponderCore.Policy(DEPLOY, CHAIN_KEY, SOURCE_CHAIN, EMITTER, 100, 200, 50, 100);
    }

    function _incidentTx(MockVerifier v, AirResponderCore c, bytes32 id, uint8 severity, uint64 index, uint64 height)
        internal
    {
        height;
        bytes memory data = abi.encodeWithSelector(c.RAISE_SELECTOR(), id, DEPLOY, severity, c.policyHash());
        v.configure(_encoded(data), index);
    }

    function _resolutionTx(MockVerifier v, AirResponderCore c, bytes32 id, uint64 index, uint64 height) internal {
        height;
        bytes memory data = abi.encodeWithSelector(c.RESOLVE_SELECTOR(), id, DEPLOY, c.policyHash());
        v.configure(_encoded(data), index);
    }

    function _encoded(bytes memory data) internal pure returns (bytes memory) {
        bytes[] memory chunks = new bytes[](3);
        chunks[0] = abi.encode(uint64(1), uint64(200_000), address(0xA11CE), false, EMITTER, uint256(0), data);
        EvmV1Decoder.AccessListEntryBytes32[] memory accessList = new EvmV1Decoder.AccessListEntryBytes32[](0);
        chunks[1] = abi.encode(SOURCE_CHAIN, uint128(1), uint128(2), accessList, uint8(0), bytes32(0), bytes32(0));
        EvmV1Decoder.LogEntryTuple[] memory logs = new EvmV1Decoder.LogEntryTuple[](0);
        chunks[2] = abi.encode(uint8(1), uint64(120_000), logs, bytes(""));
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
}
