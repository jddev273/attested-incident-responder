// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAirContainmentTarget} from "./AttestedIncidentResponder.sol";

/// @notice Safe transaction Guard (execTransaction).
interface IAirTransactionGuard {
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    ) external;

    function checkAfterExecution(bytes32 txHash, bool success) external;
}

/// @notice Safe module Guard (execTransactionFromModule). Installing only the transaction Guard
/// leaves module transfers unconstrained.
interface IAirModuleGuard {
    function checkModuleTransaction(
        address to,
        uint256 value,
        bytes memory data,
        uint8 operation,
        address module
    ) external returns (bytes32 moduleTxHash);

    function checkAfterModuleExecution(bytes32 txHash, bool success) external;
}

/// @notice AIR containment target for an existing Safe. Install this address as both the
/// transaction Guard and the module Guard. NORMAL is unrestricted. LIMITED caps native Call
/// value and requires gasPrice == 0 so ETH refunds cannot bypass the budget. FROZEN rejects
/// every transaction and module execution. Failed inner execution reverts so LIMITED accounting
/// cannot stick without a successful spend.
contract AirSafeGuard is IAirContainmentTarget, IAirTransactionGuard, IAirModuleGuard {
    enum Mode {
        NORMAL,
        LIMITED,
        FROZEN
    }

    address public immutable owner;
    address public immutable safe;
    uint256 public immutable limitedBudget;
    address public responder;
    Mode public mode;
    uint256 public limitedSpent;

    error NotOwner();
    error NotResponder();
    error NotSafe();
    error ResponderAlreadyBound();
    error InvalidResponder();
    error InvalidSafe();
    error InvalidMode();
    error InvalidLimitedBudget();
    error GuardFrozen();
    error GuardDelegateCall();
    error GuardCalldataNotAllowed();
    error GuardRefundToken();
    error GuardGasRefund();
    error GuardExecutionFailed();
    error LimitedBudgetExceeded();

    event ResponderBound(address indexed responder);
    event ModeChanged(Mode indexed previousMode, Mode indexed newMode);

    constructor(address safe_, uint256 limitedBudget_) {
        owner = msg.sender;
        if (safe_ == address(0)) revert InvalidSafe();
        if (limitedBudget_ == 0) revert InvalidLimitedBudget();
        safe = safe_;
        limitedBudget = limitedBudget_;
    }

    function bindResponder(address responder_) external {
        if (msg.sender != owner) revert NotOwner();
        if (responder != address(0)) revert ResponderAlreadyBound();
        if (responder_ == address(0) || responder_.code.length == 0) revert InvalidResponder();
        responder = responder_;
        emit ResponderBound(responder_);
    }

    function applyMode(uint8 mode_) external {
        if (msg.sender != responder) revert NotResponder();
        if (mode_ > uint8(Mode.FROZEN)) revert InvalidMode();
        Mode next = Mode(mode_);
        Mode previous = mode;
        mode = next;
        if (next == Mode.NORMAL) limitedSpent = 0;
        emit ModeChanged(previous, next);
    }

    function checkTransaction(
        address,
        uint256 value,
        bytes memory data,
        uint8 operation,
        uint256,
        uint256,
        uint256 gasPrice,
        address gasToken,
        address payable,
        bytes memory,
        address
    ) external {
        if (msg.sender != safe) revert NotSafe();
        if (mode == Mode.NORMAL) return;
        if (gasPrice != 0) revert GuardGasRefund();
        if (gasToken != address(0)) revert GuardRefundToken();
        _enforce(value, data, operation);
    }

    function checkAfterExecution(bytes32, bool success) external {
        if (msg.sender != safe) revert NotSafe();
        if (!success) revert GuardExecutionFailed();
    }

    function checkModuleTransaction(address, uint256 value, bytes memory data, uint8 operation, address)
        external
        returns (bytes32 moduleTxHash)
    {
        if (msg.sender != safe) revert NotSafe();
        if (mode != Mode.NORMAL) {
            _enforce(value, data, operation);
        }
        moduleTxHash = keccak256(abi.encode(value, keccak256(data), operation, limitedSpent, mode));
    }

    function checkAfterModuleExecution(bytes32, bool success) external {
        if (msg.sender != safe) revert NotSafe();
        if (!success) revert GuardExecutionFailed();
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x01ffc9a7 || interfaceId == 0xe6d7a83a
            || interfaceId == type(IAirModuleGuard).interfaceId;
    }

    function _enforce(uint256 value, bytes memory data, uint8 operation) internal {
        if (mode == Mode.FROZEN) revert GuardFrozen();
        if (operation != 0) revert GuardDelegateCall();
        if (data.length != 0) revert GuardCalldataNotAllowed();
        uint256 nextSpent = limitedSpent + value;
        if (nextSpent > limitedBudget) revert LimitedBudgetExceeded();
        limitedSpent = nextSpent;
    }
}
