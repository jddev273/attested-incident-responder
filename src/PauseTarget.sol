// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAirContainmentTarget} from "./AttestedIncidentResponder.sol";

/// @notice Minimal non-vault containment target: AIR can pause or restrict an existing module.
contract PauseTarget is IAirContainmentTarget {
    enum Mode {
        NORMAL,
        LIMITED,
        FROZEN
    }

    address public immutable owner;
    address public responder;
    Mode public mode;
    uint256 public limitedCalls;
    uint256 public immutable limitedQuota;

    error NotOwner();
    error NotResponder();
    error ResponderAlreadyBound();
    error InvalidResponder();
    error InvalidMode();
    error InvalidQuota();
    error Paused();
    error LimitedQuotaExceeded();

    event ResponderBound(address indexed responder);
    event ModeChanged(Mode indexed previousMode, Mode indexed newMode);
    event Action(address indexed caller, Mode mode);

    constructor(uint256 limitedQuota_) {
        owner = msg.sender;
        if (limitedQuota_ == 0) revert InvalidQuota();
        limitedQuota = limitedQuota_;
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
        if (next == Mode.NORMAL) limitedCalls = 0;
        emit ModeChanged(previous, next);
    }

    function act() external {
        Mode current = mode;
        if (current == Mode.FROZEN) revert Paused();
        if (current == Mode.LIMITED) {
            uint256 next = limitedCalls + 1;
            if (next > limitedQuota) revert LimitedQuotaExceeded();
            limitedCalls = next;
        }
        emit Action(msg.sender, current);
    }
}
