// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "./Vm.sol";

/// @dev Minimal replacement for `forge-std/Script.sol` used by this scaffold.
abstract contract Script {
    Vm internal constant vm =
        Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
}
