// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev Minimal cheatcode interface required by the local deployment script.
interface Vm {
    function envUint(string calldata name) external view returns (uint256 value);

    function startBroadcast(uint256 privateKey) external;

    function stopBroadcast() external;
}
