// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {PqspVerifier} from "../src/PqspVerifier.sol";

/// @notice Minimal Foundry deployment script for the PQSP verifier registry.
/// @dev Expects `0G_PRIVATE_KEY` to be present in the environment. Broadcast
///      against the target 0G RPC with:
///      `forge script script/DeployPqspVerifier.s.sol:DeployPqspVerifier --rpc-url <0G_CHAIN_RPC_URL> --broadcast`
contract DeployPqspVerifier is Script {
    function run() external returns (PqspVerifier verifier) {
        uint256 deployerPrivateKey = vm.envUint("0G_PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);
        verifier = new PqspVerifier();
        vm.stopBroadcast();

        return verifier;
    }
}
