// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {ClankerGate4337} from "../src/ClankerGate4337.sol";

contract Deploy4337 is Script {
    function run() external returns (ClankerGate4337) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);

        ClankerGate4337 gate = new ClankerGate4337();

        vm.stopBroadcast();

        return gate;
    }
}
