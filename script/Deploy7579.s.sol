// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {ClankerGate7579} from "../src/ClankerGate7579.sol";

contract Deploy7579 is Script {
    function run() external returns (ClankerGate7579) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);

        ClankerGate7579 gate = new ClankerGate7579();

        vm.stopBroadcast();

        return gate;
    }
}
