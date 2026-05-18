// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Script} from "forge-std/Script.sol";
import {ClankerGate4337} from "../src/ClankerGate4337.sol";
import {ClankerGateSafe} from "../src/ClankerGateSafe.sol";
import {ClankerGate7579} from "../src/ClankerGate7579.sol";

contract Deploy is Script {
    function run() external returns (ClankerGate4337, ClankerGateSafe, ClankerGate7579) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);

        ClankerGate4337 gate4337 = new ClankerGate4337();
        ClankerGateSafe gateSafe = new ClankerGateSafe();
        ClankerGate7579 gate7579 = new ClankerGate7579();

        vm.stopBroadcast();

        return (gate4337, gateSafe, gate7579);
    }
}
