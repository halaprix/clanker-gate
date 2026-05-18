// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Script} from "forge-std/Script.sol";
import {ClankerGateSafe} from "../src/ClankerGateSafe.sol";

contract DeploySafe is Script {
    function run() external returns (ClankerGateSafe) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);

        ClankerGateSafe gate = new ClankerGateSafe();

        vm.stopBroadcast();

        return gate;
    }
}
