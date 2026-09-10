// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {ScanRegistry} from "../src/ScanRegistry.sol";

contract Deploy is Script {
    function run() external returns (ScanRegistry registry) {
        vm.startBroadcast();
        registry = new ScanRegistry();
        vm.stopBroadcast();
        console.log("ScanRegistry deployed at:", address(registry));
    }
}
