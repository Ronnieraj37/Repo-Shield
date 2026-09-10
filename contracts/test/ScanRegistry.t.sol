// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ScanRegistry} from "../src/ScanRegistry.sol";

contract ScanRegistryTest is Test {
    ScanRegistry registry;

    event ScanPublished(
        bytes32 indexed repoId,
        string repo,
        bytes32 commit,
        uint16 threatScore,
        ScanRegistry.Verdict verdict,
        address indexed reporter,
        uint40 scannedAt
    );

    function setUp() public {
        registry = new ScanRegistry();
    }

    function test_publish_storesLatest() public {
        registry.publish("evil/repo", bytes32(uint256(0xabc)), 100, ScanRegistry.Verdict.Danger);

        ScanRegistry.Scan memory s = registry.verdictOf("evil/repo");
        assertEq(s.threatScore, 100);
        assertEq(uint8(s.verdict), uint8(ScanRegistry.Verdict.Danger));
        assertEq(s.reporter, address(this));
        assertEq(s.count, 1);
        assertEq(registry.totalPublications(), 1);
    }

    function test_publish_emitsEvent() public {
        bytes32 repoId = keccak256(bytes("evil/repo"));
        vm.expectEmit(true, false, false, true);
        emit ScanPublished(
            repoId,
            "evil/repo",
            bytes32(uint256(0xabc)),
            100,
            ScanRegistry.Verdict.Danger,
            address(this),
            uint40(block.timestamp)
        );
        registry.publish("evil/repo", bytes32(uint256(0xabc)), 100, ScanRegistry.Verdict.Danger);
    }

    function test_republish_incrementsCount() public {
        registry.publish("a/b", bytes32(0), 10, ScanRegistry.Verdict.Safe);
        registry.publish("a/b", bytes32(0), 80, ScanRegistry.Verdict.Danger);
        assertEq(registry.verdictOf("a/b").count, 2);
        assertEq(uint8(registry.verdictOf("a/b").verdict), uint8(ScanRegistry.Verdict.Danger));
    }

    function test_rejects_unknownVerdict() public {
        vm.expectRevert(ScanRegistry.InvalidVerdict.selector);
        registry.publish("a/b", bytes32(0), 0, ScanRegistry.Verdict.Unknown);
    }

    function test_rejects_scoreOver100() public {
        vm.expectRevert(ScanRegistry.ScoreTooHigh.selector);
        registry.publish("a/b", bytes32(0), 101, ScanRegistry.Verdict.Safe);
    }
}
