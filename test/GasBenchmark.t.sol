// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Test, console} from "forge-std/Test.sol";
import {ClankerGate4337} from "../src/ClankerGate4337.sol";
import {ClankerGateCore, ParamRule, Permission} from "../src/ClankerGateCore.sol";
import {PackedUserOperation, IEntryPoint} from "../src/interfaces/IERC4337.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract MockAccount {
    address private _owner;

    constructor(address owner_) {
        _owner = owner_;
    }

    function owner() external view returns (address) {
        return _owner;
    }
}

// Baseline: ABI decode validation approach
contract ABIDecodeValidator {
    function validateWithABIDecode(
        bytes calldata callData,
        address, // expectedTarget
        bytes4 expectedSelector,
        uint256 maxAmount
    ) external pure returns (bool) {
        bytes4 selector = bytes4(callData[0:4]);
        
        if (selector != expectedSelector) return false;
        
        if (callData.length >= 164) {
            uint256 amount;
            assembly {
                amount := calldataload(add(callData.offset, 164))
            }
            if (amount > maxAmount) return false;
        }
        
        return true;
    }
}

contract GasBenchmark is Test {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /// @notice Build a PackedUserOperation for gate.validateUserOp (v0.7 2-arg form).
    /// Gate only reads sender/callData/signature; other fields may be zero.
    function _packUserOp(address sender, bytes memory callData, bytes memory sigField)
        internal pure returns (PackedUserOperation memory u)
    {
        u.sender = sender;
        u.callData = callData;
        u.signature = sigField;
    }

    ClankerGate4337 gate;
    ABIDecodeValidator abiValidator;
    MockAccount account;
    uint256 ownerKey;
    address owner;

    function setUp() public {
        ownerKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        owner = vm.addr(ownerKey);

        gate = new ClankerGate4337();
        abiValidator = new ABIDecodeValidator();
        account = new MockAccount(owner);
    }

    // ============ CLANKERGATE GAS MEASUREMENTS ============

    function test_Gas_SetPolicyRoot() public {
        vm.prank(address(account));
        uint256 gasBefore = gasleft();
        gate.setPolicyRoot(address(account), bytes32(uint256(1)));
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("setPolicyRoot:", gasUsed);
        assertLt(gasUsed, 60000, "setPolicyRoot should use < 60k gas");
    }

    function test_Gas_ValidateUserOp_0_Rules() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = false;

        _setupAndMeasure(permission, hex"12345678", "validateUserOp (0 rules)");
    }

    function test_Gas_ValidateUserOp_1_Rule_EQ() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        permission.rules[0] = ParamRule(0, 0, bytes32(uint256(100)), new bytes32[](0));
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = false;

        bytes memory callData = abi.encodePacked(
            bytes4(0x12345678),
            bytes32(uint256(100))
        );

        _setupAndMeasure(permission, callData, "validateUserOp (1 rule EQ)");
    }

    function test_Gas_ValidateUserOp_1_Rule_IN_3_Values() public {
        bytes32[] memory allowedValues = new bytes32[](3);
        allowedValues[0] = bytes32(uint256(100));
        allowedValues[1] = bytes32(uint256(200));
        allowedValues[2] = bytes32(uint256(300));

        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        permission.rules[0] = ParamRule(0, 5, bytes32(0), allowedValues);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = false;

        bytes memory callData = abi.encodePacked(
            bytes4(0x12345678),
            bytes32(uint256(200))
        );

        _setupAndMeasure(permission, callData, "validateUserOp (1 rule IN, 3 values)");
    }

    function test_Gas_ValidateUserOp_5_Rules() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](5);
        // Offsets are relative to after the selector
        permission.rules[0] = ParamRule(0, 4, bytes32(uint256(1000)), new bytes32[](0));   // LTE at first param (offset 0)
        permission.rules[1] = ParamRule(32, 4, bytes32(uint256(1000)), new bytes32[](0)); // LTE at second param
        permission.rules[2] = ParamRule(64, 4, bytes32(uint256(1000)), new bytes32[](0)); // LTE at third param
        permission.rules[3] = ParamRule(96, 4, bytes32(uint256(1000)), new bytes32[](0)); // LTE at fourth param
        permission.rules[4] = ParamRule(128, 4, bytes32(uint256(1000)), new bytes32[](0)); // LTE at fifth param
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = false;

        // 4 byte selector + 5 x 32 bytes = 164 bytes
        bytes memory callData = new bytes(164);
        callData[0] = bytes1(0x12);
        callData[1] = bytes1(0x34);
        callData[2] = bytes1(0x56);
        callData[3] = bytes1(0x78);
        // All params default to 0, which is <= 1000 for all LTE rules

        _setupAndMeasure(permission, callData, "validateUserOp (5 rules)");
    }

    function test_Gas_ValidateUserOp_10_Rules() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](10);
        
        for (uint256 i = 0; i < 10; i++) {
            permission.rules[i] = ParamRule(i * 32, 4, bytes32(type(uint256).max), new bytes32[](0));
        }
        
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = false;

        bytes memory callData = new bytes(324);
        callData[0] = bytes1(0x12);
        callData[1] = bytes1(0x34);
        callData[2] = bytes1(0x56);
        callData[3] = bytes1(0x78);

        _setupAndMeasure(permission, callData, "validateUserOp (10 rules)");
    }

    function test_Gas_SingleUse_Tracking() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](0);
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = true;

        _setupAndMeasure(permission, hex"12345678", "validateUserOp (singleUse=true)");
    }

    // ============ COMPARISON: ABI DECODE vs CLANKERGATE ============

    function test_Gas_Comparison_ABIDecode() public view {
        bytes memory callData = abi.encodePacked(
            bytes4(0x12345678),
            new bytes(156),
            bytes32(uint256(500)) // amount at offset 160
        );

        uint256 gasBefore = gasleft();
        abiValidator.validateWithABIDecode(
            callData,
            address(0x1111),
            0x12345678,
            1000
        );
        uint256 gasUsed = gasBefore - gasleft();

        console.log("ABI Decode approach:", gasUsed);
    }

    function test_Gas_Comparison_ClankerGate() public {
        Permission memory permission;
        permission.target = address(0);
        permission.selector = 0x12345678;
        permission.rules = new ParamRule[](1);
        // Offset 0 means absolute offset 4 (after selector), first param
        permission.rules[0] = ParamRule(0, 4, bytes32(uint256(1000)), new bytes32[](0)); // amountIn <= 1000
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = false;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        // Create calldata: selector + 32 bytes for amount (500)
        bytes memory callData = abi.encodePacked(
            bytes4(0x12345678),
            bytes32(uint256(500))
        );

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory guardData = abi.encode(new bytes32[](0), permission, signature);

        uint256 gasBefore = gasleft();
        gate.validateUserOp(_packUserOp(address(account), callData, guardData), userOpHash);
        uint256 gasUsed = gasBefore - gasleft();

        console.log("ClankerGate approach:", gasUsed);
    }

    // ============ CALCDATA EXTRACTION COMPARISON ============

    function test_Gas_CalldataExtraction_ClankerGate() public view {
        bytes memory callData = new bytes(164);
        
        uint256 gasBefore = gasleft();
        
        // Direct calldataload approach (ClankerGate)
        bytes32 value;
        assembly {
            value := mload(add(add(callData, 32), 164))
        }
        
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Calldata extraction (ClankerGate):", gasUsed);
        assertTrue(value != bytes32(0) || value == bytes32(0)); // silence warning
    }

    function test_Gas_CalldataExtraction_ABIDecode() public view {
        bytes memory callData = new bytes(164);
        
        uint256 gasBefore = gasleft();
        
        // ABI decode approach
        bytes memory params = abi.decode(callData, (bytes));
        bytes32 value = bytes32(params);
        
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Calldata extraction (ABI decode):", gasUsed);
        assertTrue(value != bytes32(0) || value == bytes32(0)); // silence warning
    }

    // ============ HELPER ============

    function _setupAndMeasure(
        Permission memory permission,
        bytes memory callData,
        string memory label
    ) internal {
        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory guardData = abi.encode(new bytes32[](0), permission, signature);

        uint256 gasBefore = gasleft();
        vm.prank(address(account));
        gate.validateUserOp(_packUserOp(address(account), callData, guardData), userOpHash);
        uint256 gasUsed = gasBefore - gasleft();

        console.log(label, ":", gasUsed);
    }
}
