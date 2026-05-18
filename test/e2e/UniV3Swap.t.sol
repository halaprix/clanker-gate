// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IEntryPoint, IAccount} from "../../src/interfaces/IERC4337.sol";
import {ClankerGate4337} from "../../src/ClankerGate4337.sol";
import {ClankerGateCore, ParamRule, Permission} from "../../src/ClankerGateCore.sol";

interface ISwapRouter {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);
}

contract SimpleAccountMock is IAccount {
    address private _owner;

    constructor(address owner_) {
        _owner = owner_;
    }

    function owner() external view override returns (address) {
        return _owner;
    }

    function validateUserOp(bytes calldata, bytes32, uint256) external pure override returns (uint256) {
        return 0;
    }

    function execute(address dest, uint256 value, bytes calldata func) external {
        (bool success, ) = dest.call{value: value}(func);
        require(success, "execute failed");
    }
}

contract UniV3SwapTest is Test {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /// @notice Encode UserOperation as bytes for validateUserOp (which now takes bytes)
    function _encodeUserOp(IEntryPoint.UserOperation memory userOp) internal pure returns (bytes memory) {
        return abi.encode(
            userOp.sender,
            userOp.nonce,
            userOp.initCode,
            userOp.callData,
            userOp.callGasLimit,
            userOp.verificationGasLimit,
            userOp.preVerificationGas,
            userOp.maxFeePerGas,
            userOp.maxPriorityFeePerGas,
            userOp.paymasterAndData,
            userOp.signature
        );
    }

    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant SWAP_ROUTER = 0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45;

    ClankerGate4337 gate;
    SimpleAccountMock account;
    uint256 ownerKey;
    address owner;

    function setUp() public {
        vm.createSelectFork("mainnet");

        ownerKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        owner = vm.addr(ownerKey);

        gate = new ClankerGate4337();
        account = new SimpleAccountMock(owner);

        vm.deal(address(account), 10 ether);
    }

    function test_ExactInputSingle_WithPolicyValidation() public {
        Permission memory permission;
        permission.target = SWAP_ROUTER;
        permission.selector = bytes4(keccak256("exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))"));
        permission.rules = new ParamRule[](2);
        
        permission.rules[0] = ParamRule({
            offset: 0,
            op: 0,
            value: bytes32(uint256(uint160(WETH))),
            values: new bytes32[](0)
        });
        
        permission.rules[1] = ParamRule({
            offset: 160,
            op: 4,
            value: bytes32(uint256(1 ether)),
            values: new bytes32[](0)
        });
        
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = false;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes memory approveData = abi.encodeCall(IERC20.approve, (SWAP_ROUTER, type(uint256).max));
        vm.prank(address(account));
        account.execute(WETH, 0, approveData);

        bytes memory depositData = abi.encodeWithSignature("deposit()");
        vm.prank(address(account));
        account.execute(WETH, 1 ether, depositData);

        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
            tokenIn: WETH,
            tokenOut: USDC,
            fee: 3000,
            recipient: address(account),
            deadline: block.timestamp + 1 hours,
            amountIn: 0.5 ether,
            amountOutMinimum: 0,
            sqrtPriceLimitX96: 0
        });

        bytes memory swapCalldata = abi.encodeCall(ISwapRouter.exactInputSingle, params);

        bytes32[] memory proof = new bytes32[](0);
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(proof, permission, signature);

        IEntryPoint.UserOperation memory userOp = _buildUserOp(address(account), swapCalldata);

        uint256 validationData = gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
        assertEq(validationData, 0, "Validation should pass");

        // Note: Actual swap execution skipped in fork test
        // Real execution would require proper liquidity pool setup
        // The validation logic is what we're testing here
    }

    function test_ExactInputSingle_RevertWhen_AmountExceedsLimit() public {
        Permission memory permission;
        permission.target = SWAP_ROUTER;
        permission.selector = bytes4(keccak256("exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))"));
        permission.rules = new ParamRule[](1);
        
        permission.rules[0] = ParamRule({
            offset: 160,
            op: 4,
            value: bytes32(uint256(0.5 ether)),
            values: new bytes32[](0)
        });
        
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = false;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes memory approveData = abi.encodeCall(IERC20.approve, (SWAP_ROUTER, type(uint256).max));
        vm.prank(address(account));
        account.execute(WETH, 0, approveData);

        bytes memory depositData = abi.encodeWithSignature("deposit()");
        vm.prank(address(account));
        account.execute(WETH, 2 ether, depositData);

        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
            tokenIn: WETH,
            tokenOut: USDC,
            fee: 3000,
            recipient: address(account),
            deadline: block.timestamp + 1 hours,
            amountIn: 1 ether,
            amountOutMinimum: 0,
            sqrtPriceLimitX96: 0
        });

        bytes memory swapCalldata = abi.encodeCall(ISwapRouter.exactInputSingle, params);

        bytes32[] memory proof = new bytes32[](0);
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(abi.encodeWithSelector(
            ClankerGateCore.RuleViolation.selector,
            0,
            uint8(4),
            bytes32(uint256(0.5 ether)),
            bytes32(uint256(1 ether))
        ));
        
        IEntryPoint.UserOperation memory userOp = _buildUserOp(address(account), swapCalldata);
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }

    function test_ExactInputSingle_RevertWhen_WrongTokenIn() public {
        Permission memory permission;
        permission.target = SWAP_ROUTER;
        permission.selector = bytes4(keccak256("exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))"));
        permission.rules = new ParamRule[](1);
        
        permission.rules[0] = ParamRule({
            offset: 0,
            op: 0,
            value: bytes32(uint256(uint160(WETH))),
            values: new bytes32[](0)
        });
        
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = false;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
            tokenIn: USDC,
            tokenOut: WETH,
            fee: 3000,
            recipient: address(account),
            deadline: block.timestamp + 1 hours,
            amountIn: 1000 * 1e6,
            amountOutMinimum: 0,
            sqrtPriceLimitX96: 0
        });

        bytes memory swapCalldata = abi.encodeCall(ISwapRouter.exactInputSingle, params);

        bytes32[] memory proof = new bytes32[](0);
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(proof, permission, signature);

        vm.expectRevert(abi.encodeWithSelector(
            ClankerGateCore.RuleViolation.selector,
            0,
            uint8(0),
            bytes32(uint256(uint160(WETH))),
            bytes32(uint256(uint160(USDC)))
        ));
        
        IEntryPoint.UserOperation memory userOp = _buildUserOp(address(account), swapCalldata);
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }

    function test_SingleUsePermission_WorksOnce() public {
        Permission memory permission;
        permission.target = SWAP_ROUTER;
        permission.selector = bytes4(keccak256("exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))"));
        permission.rules = new ParamRule[](1);
        permission.rules[0] = ParamRule({
            offset: 160,
            op: 4,
            value: bytes32(uint256(1 ether)),
            values: new bytes32[](0)
        });
        permission.validAfter = 0;
        permission.validUntil = 0;
        permission.chainId = 0;
        permission.singleUse = true;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        bytes32 root = leaf;

        vm.prank(address(account));
        gate.setPolicyRoot(address(account), root);

        bytes memory approveData = abi.encodeCall(IERC20.approve, (SWAP_ROUTER, type(uint256).max));
        vm.prank(address(account));
        account.execute(WETH, 0, approveData);

        bytes memory depositData = abi.encodeWithSignature("deposit()");
        vm.prank(address(account));
        account.execute(WETH, 1 ether, depositData);

        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
            tokenIn: WETH,
            tokenOut: USDC,
            fee: 3000,
            recipient: address(account),
            deadline: block.timestamp + 1 hours,
            amountIn: 0.3 ether,
            amountOutMinimum: 0,
            sqrtPriceLimitX96: 0
        });

        bytes memory swapCalldata = abi.encodeCall(ISwapRouter.exactInputSingle, params);

        bytes32[] memory proof = new bytes32[](0);
        bytes32 userOpHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory guardData = abi.encode(proof, permission, signature);

        IEntryPoint.UserOperation memory userOp = _buildUserOp(address(account), swapCalldata);
        
        vm.prank(address(account));
        uint256 result = gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
        assertEq(result, 0);

        bytes32 accountPermissionHash = gate.computePermissionHash(address(account), permission, 1);
        assertTrue(gate.usedPermissionHashes(address(account), accountPermissionHash));

        vm.expectRevert(abi.encodeWithSelector(ClankerGateCore.PermissionAlreadyUsed.selector, accountPermissionHash));
        vm.prank(address(account));
        gate.validateUserOp(_encodeUserOp(userOp), userOpHash, guardData);
    }

    function _buildUserOp(address sender, bytes memory callData) internal pure returns (IEntryPoint.UserOperation memory) {
        IEntryPoint.UserOperation memory userOp;
        userOp.sender = sender;
        userOp.nonce = 0;
        userOp.initCode = "";
        userOp.callData = callData;
        userOp.callGasLimit = 500000;
        userOp.verificationGasLimit = 500000;
        userOp.preVerificationGas = 100000;
        userOp.maxFeePerGas = 30 gwei;
        userOp.maxPriorityFeePerGas = 2 gwei;
        userOp.paymasterAndData = "";
        userOp.signature = "";
        return userOp;
    }
}
