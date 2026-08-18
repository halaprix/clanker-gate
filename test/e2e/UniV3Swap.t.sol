// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {ClankerGateValidatorBase} from "../../src/ClankerGateValidatorBase.sol";
import {Test} from "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PackedUserOperation, IEntryPoint, IAccount} from "../../src/interfaces/IERC4337.sol";
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
}

/// @notice End-to-end policy validation against real Uniswap V3 router calldata
///         (a static 8-word struct parameter). The swap itself is never executed —
///         validateUserOp only inspects calldata — so no mainnet fork is needed.
/// @dev Since the validator hardening, a permission with a non-zero target only
///      matches WRAPPED calls: the router calldata must arrive inside
///      execute(address,uint256,bytes) with the router as the wrapper target
///      (direct calldata requires permission.target == 0). Rule offsets apply to
///      the INNER (unwrapped) calldata.
contract UniV3SwapTest is Test {
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

    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant SWAP_ROUTER = 0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45;

    bytes4 constant EXACT_INPUT_SINGLE =
        bytes4(keccak256("exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))"));

    ClankerGate4337 gate;
    SimpleAccountMock account;
    uint256 ownerKey;
    address owner;

    function setUp() public {
        ownerKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        owner = vm.addr(ownerKey);

        gate = new ClankerGate4337();
        account = new SimpleAccountMock(owner);
    }

    /// @dev exactInputSingle takes one static tuple, encoded inline (offsets after
    ///      the selector): tokenIn 0, tokenOut 32, fee 64, recipient 96,
    ///      deadline 128, amountIn 160, amountOutMinimum 192, sqrtPriceLimitX96 224.
    function _swapCalldata(address tokenIn, address tokenOut, uint256 amountIn)
        internal
        view
        returns (bytes memory)
    {
        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            fee: 3000,
            recipient: address(account),
            deadline: block.timestamp + 1 hours,
            amountIn: amountIn,
            amountOutMinimum: 0,
            sqrtPriceLimitX96: 0
        });
        return abi.encodeCall(ISwapRouter.exactInputSingle, params);
    }

    /// @dev Router calldata as it reaches the gate: wrapped in the account's
    ///      execute(address,uint256,bytes).
    function _wrappedSwap(address tokenIn, address tokenOut, uint256 amountIn)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodeWithSignature(
            "execute(address,uint256,bytes)", SWAP_ROUTER, uint256(0), _swapCalldata(tokenIn, tokenOut, amountIn)
        );
    }

    function _guardData(Permission memory permission, bytes32 userOpHash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash);
        return abi.encode(new bytes32[](0), permission, abi.encodePacked(r, s, v));
    }

    function _swapPermission() internal pure returns (Permission memory permission) {
        permission.target = SWAP_ROUTER;
        permission.selector = EXACT_INPUT_SINGLE;
    }

    function test_ExactInputSingle_WithPolicyValidation() public {
        Permission memory permission = _swapPermission();
        permission.rules = new ParamRule[](2);
        permission.rules[0] =
            ParamRule({offset: 0, op: 0, value: bytes32(uint256(uint160(WETH))), values: new bytes32[](0)});
        permission.rules[1] =
            ParamRule({offset: 160, op: 4, value: bytes32(uint256(1 ether)), values: new bytes32[](0)});

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        uint256 validationData = gate.validateUserOp(
            _packUserOp(address(account), _wrappedSwap(WETH, USDC, 0.5 ether), _guardData(permission, userOpHash)),
            userOpHash
        );
        assertEq(validationData, 0, "Validation should pass");
    }

    function test_ExactInputSingle_RevertWhen_AmountExceedsLimit() public {
        Permission memory permission = _swapPermission();
        permission.rules = new ParamRule[](1);
        permission.rules[0] =
            ParamRule({offset: 160, op: 4, value: bytes32(uint256(0.5 ether)), values: new bytes32[](0)});

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        bytes memory guardData = _guardData(permission, userOpHash);

        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateCore.RuleViolation.selector,
                0,
                uint8(4),
                bytes32(uint256(0.5 ether)),
                bytes32(uint256(1 ether))
            )
        );
        gate.validateUserOp(
            _packUserOp(address(account), _wrappedSwap(WETH, USDC, 1 ether), guardData), userOpHash
        );
    }

    function test_ExactInputSingle_RevertWhen_WrongTokenIn() public {
        Permission memory permission = _swapPermission();
        permission.rules = new ParamRule[](1);
        permission.rules[0] =
            ParamRule({offset: 0, op: 0, value: bytes32(uint256(uint160(WETH))), values: new bytes32[](0)});

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        bytes memory guardData = _guardData(permission, userOpHash);

        vm.expectRevert(
            abi.encodeWithSelector(
                ClankerGateCore.RuleViolation.selector,
                0,
                uint8(0),
                bytes32(uint256(uint160(WETH))),
                bytes32(uint256(uint160(USDC)))
            )
        );
        gate.validateUserOp(
            _packUserOp(address(account), _wrappedSwap(USDC, WETH, 1000 * 1e6), guardData), userOpHash
        );
    }

    function test_ExactInputSingle_RevertWhen_UnwrappedDirectCall() public {
        // Regression lock for the hardened decode semantics: with a non-zero
        // permission.target, DIRECT (unwrapped) router calldata must be rejected.
        Permission memory permission = _swapPermission();

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes32 userOpHash = keccak256("test");
        bytes memory guardData = _guardData(permission, userOpHash);

        vm.expectRevert(
            abi.encodeWithSelector(ClankerGateValidatorBase.DirectCallRequiresTargetZero.selector, SWAP_ROUTER)
        );
        gate.validateUserOp(
            _packUserOp(address(account), _swapCalldata(WETH, USDC, 0.5 ether), guardData), userOpHash
        );
    }

    function test_SingleUsePermission_WorksOnce() public {
        Permission memory permission = _swapPermission();
        permission.rules = new ParamRule[](1);
        permission.rules[0] =
            ParamRule({offset: 160, op: 4, value: bytes32(uint256(1 ether)), values: new bytes32[](0)});
        permission.singleUse = true;

        bytes32 leaf = gate.computePermissionHash(address(account), permission, 1);
        vm.prank(address(account));
        gate.setPolicyRoot(address(account), leaf);

        bytes memory swapCalldata = _wrappedSwap(WETH, USDC, 0.3 ether);
        bytes32 userOpHash = keccak256("test");
        bytes memory guardData = _guardData(permission, userOpHash);

        vm.prank(address(account));
        uint256 result =
            gate.validateUserOp(_packUserOp(address(account), swapCalldata, guardData), userOpHash);
        assertEq(result, 0);

        bytes32 accountPermissionHash = gate.computePermissionHash(address(account), permission, 1);
        assertTrue(gate.usedPermissionHashes(address(account), accountPermissionHash));

        vm.expectRevert(
            abi.encodeWithSelector(ClankerGateCore.PermissionAlreadyUsed.selector, accountPermissionHash)
        );
        vm.prank(address(account));
        gate.validateUserOp(_packUserOp(address(account), swapCalldata, guardData), userOpHash);
    }
}
