// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {
    ProtocolCalldataTestBase,
    ProtocolValidatorHarness
} from "./ProtocolCalldataBase.sol";
import {
    ClankerGateCore,
    ParamRule,
    Permission,
    OP_EQ,
    OP_GT,
    OP_LT,
    OP_GTE,
    OP_LTE,
    OP_IN,
    OP_SGT
} from "../../src/ClankerGateCore.sol";

/// @title Compound v3 (Comet) calldata-policy scenarios (33 cases)
/// @notice Validates ClankerGateCore.validateCallDataExtended against real Comet
///         entry-point encodings — including CometExt functions reached through the
///         fallback delegatecall (allow/approve/allowBySig), the absorb() dynamic
///         array, the binary approve() sentinel, and the uint256.max amount sentinels.
/// @dev One proxy address serves both Comet and CometExt ABIs (fallback delegatecall),
///      so all permissions pin the same COMET target.
contract CometCalldataTest is ProtocolCalldataTestBase {
    address internal constant COMET = 0xc3d688B66703497DAA19211EEdff47f25384cdc3; // cUSDCv3 style
    address internal constant BASE_TOKEN = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48; // USDC
    address internal constant MANAGER = 0x1111111254EEB25477B68fb85Ed929f73A960582;

    string internal constant SIG_SUPPLY = "supply(address,uint256)";
    string internal constant SIG_SUPPLY_TO = "supplyTo(address,address,uint256)";
    string internal constant SIG_SUPPLY_FROM = "supplyFrom(address,address,address,uint256)";
    string internal constant SIG_WITHDRAW = "withdraw(address,uint256)";
    string internal constant SIG_WITHDRAW_TO = "withdrawTo(address,address,uint256)";
    string internal constant SIG_WITHDRAW_FROM = "withdrawFrom(address,address,address,uint256)";
    string internal constant SIG_TRANSFER = "transfer(address,uint256)";
    string internal constant SIG_TRANSFER_ASSET = "transferAsset(address,address,uint256)";
    string internal constant SIG_TRANSFER_ASSET_FROM = "transferAssetFrom(address,address,address,uint256)";
    string internal constant SIG_ALLOW = "allow(address,bool)";
    string internal constant SIG_APPROVE = "approve(address,uint256)";
    string internal constant SIG_ALLOW_BY_SIG =
        "allowBySig(address,address,bool,uint256,uint256,uint8,bytes32,bytes32)";
    string internal constant SIG_BUY_COLLATERAL = "buyCollateral(address,uint256,uint256,address)";
    string internal constant SIG_ABSORB = "absorb(address,address[])";
    string internal constant SIG_PAUSE = "pause(bool,bool,bool,bool,bool)";
    string internal constant SIG_ACCRUE = "accrueAccount(address)";

    function _sel(string memory sig) internal pure returns (bytes4) {
        return bytes4(keccak256(bytes(sig)));
    }

    // ------------------------------------------------------------- supply (6)

    function test_Supply_AssetPinned_Passes() public view {
        Permission memory p = _perm(
            COMET, _sel(SIG_SUPPLY), _rules2(_ruleAddr(0, OP_EQ, WETH), _ruleUint(32, OP_LTE, 10e18))
        );
        _assertValid(abi.encodeWithSignature(SIG_SUPPLY, WETH, uint256(5e18)), p);
    }

    function test_Supply_WrongAsset_Reverts() public {
        Permission memory p = _perm(COMET, _sel(SIG_SUPPLY), _rules1(_ruleAddr(0, OP_EQ, WETH)));
        _expectRuleViolation(abi.encodeWithSignature(SIG_SUPPLY, WBTC, uint256(1e8)), p, 0);
    }

    function test_Supply_AmountAboveCap_Reverts() public {
        Permission memory p = _perm(COMET, _sel(SIG_SUPPLY), _rules1(_ruleUint(32, OP_LTE, 10e18)));
        _expectRuleViolation(abi.encodeWithSignature(SIG_SUPPLY, WETH, uint256(10e18 + 1)), p, 0);
    }

    function test_SupplyTo_DstPinnedToAccount_Passes() public view {
        Permission memory p = _perm(
            COMET,
            _sel(SIG_SUPPLY_TO),
            _rules2(_ruleAddr(0, OP_EQ, ACCOUNT), _ruleAddr(32, OP_EQ, BASE_TOKEN))
        );
        _assertValid(abi.encodeWithSignature(SIG_SUPPLY_TO, ACCOUNT, BASE_TOKEN, uint256(1_000e6)), p);
    }

    function test_SupplyTo_DstAttacker_Reverts() public {
        Permission memory p = _perm(COMET, _sel(SIG_SUPPLY_TO), _rules1(_ruleAddr(0, OP_EQ, ACCOUNT)));
        _expectRuleViolation(
            abi.encodeWithSignature(SIG_SUPPLY_TO, ATTACKER, BASE_TOKEN, uint256(1_000e6)), p, 0
        );
    }

    function test_SupplyFrom_FourWordLayout_RuleOnLastWordExactFit_Passes() public view {
        // 132-byte calldata; amount at offset 96: 4 + 96 + 32 == 132 (exact fit)
        Permission memory p = _perm(
            COMET,
            _sel(SIG_SUPPLY_FROM),
            _rules3(
                _ruleAddr(0, OP_EQ, ACCOUNT), // from
                _ruleAddr(32, OP_EQ, ACCOUNT), // dst
                _ruleUint(96, OP_LTE, 5_000e6) // amount (last word)
            )
        );
        _assertValid(
            abi.encodeWithSignature(SIG_SUPPLY_FROM, ACCOUNT, ACCOUNT, BASE_TOKEN, uint256(5_000e6)), p
        );
    }

    // ------------------------------------------------------------ withdraw (4)

    function test_Withdraw_BaseAssetCapped_Passes() public view {
        Permission memory p = _perm(
            COMET,
            _sel(SIG_WITHDRAW),
            _rules2(_ruleAddr(0, OP_EQ, BASE_TOKEN), _ruleUint(32, OP_LTE, 2_000e6))
        );
        _assertValid(abi.encodeWithSignature(SIG_WITHDRAW, BASE_TOKEN, uint256(2_000e6)), p);
    }

    function test_Withdraw_FullBalanceSentinel_EqMax_Passes() public view {
        // For the base asset, amount == uint256.max withdraws the full balance
        Permission memory p = _perm(
            COMET,
            _sel(SIG_WITHDRAW),
            _rules2(_ruleAddr(0, OP_EQ, BASE_TOKEN), _ruleUint(32, OP_EQ, type(uint256).max))
        );
        _assertValid(abi.encodeWithSignature(SIG_WITHDRAW, BASE_TOKEN, type(uint256).max), p);
    }

    function test_Withdraw_MaxSentinelBlockedBySignedGuard_Reverts() public {
        // OP_SGT(-1) requires the top bit clear; uint256.max is -1 as int256
        Permission memory p = _perm(
            COMET, _sel(SIG_WITHDRAW), _rules1(_rule(32, OP_SGT, bytes32(uint256(int256(-1)))))
        );
        _expectRuleViolation(abi.encodeWithSignature(SIG_WITHDRAW, BASE_TOKEN, type(uint256).max), p, 0);
    }

    function test_WithdrawTo_RecipientAttacker_Reverts() public {
        // withdrawTo(to, asset, amount): `to` is word 0 — the exfiltration vector
        Permission memory p = _perm(COMET, _sel(SIG_WITHDRAW_TO), _rules1(_ruleAddr(0, OP_EQ, ACCOUNT)));
        _expectRuleViolation(
            abi.encodeWithSignature(SIG_WITHDRAW_TO, ATTACKER, BASE_TOKEN, uint256(1_000e6)), p, 0
        );
    }

    // ---------------------------------------------------------- withdrawFrom (1)

    function test_WithdrawFrom_SrcAndToPinned_Passes() public view {
        Permission memory p = _perm(
            COMET,
            _sel(SIG_WITHDRAW_FROM),
            _rules2(_ruleAddr(0, OP_EQ, ACCOUNT), _ruleAddr(32, OP_EQ, ACCOUNT))
        );
        _assertValid(
            abi.encodeWithSignature(SIG_WITHDRAW_FROM, ACCOUNT, ACCOUNT, BASE_TOKEN, uint256(100e6)), p
        );
    }

    // ------------------------------------------------------------ transfers (4)

    function test_Transfer_DstInAllowlist_Passes() public view {
        Permission memory p =
            _perm(COMET, _sel(SIG_TRANSFER), _rules1(_ruleIn(0, _addrSet2(ACCOUNT, MANAGER))));
        _assertValid(abi.encodeWithSignature(SIG_TRANSFER, MANAGER, uint256(10e6)), p);
    }

    function test_Transfer_DstNotInAllowlist_Reverts() public {
        Permission memory p =
            _perm(COMET, _sel(SIG_TRANSFER), _rules1(_ruleIn(0, _addrSet2(ACCOUNT, MANAGER))));
        _expectNotInSet(abi.encodeWithSignature(SIG_TRANSFER, ATTACKER, uint256(10e6)), p, 0);
    }

    function test_TransferAsset_CollateralAssetPinned_Passes() public view {
        Permission memory p = _perm(
            COMET,
            _sel(SIG_TRANSFER_ASSET),
            _rules2(_ruleAddr(0, OP_EQ, ACCOUNT), _ruleAddr(32, OP_EQ, WETH))
        );
        _assertValid(abi.encodeWithSignature(SIG_TRANSFER_ASSET, ACCOUNT, WETH, uint256(1e18)), p);
    }

    function test_TransferAsset_AgainstErc20TransferPermission_SelectorMismatch() public view {
        // transfer(address,uint256) and transferAsset(address,address,uint256) are
        // distinct selectors — an ERC20-shaped permission must not leak to the 3-arg one.
        Permission memory p = _perm(COMET, _sel(SIG_TRANSFER), _noRules());
        _assertSelectorMismatch(
            abi.encodeWithSignature(SIG_TRANSFER_ASSET, ATTACKER, WETH, uint256(1e18)), p
        );
    }

    // ------------------------------------------------- allow / approve (5)

    function test_Allow_ManagerAndFlagPinned_Passes() public view {
        Permission memory p = _perm(
            COMET, _sel(SIG_ALLOW), _rules2(_ruleAddr(0, OP_EQ, MANAGER), _ruleUint(32, OP_EQ, 1))
        );
        _assertValid(abi.encodeWithSignature(SIG_ALLOW, MANAGER, true), p);
    }

    function test_Allow_RevokeOnlyPolicy_BlocksGrant_Reverts() public {
        // allow(manager, true) hands over the ENTIRE position; a session key may
        // reasonably be allowed to revoke (false) but never to grant (true).
        Permission memory p = _perm(COMET, _sel(SIG_ALLOW), _rules1(_ruleUint(32, OP_EQ, 0)));
        _expectRuleViolation(abi.encodeWithSignature(SIG_ALLOW, MANAGER, true), p, 0);
    }

    function test_Allow_ManagerNotInAllowlist_Reverts() public {
        Permission memory p =
            _perm(COMET, _sel(SIG_ALLOW), _rules1(_ruleIn(0, _addrSet2(MANAGER, ACCOUNT))));
        _expectNotInSet(abi.encodeWithSignature(SIG_ALLOW, ATTACKER, true), p, 0);
    }

    function test_Approve_BinarySentinel_MaxApproveBlocked_Reverts() public {
        // CometExt.approve only accepts 0 or uint256.max (max == full account control).
        // A revoke-only policy pins the amount word to 0.
        Permission memory p = _perm(COMET, _sel(SIG_APPROVE), _rules1(_ruleUint(32, OP_EQ, 0)));
        _expectRuleViolation(abi.encodeWithSignature(SIG_APPROVE, MANAGER, type(uint256).max), p, 0);
    }

    function test_Approve_RevokeZero_Passes() public view {
        Permission memory p = _perm(COMET, _sel(SIG_APPROVE), _rules1(_ruleUint(32, OP_EQ, 0)));
        _assertValid(abi.encodeWithSignature(SIG_APPROVE, MANAGER, uint256(0)), p);
    }

    // ------------------------------------------------------- allowBySig (3)

    function _allowBySigCd(address owner, address manager, bool isAllowed, uint256 nonce, uint256 expiry)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSignature(
            SIG_ALLOW_BY_SIG,
            owner,
            manager,
            isAllowed,
            nonce,
            expiry,
            uint8(27),
            bytes32(uint256(0xaaaa)),
            bytes32(uint256(0xbbbb))
        );
    }

    function test_AllowBySig_OwnerPinnedAndExpiryCapped_Passes() public view {
        // 260-byte, 8 static words: owner 0 | manager 32 | isAllowed 64 |
        // nonce 96 | expiry 128 | v 160 | r 192 | s 224
        Permission memory p = _perm(
            COMET,
            _sel(SIG_ALLOW_BY_SIG),
            _rules2(_ruleAddr(0, OP_EQ, ACCOUNT), _ruleUint(128, OP_LTE, 1_800_000_000))
        );
        _assertValid(_allowBySigCd(ACCOUNT, MANAGER, true, 0, 1_750_000_000), p);
    }

    function test_AllowBySig_GrantBlockedByRevokeOnlyPolicy_Reverts() public {
        Permission memory p = _perm(COMET, _sel(SIG_ALLOW_BY_SIG), _rules1(_ruleUint(64, OP_EQ, 0)));
        _expectRuleViolation(_allowBySigCd(ACCOUNT, MANAGER, true, 0, 1_750_000_000), p, 0);
    }

    function test_AllowBySig_RuleOnFinalSWord_ExactFit_Passes() public view {
        // s occupies the final word at offset 224: 4 + 224 + 32 == 260 (exact fit)
        Permission memory p =
            _perm(COMET, _sel(SIG_ALLOW_BY_SIG), _rules1(_rule(224, OP_EQ, bytes32(uint256(0xbbbb)))));
        _assertValid(_allowBySigCd(ACCOUNT, MANAGER, false, 1, 1_750_000_000), p);
    }

    // ---------------------------------------------------- buyCollateral (2)

    function test_BuyCollateral_RecipientInLastWordPinned_Passes() public view {
        // buyCollateral(asset, minAmount, baseAmount, recipient): recipient is the
        // LAST word (offset 96) — pinning word 0 would pin the asset, not the recipient.
        Permission memory p = _perm(
            COMET,
            _sel(SIG_BUY_COLLATERAL),
            _rules2(_ruleAddr(0, OP_EQ, WETH), _ruleAddr(96, OP_EQ, ACCOUNT))
        );
        _assertValid(
            abi.encodeWithSignature(SIG_BUY_COLLATERAL, WETH, uint256(1e18), uint256(3_000e6), ACCOUNT), p
        );
    }

    function test_BuyCollateral_ZeroMinAmountBlockedBySlippageFloor_Reverts() public {
        // minAmount == 0 disables the on-chain slippage floor; policy requires >= 1
        Permission memory p = _perm(COMET, _sel(SIG_BUY_COLLATERAL), _rules1(_ruleUint(32, OP_GTE, 1)));
        _expectRuleViolation(
            abi.encodeWithSignature(SIG_BUY_COLLATERAL, WETH, uint256(0), uint256(3_000e6), ATTACKER), p, 0
        );
    }

    // ------------------------------------------------------------- absorb (4)

    function test_Absorb_AbsorberAndCanonicalPointerPinned_Passes() public view {
        address[] memory accounts = new address[](1);
        accounts[0] = ATTACKER;
        Permission memory p = _perm(
            COMET,
            _sel(SIG_ABSORB),
            _rules2(_ruleAddr(0, OP_EQ, ACCOUNT), _ruleUint(32, OP_EQ, 0x40))
        );
        _assertValid(abi.encodeWithSignature(SIG_ABSORB, ACCOUNT, accounts), p);
    }

    function test_Absorb_RelocatedArray_CaughtByPointerRule() public {
        // Same decoded args, array moved one word further (pointer 0x60 + junk word)
        bytes memory cd = abi.encodePacked(
            _sel(SIG_ABSORB),
            bytes32(uint256(uint160(ACCOUNT))), // absorber
            uint256(0x60), // non-canonical pointer
            uint256(0xdead), // junk word
            uint256(1), // real length
            bytes32(uint256(uint160(ATTACKER))) // real element
        );
        Permission memory p = _perm(COMET, _sel(SIG_ABSORB), _rules1(_ruleUint(32, OP_EQ, 0x40)));
        _expectRuleViolation(cd, p, 0);
    }

    function test_Absorb_SingleTargetPinnedInTail_Passes() public view {
        // With the pointer pinned: length at offset 64, accounts[0] at offset 96
        address[] memory accounts = new address[](1);
        accounts[0] = ATTACKER;
        Permission memory p = _perm(
            COMET,
            _sel(SIG_ABSORB),
            _rules3(
                _ruleUint(32, OP_EQ, 0x40),
                _ruleUint(64, OP_EQ, 1),
                _ruleAddr(96, OP_EQ, ATTACKER)
            )
        );
        _assertValid(abi.encodeWithSignature(SIG_ABSORB, ACCOUNT, accounts), p);
    }

    function test_Absorb_EmptyArrayBlockedByLengthRule_Reverts() public {
        // absorb with an empty array still bumps numAbsorbs on-chain — block it
        address[] memory accounts = new address[](0);
        Permission memory p = _perm(
            COMET, _sel(SIG_ABSORB), _rules2(_ruleUint(32, OP_EQ, 0x40), _ruleUint(64, OP_GTE, 1))
        );
        _expectRuleViolation(abi.encodeWithSignature(SIG_ABSORB, ACCOUNT, accounts), p, 1);
    }

    // -------------------------------------------------------------- pause (1)

    function test_Pause_DirtyBoolWord_CaughtByEqRule_Reverts() public {
        // A hand-crafted bool word of 2 (Solidity would reject it at decode time,
        // but the validator sees raw words and must catch it before the call).
        bytes memory cd = abi.encodePacked(
            _sel(SIG_PAUSE), uint256(2), uint256(0), uint256(0), uint256(0), uint256(0)
        );
        Permission memory p = _perm(COMET, _sel(SIG_PAUSE), _rules1(_ruleUint(0, OP_LTE, 1)));
        _expectRuleViolation(cd, p, 0);
    }

    // ------------------------------------------------------ accrueAccount (1)

    function test_AccrueAccount_SingleWordExactFit_Passes() public view {
        // 36-byte calldata; rule at offset 0: 4 + 0 + 32 == 36 (minimal exact fit)
        Permission memory p = _perm(COMET, _sel(SIG_ACCRUE), _rules1(_ruleAddr(0, OP_EQ, ACCOUNT)));
        _assertValid(abi.encodeWithSignature(SIG_ACCRUE, ACCOUNT), p);
    }

    // ------------------------------------------------- wrapped execution (2)

    function test_Wrapped7579_InnerSupplyDecodedAndValidated() public view {
        bytes memory inner = abi.encodeWithSignature(SIG_SUPPLY, WETH, uint256(1e18));
        bytes memory wrapped = _wrap7579Single(COMET, 0, inner);

        (ClankerGateCore.ExecKind kind, address target, uint256 innerOffset, uint256 innerLength,) =
            harness.decodeAny(wrapped);

        assertEq(uint8(kind), uint8(ClankerGateCore.ExecKind.Execute7579Single));
        assertEq(target, COMET, "wrapper target must be Comet");
        assertEq(innerLength, inner.length, "inner length preserved");

        Permission memory p = _perm(
            COMET, _sel(SIG_SUPPLY), _rules2(_ruleAddr(0, OP_EQ, WETH), _ruleUint(32, OP_LTE, 10e18))
        );
        _assertValid(_slice(wrapped, innerOffset, innerLength), p);
    }

    function test_Wrapped4337_WithdrawToAttacker_CaughtOnInnerCalldata() public {
        // The attacker hides an exfiltrating withdrawTo inside an execute() wrapper;
        // after unwrapping, the recipient rule still fires on the inner bytes.
        bytes memory inner =
            abi.encodeWithSignature(SIG_WITHDRAW_TO, ATTACKER, BASE_TOKEN, uint256(1_000e6));
        bytes memory wrapped = _wrap4337(COMET, 0, inner);

        (,, uint256 innerOffset, uint256 innerLength,) = harness.decodeAny(wrapped);

        Permission memory p = _perm(COMET, _sel(SIG_WITHDRAW_TO), _rules1(_ruleAddr(0, OP_EQ, ACCOUNT)));
        _expectRuleViolation(_slice(wrapped, innerOffset, innerLength), p, 0);
    }
}
