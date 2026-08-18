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

/// @title Aave v3 Pool calldata-policy scenarios (42 cases)
/// @notice Validates ClankerGateCore.validateCallDataExtended against real Aave v3.6
///         Pool entry-point encodings, including the deprecated deposit alias,
///         permit variants, flashLoan dynamic arrays, multicall nesting, and the
///         L2Pool packed-bytes32 compact variants.
/// @dev Word layout reference (offsets are bytes after the 4-byte selector):
///      supply(address,uint256,address,uint16):  0 asset | 32 amount | 64 onBehalfOf | 96 referralCode  (132 B)
///      withdraw(address,uint256,address):        0 asset | 32 amount | 64 to                            (100 B)
///      borrow(address,uint256,uint256,uint16,address): 0 asset | 32 amount | 64 irMode | 96 ref | 128 onBehalfOf (164 B)
contract AaveV3CalldataTest is ProtocolCalldataTestBase {
    address internal constant POOL = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2;

    string internal constant SIG_SUPPLY = "supply(address,uint256,address,uint16)";
    string internal constant SIG_DEPOSIT = "deposit(address,uint256,address,uint16)";
    string internal constant SIG_WITHDRAW = "withdraw(address,uint256,address)";
    string internal constant SIG_BORROW = "borrow(address,uint256,uint256,uint16,address)";
    string internal constant SIG_REPAY = "repay(address,uint256,uint256,address)";
    string internal constant SIG_REPAY_ATOKENS = "repayWithATokens(address,uint256,uint256)";
    string internal constant SIG_SET_COLLATERAL = "setUserUseReserveAsCollateral(address,bool)";
    string internal constant SIG_SET_EMODE = "setUserEMode(uint8)";
    string internal constant SIG_LIQUIDATION = "liquidationCall(address,address,address,uint256,bool)";
    string internal constant SIG_SUPPLY_PERMIT =
        "supplyWithPermit(address,uint256,address,uint16,uint256,uint8,bytes32,bytes32)";
    string internal constant SIG_FLASHLOAN =
        "flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)";
    string internal constant SIG_MINT_TO_TREASURY = "mintToTreasury(address[])";
    string internal constant SIG_MULTICALL = "multicall(bytes[])";
    string internal constant SIG_L2_SUPPLY = "supply(bytes32)";
    string internal constant SIG_L2_WITHDRAW = "withdraw(bytes32)";

    function _sel(string memory sig) internal pure returns (bytes4) {
        return bytes4(keccak256(bytes(sig)));
    }

    function _supplyCd(address asset, uint256 amount, address onBehalfOf, uint16 ref)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSignature(SIG_SUPPLY, asset, amount, onBehalfOf, ref);
    }

    // ------------------------------------------------------------ supply (9)

    function test_Supply_AssetReceiverAndCapPinned_Passes() public view {
        Permission memory p = _perm(
            POOL,
            _sel(SIG_SUPPLY),
            _rules3(
                _ruleAddr(0, OP_EQ, USDC),
                _ruleUint(32, OP_LTE, 10_000e6),
                _ruleAddr(64, OP_EQ, ACCOUNT)
            )
        );
        _assertValid(_supplyCd(USDC, 5_000e6, ACCOUNT, 0), p);
    }

    function test_Supply_WrongAsset_Reverts() public {
        Permission memory p = _perm(POOL, _sel(SIG_SUPPLY), _rules1(_ruleAddr(0, OP_EQ, USDC)));
        _expectRuleViolation(_supplyCd(DAI, 5_000e18, ACCOUNT, 0), p, 0);
    }

    function test_Supply_AmountAboveCap_Reverts() public {
        Permission memory p = _perm(POOL, _sel(SIG_SUPPLY), _rules1(_ruleUint(32, OP_LTE, 10_000e6)));
        _expectRuleViolation(_supplyCd(USDC, 10_000e6 + 1, ACCOUNT, 0), p, 0);
    }

    function test_Supply_AmountExactlyAtCap_Passes() public view {
        Permission memory p = _perm(POOL, _sel(SIG_SUPPLY), _rules1(_ruleUint(32, OP_LTE, 10_000e6)));
        _assertValid(_supplyCd(USDC, 10_000e6, ACCOUNT, 0), p);
    }

    function test_Supply_ZeroAmountBlockedByGtRule_Reverts() public {
        Permission memory p = _perm(POOL, _sel(SIG_SUPPLY), _rules1(_ruleUint(32, OP_GT, 0)));
        _expectRuleViolation(_supplyCd(USDC, 0, ACCOUNT, 0), p, 0);
    }

    function test_Supply_NonzeroReferralCodeBlocked_Reverts() public {
        // referralCode is a uint16 padded to a full word at offset 96
        Permission memory p = _perm(POOL, _sel(SIG_SUPPLY), _rules1(_ruleUint(96, OP_EQ, 0)));
        _expectRuleViolation(_supplyCd(USDC, 1e6, ACCOUNT, 42), p, 0);
    }

    function test_Supply_OnBehalfOfAttacker_Reverts() public {
        Permission memory p = _perm(POOL, _sel(SIG_SUPPLY), _rules1(_ruleAddr(64, OP_EQ, ACCOUNT)));
        _expectRuleViolation(_supplyCd(USDC, 1e6, ATTACKER, 0), p, 0);
    }

    function test_Supply_AssetInAllowlist_Passes() public view {
        Permission memory p =
            _perm(POOL, _sel(SIG_SUPPLY), _rules1(_ruleIn(0, _addrSet3(USDC, WETH, DAI))));
        _assertValid(_supplyCd(WETH, 1e18, ACCOUNT, 0), p);
    }

    function test_Supply_AssetNotInAllowlist_Reverts() public {
        Permission memory p =
            _perm(POOL, _sel(SIG_SUPPLY), _rules1(_ruleIn(0, _addrSet3(USDC, WETH, DAI))));
        _expectNotInSet(_supplyCd(WBTC, 1e8, ACCOUNT, 0), p, 0);
    }

    // ------------------------------------------------------ deposit alias (2)

    function test_Deposit_DeprecatedAlias_SameLayoutValidates() public view {
        // deposit() shares supply()'s exact layout but has its own selector,
        // so it needs (and can be granted) its own permission leaf.
        Permission memory p = _perm(
            POOL,
            _sel(SIG_DEPOSIT),
            _rules2(_ruleAddr(0, OP_EQ, USDC), _ruleAddr(64, OP_EQ, ACCOUNT))
        );
        _assertValid(abi.encodeWithSignature(SIG_DEPOSIT, USDC, uint256(1e6), ACCOUNT, uint16(0)), p);
    }

    function test_Deposit_CalldataAgainstSupplyPermission_SelectorMismatch() public view {
        // A supply-only permission must NOT authorize the deprecated deposit alias.
        Permission memory p = _perm(POOL, _sel(SIG_SUPPLY), _noRules());
        _assertSelectorMismatch(
            abi.encodeWithSignature(SIG_DEPOSIT, USDC, uint256(1e6), ACCOUNT, uint16(0)), p
        );
    }

    // ----------------------------------------------------------- withdraw (6)

    function test_Withdraw_RecipientPinned_Passes() public view {
        Permission memory p = _perm(
            POOL, _sel(SIG_WITHDRAW), _rules2(_ruleAddr(0, OP_EQ, USDC), _ruleAddr(64, OP_EQ, ACCOUNT))
        );
        _assertValid(abi.encodeWithSignature(SIG_WITHDRAW, USDC, uint256(500e6), ACCOUNT), p);
    }

    function test_Withdraw_RecipientAttacker_Reverts() public {
        Permission memory p = _perm(POOL, _sel(SIG_WITHDRAW), _rules1(_ruleAddr(64, OP_EQ, ACCOUNT)));
        _expectRuleViolation(abi.encodeWithSignature(SIG_WITHDRAW, USDC, uint256(500e6), ATTACKER), p, 0);
    }

    function test_Withdraw_FullWithdrawSentinelOnly_ViaOpIn_Passes() public view {
        // Policy that ONLY allows the canonical "withdraw everything" sentinel
        bytes32[] memory allowed = new bytes32[](1);
        allowed[0] = bytes32(type(uint256).max);
        Permission memory p = _perm(POOL, _sel(SIG_WITHDRAW), _rules1(_ruleIn(32, allowed)));
        _assertValid(abi.encodeWithSignature(SIG_WITHDRAW, USDC, type(uint256).max, ACCOUNT), p);
    }

    function test_Withdraw_MaxSentinelBlockedByLteCap_Reverts() public {
        // An amount cap silently also blocks the uint256.max "withdraw all" sentinel —
        // the policy compiler must decide this explicitly, so we lock the behavior.
        Permission memory p = _perm(POOL, _sel(SIG_WITHDRAW), _rules1(_ruleUint(32, OP_LTE, 1_000e6)));
        _expectRuleViolation(abi.encodeWithSignature(SIG_WITHDRAW, USDC, type(uint256).max, ACCOUNT), p, 0);
    }

    function test_Withdraw_SignedGuardAllowsNormalAmount_Passes() public view {
        // OP_SGT with expected = -1 accepts any amount with the top bit clear
        Permission memory p = _perm(
            POOL, _sel(SIG_WITHDRAW), _rules1(_rule(32, OP_SGT, bytes32(uint256(int256(-1)))))
        );
        _assertValid(abi.encodeWithSignature(SIG_WITHDRAW, USDC, uint256(1e6), ACCOUNT), p);
    }

    function test_Withdraw_SignedGuardBlocksMaxSentinel_Reverts() public {
        // uint256.max reinterpreted as int256 is -1, which is not > -1
        Permission memory p = _perm(
            POOL, _sel(SIG_WITHDRAW), _rules1(_rule(32, OP_SGT, bytes32(uint256(int256(-1)))))
        );
        _expectRuleViolation(abi.encodeWithSignature(SIG_WITHDRAW, USDC, type(uint256).max, ACCOUNT), p, 0);
    }

    // ------------------------------------------------------------- borrow (3)

    function test_Borrow_VariableRateModeOnly_Passes() public view {
        // Since v3.2 only interestRateMode == 2 (variable) is valid on-chain
        Permission memory p = _perm(
            POOL,
            _sel(SIG_BORROW),
            _rules2(_ruleUint(64, OP_EQ, 2), _ruleAddr(128, OP_EQ, ACCOUNT))
        );
        _assertValid(
            abi.encodeWithSignature(SIG_BORROW, USDC, uint256(100e6), uint256(2), uint16(0), ACCOUNT), p
        );
    }

    function test_Borrow_DeprecatedStableRateMode_Reverts() public {
        Permission memory p = _perm(POOL, _sel(SIG_BORROW), _rules1(_ruleUint(64, OP_EQ, 2)));
        _expectRuleViolation(
            abi.encodeWithSignature(SIG_BORROW, USDC, uint256(100e6), uint256(1), uint16(0), ACCOUNT), p, 0
        );
    }

    function test_Borrow_OnBehalfOfAtWordFour_AttackerReverts() public {
        // onBehalfOf is the LAST word (offset 128) in borrow — credit delegation target
        Permission memory p = _perm(POOL, _sel(SIG_BORROW), _rules1(_ruleAddr(128, OP_EQ, ACCOUNT)));
        _expectRuleViolation(
            abi.encodeWithSignature(SIG_BORROW, USDC, uint256(100e6), uint256(2), uint16(0), ATTACKER), p, 0
        );
    }

    // -------------------------------------------------------------- repay (2)

    function test_Repay_RepayAllSentinel_Passes() public view {
        Permission memory p = _perm(
            POOL,
            _sel(SIG_REPAY),
            _rules2(_ruleUint(32, OP_EQ, type(uint256).max), _ruleAddr(96, OP_EQ, ACCOUNT))
        );
        _assertValid(
            abi.encodeWithSignature(SIG_REPAY, USDC, type(uint256).max, uint256(2), ACCOUNT), p
        );
    }

    function test_RepayWithATokens_ThreeWordExactFit_Passes() public view {
        // 100-byte calldata; rule on the last word: 4 + 64 + 32 == 100 (exact fit)
        Permission memory p = _perm(
            POOL,
            _sel(SIG_REPAY_ATOKENS),
            _rules2(_ruleAddr(0, OP_EQ, USDC), _ruleUint(64, OP_EQ, 2))
        );
        _assertValid(
            abi.encodeWithSignature(SIG_REPAY_ATOKENS, USDC, uint256(50e6), uint256(2)), p
        );
    }

    // -------------------------------------------- collateral / eMode flags (3)

    function test_SetCollateral_EnableOnlyPolicy_Passes() public view {
        Permission memory p = _perm(
            POOL,
            _sel(SIG_SET_COLLATERAL),
            _rules2(_ruleAddr(0, OP_EQ, WETH), _ruleUint(32, OP_EQ, 1))
        );
        _assertValid(abi.encodeWithSignature(SIG_SET_COLLATERAL, WETH, true), p);
    }

    function test_SetCollateral_DisableBlockedByEnableOnlyPolicy_Reverts() public {
        // Disabling collateral can trigger liquidation — enable-only session policy
        Permission memory p = _perm(POOL, _sel(SIG_SET_COLLATERAL), _rules1(_ruleUint(32, OP_EQ, 1)));
        _expectRuleViolation(abi.encodeWithSignature(SIG_SET_COLLATERAL, WETH, false), p, 0);
    }

    function test_SetUserEMode_CategoryAboveCap_Reverts() public {
        Permission memory p = _perm(POOL, _sel(SIG_SET_EMODE), _rules1(_ruleUint(0, OP_LTE, 3)));
        _expectRuleViolation(abi.encodeWithSignature(SIG_SET_EMODE, uint8(5)), p, 0);
    }

    // ------------------------------------------------------ liquidationCall (1)

    function test_LiquidationCall_BorrowerAndFlagsPinned_ExactFit_Passes() public view {
        // 164-byte calldata; receiveAToken bool at offset 128: 4 + 128 + 32 == 164
        Permission memory p = _perm(
            POOL,
            _sel(SIG_LIQUIDATION),
            _rules3(
                _ruleAddr(32, OP_EQ, USDC), // debtAsset
                _ruleAddr(64, OP_EQ, ATTACKER), // borrower being liquidated
                _ruleUint(128, OP_EQ, 0) // receiveAToken = false
            )
        );
        _assertValid(
            abi.encodeWithSignature(SIG_LIQUIDATION, WETH, USDC, ATTACKER, uint256(1_000e6), false), p
        );
    }

    // ------------------------------------------------------ permit variant (2)

    function test_SupplyWithPermit_DeadlineCapped_Passes() public view {
        // 260-byte, 8-word static layout; deadline at offset 128
        Permission memory p = _perm(
            POOL,
            _sel(SIG_SUPPLY_PERMIT),
            _rules2(_ruleAddr(0, OP_EQ, USDC), _ruleUint(128, OP_LTE, 1_800_000_000))
        );
        _assertValid(
            abi.encodeWithSignature(
                SIG_SUPPLY_PERMIT,
                USDC,
                uint256(1e6),
                ACCOUNT,
                uint16(0),
                uint256(1_750_000_000),
                uint8(27),
                bytes32(uint256(0xaaaa)),
                bytes32(uint256(0xbbbb))
            ),
            p
        );
    }

    function test_SupplyWithPermit_RuleOnFinalSWord_ExactFit_Passes() public view {
        // permitS occupies the final word at offset 224: 4 + 224 + 32 == 260 (exact fit)
        bytes32 s = bytes32(uint256(0xbbbb));
        Permission memory p = _perm(POOL, _sel(SIG_SUPPLY_PERMIT), _rules1(_rule(224, OP_EQ, s)));
        _assertValid(
            abi.encodeWithSignature(
                SIG_SUPPLY_PERMIT,
                USDC,
                uint256(1e6),
                ACCOUNT,
                uint16(0),
                uint256(1_750_000_000),
                uint8(27),
                bytes32(uint256(0xaaaa)),
                s
            ),
            p
        );
    }

    // ----------------------------------------------------------- flashLoan (3)

    function _flashLoanCd(address receiver, address asset, uint256 amount)
        internal
        pure
        returns (bytes memory)
    {
        address[] memory assets = new address[](1);
        assets[0] = asset;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = amount;
        uint256[] memory modes = new uint256[](1);
        modes[0] = 0;
        return abi.encodeWithSignature(
            SIG_FLASHLOAN, receiver, assets, amounts, modes, address(0), bytes(""), uint16(0)
        );
    }

    function test_FlashLoan_CanonicalHeadPointerPinned_Passes() public view {
        // Head is 7 words; the assets[] offset pointer at word 1 is 0xe0 in
        // canonical encoding. Pinning pointers freezes the ABI layout so tail
        // rules below cannot be dodged by relocating the tail.
        Permission memory p = _perm(
            POOL,
            _sel(SIG_FLASHLOAN),
            _rules2(_ruleAddr(0, OP_EQ, ACCOUNT), _ruleUint(32, OP_EQ, 0xe0))
        );
        _assertValid(_flashLoanCd(ACCOUNT, USDC, 1_000e6), p);
    }

    function test_FlashLoan_WrongReceiver_Reverts() public {
        Permission memory p = _perm(POOL, _sel(SIG_FLASHLOAN), _rules1(_ruleAddr(0, OP_EQ, ACCOUNT)));
        _expectRuleViolation(_flashLoanCd(ATTACKER, USDC, 1_000e6), p, 0);
    }

    function test_FlashLoan_RuleReadsAssetElementInTail_Passes() public view {
        // With the pointer pinned to 0xe0: assets.length sits at offset 224 and
        // assets[0] at offset 256 — a rule can then safely target tail data.
        Permission memory p = _perm(
            POOL,
            _sel(SIG_FLASHLOAN),
            _rules3(
                _ruleUint(32, OP_EQ, 0xe0), // pin assets pointer
                _ruleUint(224, OP_EQ, 1), // assets.length == 1
                _ruleAddr(256, OP_EQ, USDC) // assets[0]
            )
        );
        _assertValid(_flashLoanCd(ACCOUNT, USDC, 1_000e6), p);
    }

    // ------------------------------------------------------- mintToTreasury (2)

    function test_MintToTreasury_CanonicalArrayPinned_Passes() public view {
        address[] memory assets = new address[](1);
        assets[0] = USDC;
        Permission memory p = _perm(
            POOL,
            _sel(SIG_MINT_TO_TREASURY),
            _rules3(
                _ruleUint(0, OP_EQ, 0x20), // canonical array pointer
                _ruleUint(32, OP_EQ, 1), // length == 1
                _ruleAddr(64, OP_EQ, USDC) // element 0
            )
        );
        _assertValid(abi.encodeWithSignature(SIG_MINT_TO_TREASURY, assets), p);
    }

    function test_MintToTreasury_RelocatedTail_CaughtByPointerRule() public {
        // Same decoded arguments, non-canonical pointer (0x40 with a junk word).
        // Without the pointer rule, the length/element rules would read the junk
        // word instead of the real array — this is THE core fixed-offset hazard.
        bytes memory cd = abi.encodePacked(
            _sel(SIG_MINT_TO_TREASURY),
            uint256(0x40), // non-canonical pointer
            uint256(0xdead), // junk word where the length "should" be
            uint256(1), // real length
            bytes32(uint256(uint160(USDC))) // real element
        );
        Permission memory p = _perm(
            POOL,
            _sel(SIG_MINT_TO_TREASURY),
            _rules2(_ruleUint(0, OP_EQ, 0x20), _ruleUint(32, OP_EQ, 1))
        );
        _expectRuleViolation(cd, p, 0);
    }

    // ------------------------------------------------------------ multicall (1)

    function test_Multicall_NotUnwrapped_SupplyPermissionRejectsIt() public view {
        // Pool inherits OZ Multicall. The validator does NOT recurse into
        // bytes[] elements, so a supply permission must reject multicall
        // calldata outright (selector mismatch) — granting 0xac9650d8 itself
        // would be an unrestricted bypass and must never be done.
        bytes[] memory inner = new bytes[](1);
        inner[0] = _supplyCd(USDC, 1e6, ACCOUNT, 0);
        Permission memory p = _perm(POOL, _sel(SIG_SUPPLY), _noRules());
        _assertSelectorMismatch(abi.encodeWithSignature(SIG_MULTICALL, inner), p);
    }

    // ------------------------------------------------- L2Pool compact args (4)

    function _l2SupplyWord(uint16 assetId, uint128 amount, uint16 ref) internal pure returns (bytes32) {
        return bytes32(uint256(assetId) | (uint256(amount) << 16) | (uint256(ref) << 144));
    }

    function _l2WithdrawWord(uint16 assetId, uint128 amount) internal pure returns (bytes32) {
        return bytes32(uint256(assetId) | (uint256(amount) << 16));
    }

    function test_L2Supply_ExactPackedWordPinned_Passes() public view {
        // Packed bytes32: [0:16) assetId | [16:144) amount | [144:160) referral.
        // Field-level ops don't exist, so the safe policy is EQ on the whole word.
        bytes32 packed = _l2SupplyWord(1, 1_000e6, 0);
        Permission memory p = _perm(POOL, _sel(SIG_L2_SUPPLY), _rules1(_rule(0, OP_EQ, packed)));
        _assertValid(abi.encodeWithSignature(SIG_L2_SUPPLY, packed), p);
    }

    function test_L2Supply_DifferentAmountInPackedWord_Reverts() public {
        Permission memory p = _perm(
            POOL, _sel(SIG_L2_SUPPLY), _rules1(_rule(0, OP_EQ, _l2SupplyWord(1, 1_000e6, 0)))
        );
        bytes32 tampered = _l2SupplyWord(1, 2_000e6, 0);
        _expectRuleViolation(abi.encodeWithSignature(SIG_L2_SUPPLY, tampered), p, 0);
    }

    function test_L2Withdraw_PackedLteCapSameAsset_Passes() public view {
        // With assetId fixed in the low 16 bits and zero padding above bit 144,
        // LTE on the whole packed word caps the amount field.
        Permission memory p = _perm(
            POOL, _sel(SIG_L2_WITHDRAW), _rules1(_rule(0, OP_LTE, _l2WithdrawWord(1, 5_000e6)))
        );
        _assertValid(abi.encodeWithSignature(SIG_L2_WITHDRAW, _l2WithdrawWord(1, 4_000e6)), p);
    }

    function test_L2Withdraw_PackedCapExceeded_Reverts() public {
        Permission memory p = _perm(
            POOL, _sel(SIG_L2_WITHDRAW), _rules1(_rule(0, OP_LTE, _l2WithdrawWord(1, 5_000e6)))
        );
        _expectRuleViolation(abi.encodeWithSignature(SIG_L2_WITHDRAW, _l2WithdrawWord(1, 5_000e6 + 1)), p, 0);
    }

    // ------------------------------------------------- length boundaries (3)

    function test_ShortCalldata_UnderFourBytes_InvalidLength() public view {
        Permission memory p = _perm(POOL, _sel(SIG_SUPPLY), _noRules());
        _assertInvalidLength(hex"617ba0", p);
    }

    function test_SelectorOnlyCalldata_RuleAtOffsetZero_OutOfRange() public {
        Permission memory p = _perm(POOL, _sel(SIG_SET_EMODE), _rules1(_ruleUint(0, OP_EQ, 1)));
        _expectOutOfRange(abi.encodePacked(_sel(SIG_SET_EMODE)), p, 4);
    }

    function test_Supply_TruncatedByOneByte_RuleOnLastWord_OutOfRange() public {
        // 131 of 132 bytes: rule at offset 96 needs bytes [100, 132) — one short
        bytes memory cd = _truncate(_supplyCd(USDC, 1e6, ACCOUNT, 0), 131);
        Permission memory p = _perm(POOL, _sel(SIG_SUPPLY), _rules1(_ruleUint(96, OP_EQ, 0)));
        _expectOutOfRange(cd, p, 100);
    }

    // ------------------------------------------------- wrapped execution (1)

    function test_Wrapped4337_InnerSupplyDecodedAndValidated() public view {
        bytes memory inner = _supplyCd(USDC, 1_000e6, ACCOUNT, 0);
        bytes memory wrapped = _wrap4337(POOL, 0, inner);

        (ClankerGateCore.ExecKind kind, address target, uint256 innerOffset, uint256 innerLength,) =
            harness.decodeAny(wrapped);

        assertEq(uint8(kind), uint8(ClankerGateCore.ExecKind.Execute4337));
        assertEq(target, POOL, "wrapper target must be the Pool");
        assertEq(innerLength, inner.length, "inner length preserved");

        Permission memory p = _perm(
            POOL,
            _sel(SIG_SUPPLY),
            _rules2(_ruleAddr(0, OP_EQ, USDC), _ruleUint(32, OP_LTE, 10_000e6))
        );
        _assertValid(_slice(wrapped, innerOffset, innerLength), p);
    }
}
