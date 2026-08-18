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

/// @title Aave v4 (Hub-and-Spoke) calldata-policy scenarios (25 cases)
/// @notice Validates ClankerGateCore.validateCallDataExtended against Aave v4
///         user entry points: the Spoke (reserveId-addressed, one contract for many
///         reserves), the SignatureGateway / position-manager intent functions with
///         inline static tuples, the one dynamic tuple (SetUserPositionManagers),
///         the NativeTokenGateway, and the ERC-4626 TokenizationSpoke.
/// @dev v4 has no flashloan and no eMode. reserveId is a uint256 word (not an
///      address), so pinning it is the v4 analogue of pinning an asset address.
///      Spoke withdraw/repay treat ANY amount >= balance/debt as "all" — there is
///      no uint256.max sentinel, which makes amount caps even more important.
contract AaveV4CalldataTest is ProtocolCalldataTestBase {
    address internal constant SPOKE = 0x5b0ce00000000000000000000000000000000001;
    address internal constant SIG_GATEWAY = 0x9a7E000000000000000000000000000000000001;
    address internal constant GIVER_PM = 0x91fE000000000000000000000000000000000001;
    address internal constant TAKER_PM = 0x7A6e000000000000000000000000000000000001;
    address internal constant CONFIG_PM = 0xC0ff000000000000000000000000000000000001;
    address internal constant NATIVE_GW = 0x6a70000000000000000000000000000000000001;
    address internal constant TOKENIZATION_SPOKE = 0x4626000000000000000000000000000000000001;
    address internal constant MANAGER = 0x1111111254EEB25477B68fb85Ed929f73A960582;

    uint256 internal constant USDC_RESERVE = 3;
    uint256 internal constant WETH_RESERVE = 1;

    // Spoke
    string internal constant SIG_SUPPLY = "supply(uint256,uint256,address)";
    string internal constant SIG_WITHDRAW = "withdraw(uint256,uint256,address)";
    string internal constant SIG_BORROW = "borrow(uint256,uint256,address)";
    string internal constant SIG_REPAY = "repay(uint256,uint256,address)";
    string internal constant SIG_LIQUIDATION = "liquidationCall(uint256,uint256,address,uint256,bool)";
    string internal constant SIG_SET_COLLATERAL = "setUsingAsCollateral(uint256,bool,address)";
    string internal constant SIG_SET_PM = "setUserPositionManager(address,bool)";
    string internal constant SIG_SET_PMS_WITH_SIG =
        "setUserPositionManagersWithSig((address,(address,bool)[],uint256,uint256),bytes)";
    // SignatureGateway
    string internal constant SIG_SUPPLY_WITH_SIG =
        "supplyWithSig((address,uint256,uint256,address,uint256,uint256),bytes)";
    string internal constant SIG_WITHDRAW_WITH_SIG =
        "withdrawWithSig((address,uint256,uint256,address,uint256,uint256),bytes)";
    string internal constant SIG_BORROW_WITH_SIG =
        "borrowWithSig((address,uint256,uint256,address,uint256,uint256),bytes)";
    // ConfigPositionManager
    string internal constant SIG_SET_GLOBAL_PERM_WITH_SIG =
        "setGlobalPermissionWithSig((address,address,address,bool,uint256,uint256),bytes)";
    string internal constant SIG_SET_COLLATERAL_PERM_WITH_SIG =
        "setCanSetUsingAsCollateralPermissionWithSig((address,address,address,bool,uint256,uint256),bytes)";
    // Giver / Taker position managers
    string internal constant SIG_REPAY_ON_BEHALF = "repayOnBehalfOf(address,uint256,uint256,address)";
    string internal constant SIG_APPROVE_BORROW = "approveBorrow(address,uint256,address,uint256)";
    // NativeTokenGateway
    string internal constant SIG_SUPPLY_NATIVE = "supplyNative(address,uint256,uint256)";
    // TokenizationSpoke (ERC-4626)
    string internal constant SIG_4626_WITHDRAW = "withdraw(uint256,address,address)";
    string internal constant SIG_DEPOSIT_WITH_SIG =
        "depositWithSig((address,uint256,address,uint256,uint256),bytes)";
    string internal constant SIG_MINT_WITH_SIG =
        "mintWithSig((address,uint256,address,uint256,uint256),bytes)";

    struct PositionManagerUpdate {
        address positionManager;
        bool approve;
    }

    struct SetUserPositionManagers {
        address onBehalfOf;
        PositionManagerUpdate[] updates;
        uint256 nonce;
        uint256 deadline;
    }

    struct GatewayIntent {
        address spoke;
        uint256 reserveId;
        uint256 amount;
        address onBehalfOf;
        uint256 nonce;
        uint256 deadline;
    }

    struct ConfigPermissionIntent {
        address spoke;
        address delegator;
        address delegatee;
        bool status;
        uint256 nonce;
        uint256 deadline;
    }

    struct TokenizedIntent {
        address depositor;
        uint256 assets;
        address receiver;
        uint256 nonce;
        uint256 deadline;
    }

    function _sel(string memory sig) internal pure returns (bytes4) {
        return bytes4(keccak256(bytes(sig)));
    }

    function _dummySig() internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(uint256(0xaaaa)), bytes32(uint256(0xbbbb)), uint8(27));
    }

    // ---------------------------------------------------------- Spoke core (8)

    function test_Supply_ReserveAndReceiverPinned_Passes() public view {
        // supply(reserveId, amount, onBehalfOf): 0 | 32 | 64
        Permission memory p = _perm(
            SPOKE,
            _sel(SIG_SUPPLY),
            _rules3(
                _ruleUint(0, OP_EQ, USDC_RESERVE),
                _ruleUint(32, OP_LTE, 10_000e6),
                _ruleAddr(64, OP_EQ, ACCOUNT)
            )
        );
        _assertValid(abi.encodeWithSignature(SIG_SUPPLY, USDC_RESERVE, uint256(5_000e6), ACCOUNT), p);
    }

    function test_Supply_WrongReserveId_Reverts() public {
        Permission memory p = _perm(SPOKE, _sel(SIG_SUPPLY), _rules1(_ruleUint(0, OP_EQ, USDC_RESERVE)));
        _expectRuleViolation(
            abi.encodeWithSignature(SIG_SUPPLY, WETH_RESERVE, uint256(1e18), ACCOUNT), p, 0
        );
    }

    function test_Supply_OnBehalfOfAttacker_Reverts() public {
        Permission memory p = _perm(SPOKE, _sel(SIG_SUPPLY), _rules1(_ruleAddr(64, OP_EQ, ACCOUNT)));
        _expectRuleViolation(
            abi.encodeWithSignature(SIG_SUPPLY, USDC_RESERVE, uint256(1e6), ATTACKER), p, 0
        );
    }

    function test_Borrow_AmountAboveCap_Reverts() public {
        Permission memory p = _perm(SPOKE, _sel(SIG_BORROW), _rules1(_ruleUint(32, OP_LTE, 1_000e6)));
        _expectRuleViolation(
            abi.encodeWithSignature(SIG_BORROW, USDC_RESERVE, uint256(1_000e6 + 1), ACCOUNT), p, 0
        );
    }

    function test_Withdraw_SignedGuardAllowsNormalAmount_Passes() public view {
        // v4 withdraw clamps ANY oversized amount to the full balance (no explicit
        // max sentinel), so a top-bit guard still permits every realistic amount.
        Permission memory p = _perm(
            SPOKE, _sel(SIG_WITHDRAW), _rules1(_rule(32, OP_SGT, bytes32(uint256(int256(-1)))))
        );
        _assertValid(abi.encodeWithSignature(SIG_WITHDRAW, USDC_RESERVE, uint256(750e6), ACCOUNT), p);
    }

    function test_Withdraw_SignedGuardBlocksImplicitFullWithdraw_Reverts() public {
        Permission memory p = _perm(
            SPOKE, _sel(SIG_WITHDRAW), _rules1(_rule(32, OP_SGT, bytes32(uint256(int256(-1)))))
        );
        _expectRuleViolation(
            abi.encodeWithSignature(SIG_WITHDRAW, USDC_RESERVE, type(uint256).max, ACCOUNT), p, 0
        );
    }

    function test_Repay_OverpayClampedOnChain_PolicyAllowsAnyAmount_Passes() public view {
        // repay clamps to the full debt, so a repay-only permission can safely
        // leave the amount unconstrained and pin reserve + debtor instead.
        Permission memory p = _perm(
            SPOKE,
            _sel(SIG_REPAY),
            _rules2(_ruleUint(0, OP_EQ, USDC_RESERVE), _ruleAddr(64, OP_EQ, ACCOUNT))
        );
        _assertValid(abi.encodeWithSignature(SIG_REPAY, USDC_RESERVE, type(uint256).max, ACCOUNT), p);
    }

    function test_LiquidationCall_FiveWordExactFit_Passes() public view {
        // liquidationCall(collateralReserveId, debtReserveId, user, debtToCover,
        // receiveShares): 164 bytes; bool at offset 128: 4 + 128 + 32 == 164
        Permission memory p = _perm(
            SPOKE,
            _sel(SIG_LIQUIDATION),
            _rules3(
                _ruleUint(32, OP_EQ, USDC_RESERVE), // debt reserve
                _ruleAddr(64, OP_EQ, ATTACKER), // liquidated user
                _ruleUint(128, OP_EQ, 0) // receiveShares = false
            )
        );
        _assertValid(
            abi.encodeWithSignature(
                SIG_LIQUIDATION, WETH_RESERVE, USDC_RESERVE, ATTACKER, uint256(1_000e6), false
            ),
            p
        );
    }

    // ---------------------------------------- collateral & position manager (4)

    function test_SetUsingAsCollateral_EnableOnly_Passes() public view {
        // setUsingAsCollateral(reserveId, usingAsCollateral, onBehalfOf): 0 | 32 | 64
        Permission memory p = _perm(
            SPOKE,
            _sel(SIG_SET_COLLATERAL),
            _rules2(_ruleUint(32, OP_EQ, 1), _ruleAddr(64, OP_EQ, ACCOUNT))
        );
        _assertValid(abi.encodeWithSignature(SIG_SET_COLLATERAL, WETH_RESERVE, true, ACCOUNT), p);
    }

    function test_SetUsingAsCollateral_DisableBlocked_Reverts() public {
        Permission memory p = _perm(SPOKE, _sel(SIG_SET_COLLATERAL), _rules1(_ruleUint(32, OP_EQ, 1)));
        _expectRuleViolation(
            abi.encodeWithSignature(SIG_SET_COLLATERAL, WETH_RESERVE, false, ACCOUNT), p, 0
        );
    }

    function test_SetUserPositionManager_InAllowlist_Passes() public view {
        // Position managers get sweeping onBehalfOf powers — allowlist them
        Permission memory p = _perm(
            SPOKE,
            _sel(SIG_SET_PM),
            _rules2(_ruleIn(0, _addrSet3(GIVER_PM, TAKER_PM, CONFIG_PM)), _ruleUint(32, OP_EQ, 1))
        );
        _assertValid(abi.encodeWithSignature(SIG_SET_PM, TAKER_PM, true), p);
    }

    function test_SetUserPositionManager_UnknownManager_Reverts() public {
        Permission memory p =
            _perm(SPOKE, _sel(SIG_SET_PM), _rules1(_ruleIn(0, _addrSet3(GIVER_PM, TAKER_PM, CONFIG_PM))));
        _expectNotInSet(abi.encodeWithSignature(SIG_SET_PM, ATTACKER, true), p, 0);
    }

    // ------------------------------- setUserPositionManagersWithSig (dynamic) (3)

    function _pmsWithSigCd(address onBehalfOf, address manager, bool approve)
        internal
        pure
        returns (bytes memory)
    {
        SetUserPositionManagers memory params;
        params.onBehalfOf = onBehalfOf;
        params.updates = new PositionManagerUpdate[](1);
        params.updates[0] = PositionManagerUpdate(manager, approve);
        params.nonce = 1;
        params.deadline = 1_750_000_000;
        return abi.encodeWithSelector(_sel(SIG_SET_PMS_WITH_SIG), params, _dummySig());
    }

    function test_SetUserPositionManagersWithSig_CanonicalHeadPointers_Passes() public view {
        // The only dynamic tuple in v4: head = [params ptr (0x40), signature ptr
        // (0x120 for a 1-element updates array)]. Pinning both freezes the layout.
        Permission memory p = _perm(
            SPOKE,
            _sel(SIG_SET_PMS_WITH_SIG),
            _rules2(_ruleUint(0, OP_EQ, 0x40), _ruleUint(32, OP_EQ, 0x120))
        );
        _assertValid(_pmsWithSigCd(ACCOUNT, TAKER_PM, true), p);
    }

    function test_SetUserPositionManagersWithSig_TailFieldsPinned_Passes() public view {
        // With pointers frozen: onBehalfOf @64, inner updates ptr @96 (=0x80,
        // relative to the tuple start), updates.length @192, updates[0].approve @256
        Permission memory p = _perm(
            SPOKE,
            _sel(SIG_SET_PMS_WITH_SIG),
            _rules4(
                _ruleUint(0, OP_EQ, 0x40),
                _ruleAddr(64, OP_EQ, ACCOUNT),
                _ruleUint(192, OP_EQ, 1), // exactly one update per call
                _ruleAddr(224, OP_EQ, TAKER_PM) // updates[0].positionManager
            )
        );
        _assertValid(_pmsWithSigCd(ACCOUNT, TAKER_PM, true), p);
    }

    function test_SetUserPositionManagersWithSig_RelocatedParams_CaughtByPointerRule() public {
        // Attacker shifts the params tuple one word (ptr 0x60 + junk); tail rules
        // would silently read shifted garbage were the pointer not pinned.
        bytes memory cd = abi.encodePacked(
            _sel(SIG_SET_PMS_WITH_SIG),
            uint256(0x60), // non-canonical params pointer
            uint256(0x140), // shifted signature pointer
            uint256(0xdead), // junk word
            bytes32(uint256(uint160(ATTACKER))) // onBehalfOf now lives here
        );
        Permission memory p =
            _perm(SPOKE, _sel(SIG_SET_PMS_WITH_SIG), _rules1(_ruleUint(0, OP_EQ, 0x40)));
        _expectRuleViolation(cd, p, 0);
    }

    // ------------------------------------------------- SignatureGateway (3)

    function _gatewayIntentCd(string memory sig, address spoke, uint256 amount, address onBehalfOf)
        internal
        pure
        returns (bytes memory)
    {
        GatewayIntent memory intent =
            GatewayIntent(spoke, USDC_RESERVE, amount, onBehalfOf, 1, 1_750_000_000);
        return abi.encodeWithSelector(_sel(sig), intent, _dummySig());
    }

    function test_SupplyWithSig_InlineStaticTuple_Passes() public view {
        // The 6-field intent tuple is fully static, so it is encoded INLINE in the
        // head (no pointer): spoke @0, reserveId @32, amount @64, onBehalfOf @96,
        // nonce @128, deadline @160, then the signature pointer @192 (= 0xE0).
        Permission memory p = _perm(
            SIG_GATEWAY,
            _sel(SIG_SUPPLY_WITH_SIG),
            _rules4(
                _ruleAddr(0, OP_EQ, SPOKE),
                _ruleUint(64, OP_LTE, 10_000e6),
                _ruleAddr(96, OP_EQ, ACCOUNT),
                _ruleUint(192, OP_EQ, 0xE0)
            )
        );
        _assertValid(_gatewayIntentCd(SIG_SUPPLY_WITH_SIG, SPOKE, 5_000e6, ACCOUNT), p);
    }

    function test_BorrowWithSigCalldata_AgainstWithdrawWithSigPermission_SelectorMismatch()
        public
        view
    {
        // withdrawWithSig and borrowWithSig have byte-identical layouts — the
        // selector is the ONLY distinguisher, so this must hard-fail.
        Permission memory p = _perm(SIG_GATEWAY, _sel(SIG_WITHDRAW_WITH_SIG), _noRules());
        _assertSelectorMismatch(_gatewayIntentCd(SIG_BORROW_WITH_SIG, SPOKE, 1_000e6, ACCOUNT), p);
    }

    function test_ConfigPermissionWithSigVariants_SelectorOnlyDistinguisher_Mismatch() public view {
        // All four ConfigPositionManager *WithSig permission structs share one
        // layout; granting the collateral-toggle delegation must not authorize
        // the global-permission delegation.
        ConfigPermissionIntent memory intent =
            ConfigPermissionIntent(SPOKE, ACCOUNT, MANAGER, true, 1, 1_750_000_000);
        bytes memory cd =
            abi.encodeWithSelector(_sel(SIG_SET_GLOBAL_PERM_WITH_SIG), intent, _dummySig());
        Permission memory p = _perm(CONFIG_PM, _sel(SIG_SET_COLLATERAL_PERM_WITH_SIG), _noRules());
        _assertSelectorMismatch(cd, p);
    }

    // ------------------------------------------- Giver / Taker managers (3)

    function test_RepayOnBehalfOf_MaxUintBlocked_MirrorsOnChainRevert() public {
        // GiverPositionManager rejects amount == uint256.max on-chain
        // (RepayOnBehalfMaxUintNotAllowed); the policy mirrors it with OP_LT max.
        Permission memory p = _perm(
            GIVER_PM, _sel(SIG_REPAY_ON_BEHALF), _rules1(_ruleUint(64, OP_LT, type(uint256).max))
        );
        _expectRuleViolation(
            abi.encodeWithSignature(SIG_REPAY_ON_BEHALF, SPOKE, USDC_RESERVE, type(uint256).max, ACCOUNT),
            p,
            0
        );
    }

    function test_RepayOnBehalfOf_MaxMinusOne_RepayAllIdiom_Passes() public view {
        // uint256.max - 1 is the "repay everything" idiom for this manager
        Permission memory p = _perm(
            GIVER_PM,
            _sel(SIG_REPAY_ON_BEHALF),
            _rules2(_ruleUint(64, OP_LT, type(uint256).max), _ruleAddr(96, OP_EQ, ACCOUNT))
        );
        _assertValid(
            abi.encodeWithSignature(
                SIG_REPAY_ON_BEHALF, SPOKE, USDC_RESERVE, type(uint256).max - 1, ACCOUNT
            ),
            p
        );
    }

    function test_ApproveBorrow_InfiniteAllowanceSentinelBlocked_Reverts() public {
        // approveBorrow(spoke, reserveId, spender, amount): amount == uint256.max is
        // a never-decremented infinite allowance — block it, cap real approvals.
        Permission memory p = _perm(
            TAKER_PM,
            _sel(SIG_APPROVE_BORROW),
            _rules2(_ruleAddr(64, OP_EQ, MANAGER), _ruleUint(96, OP_LTE, 1_000e6))
        );
        _expectRuleViolation(
            abi.encodeWithSignature(SIG_APPROVE_BORROW, SPOKE, USDC_RESERVE, MANAGER, type(uint256).max),
            p,
            1
        );
    }

    // ------------------------------------------------ NativeTokenGateway (2)

    function test_SupplyNative_AmountCapped_Passes() public view {
        // supplyNative(spoke, reserveId, amount): the contract requires
        // msg.value == amount, so the calldata amount rule also constrains the ETH
        // sent (the gate's separate maxValue check must be set consistently).
        Permission memory p = _perm(
            NATIVE_GW,
            _sel(SIG_SUPPLY_NATIVE),
            _rules2(_ruleAddr(0, OP_EQ, SPOKE), _ruleUint(64, OP_LTE, 5e18))
        );
        _assertValid(abi.encodeWithSignature(SIG_SUPPLY_NATIVE, SPOKE, WETH_RESERVE, uint256(2e18)), p);
    }

    function test_SupplyNative_UnregisteredSpoke_Reverts() public {
        Permission memory p =
            _perm(NATIVE_GW, _sel(SIG_SUPPLY_NATIVE), _rules1(_ruleAddr(0, OP_EQ, SPOKE)));
        _expectRuleViolation(
            abi.encodeWithSignature(SIG_SUPPLY_NATIVE, ATTACKER, WETH_RESERVE, uint256(2e18)), p, 0
        );
    }

    // ------------------------------------------------ TokenizationSpoke (2)

    function test_Erc4626Withdraw_ReceiverAttacker_Reverts() public {
        // withdraw(assets, receiver, owner): receiver @32, owner @64
        Permission memory p = _perm(
            TOKENIZATION_SPOKE,
            _sel(SIG_4626_WITHDRAW),
            _rules2(_ruleAddr(32, OP_EQ, ACCOUNT), _ruleAddr(64, OP_EQ, ACCOUNT))
        );
        _expectRuleViolation(
            abi.encodeWithSignature(SIG_4626_WITHDRAW, uint256(1_000e6), ATTACKER, ACCOUNT), p, 0
        );
    }

    function test_DepositWithSigVsMintWithSig_IdenticalLayouts_SelectorMismatch() public view {
        // depositWithSig and mintWithSig tuples are byte-identical; only the
        // selector (and EIP-712 typehash) differ. assets-denominated permission
        // must not authorize the shares-denominated call.
        TokenizedIntent memory intent = TokenizedIntent(ACCOUNT, 1_000e6, ACCOUNT, 1, 1_750_000_000);
        bytes memory cd = abi.encodeWithSelector(_sel(SIG_MINT_WITH_SIG), intent, _dummySig());
        Permission memory p = _perm(TOKENIZATION_SPOKE, _sel(SIG_DEPOSIT_WITH_SIG), _noRules());
        _assertSelectorMismatch(cd, p);
    }
}
