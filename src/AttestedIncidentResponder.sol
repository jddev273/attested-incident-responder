// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IASCProofVerifier} from "@gluwa/asc-contracts/contracts/write-ability/abstract/IASCProofVerifier.sol";
import {ASCProofVerifier} from "@gluwa/asc-contracts/contracts/write-ability/common/ASCProofVerifier.sol";
import {BlockProverTypes} from "@gluwa/asc-contracts/contracts/write-ability/common/BlockProverTypes.sol";
import {ASCSdkV1TxBytesLib} from "@gluwa/asc-contracts/contracts/write-ability/common/ASCSdkV1TxBytesLib.sol";
import {EvmV1Decoder} from "@gluwa/asc-contracts/contracts/common/EvmV1Decoder.sol";

interface IAirContainmentTarget {
    function applyMode(uint8 mode) external;
}

/// @notice Creditcoin ChainInfo ABI subset. Production AIR binds this to native precompile 0x...0FD3.
interface IAirChainInfo {
    function get_latest_attestation_height_and_hash(uint64 chainKey)
        external
        view
        returns (uint64 height, bytes32 hash, bool isAttestation, bool exists);
}

contract SentryVault is IAirContainmentTarget {
    enum Mode {
        NORMAL,
        LIMITED,
        FROZEN
    }
    address public immutable owner;
    address public immutable operator;
    uint256 public immutable limitedBudget;
    address public responder;
    Mode public mode;
    uint256 public limitedSpent;
    uint256 public paymentNonce;
    bool private paying;

    error NotOwner();
    error NotResponder();
    error NotOperator();
    error ResponderAlreadyBound();
    error InvalidResponder();
    error InvalidOperator();
    error InvalidMode();
    error InvalidLimitedBudget();
    error InvalidPayment();
    error PaymentsFrozen();
    error LimitedBudgetExceeded();
    error PaymentFailed();
    error PaymentReentrant();
    event ResponderBound(address indexed responder);
    event ModeChanged(Mode indexed previousMode, Mode indexed newMode);
    event Funded(address indexed sender, uint256 amount);
    event PaymentExecuted(
        bytes32 indexed paymentId, address indexed recipient, uint256 amount, Mode mode, uint256 limitedSpent
    );

    /// @notice The operator is the only account that can move funds. AIR containment is therefore load-bearing:
    /// NORMAL permits ordinary payments, LIMITED enforces one cumulative incident budget, and FROZEN permits none.
    /// There is deliberately no owner withdrawal or alternate call path that bypasses these mode checks.
    constructor(address operator_, uint256 limitedBudget_) {
        owner = msg.sender;
        if (operator_ == address(0)) revert InvalidOperator();
        if (limitedBudget_ == 0) revert InvalidLimitedBudget();
        operator = operator_;
        limitedBudget = limitedBudget_;
    }

    receive() external payable {
        emit Funded(msg.sender, msg.value);
    }

    function bindResponder(address responder_) external {
        if (msg.sender != owner) revert NotOwner();
        if (responder != address(0)) revert ResponderAlreadyBound();
        if (responder_ == address(0) || responder_.code.length == 0) revert InvalidResponder();
        responder = responder_;
        emit ResponderBound(responder_);
    }

    function applyMode(uint8 mode_) external {
        if (msg.sender != responder) revert NotResponder();
        if (mode_ > uint8(Mode.FROZEN)) revert InvalidMode();
        Mode next = Mode(mode_);
        Mode previous = mode;
        mode = next;
        // The LIMITED budget spans all overlapping incidents and survives LIMITED <-> FROZEN transitions.
        // Only verified recovery all the way to NORMAL starts a fresh operating budget.
        if (next == Mode.NORMAL) limitedSpent = 0;
        emit ModeChanged(previous, next);
    }

    function executePayment(address payable recipient, uint256 amount) external returns (bytes32 paymentId) {
        if (msg.sender != operator) revert NotOperator();
        if (recipient == address(0) || amount == 0) revert InvalidPayment();
        if (paying) revert PaymentReentrant();
        paying = true;

        Mode current = mode;
        if (current == Mode.FROZEN) revert PaymentsFrozen();
        if (current == Mode.LIMITED) {
            uint256 nextSpent = limitedSpent + amount;
            if (nextSpent > limitedBudget) revert LimitedBudgetExceeded();
            limitedSpent = nextSpent;
        }

        uint256 nonce = ++paymentNonce;
        paymentId = keccak256(abi.encode(block.chainid, address(this), nonce, recipient, amount));
        (bool ok,) = recipient.call{value: amount}("");
        if (!ok) revert PaymentFailed();
        paying = false;
        emit PaymentExecuted(paymentId, recipient, amount, current, limitedSpent);
    }
}

/// @notice Foreign-chain semantic anchor. A guardian may trigger evaluation but cannot choose severity:
/// it is derived from the protected treasury's live source-chain balance and immutable thresholds.
contract SourceIncidentEmitter {
    address public immutable guardian;
    address public immutable protectedTreasury;
    uint256 public immutable warningFloor;
    uint256 public immutable criticalFloor;
    uint8 public lastRaisedSeverity;

    error NotGuardian();
    error InvalidThresholds();
    error NoObjectiveIncident();
    error ObjectiveSeverityMismatch();
    error SeverityNotEscalated();
    error RiskStillActive();
    event IncidentRaised(bytes32 indexed incidentId, bytes32 indexed deploymentId, uint8 severity, bytes32 policyHash);
    event IncidentResolved(bytes32 indexed incidentId, bytes32 indexed deploymentId, bytes32 policyHash);

    constructor(address guardian_, address protectedTreasury_, uint256 warningFloor_, uint256 criticalFloor_) {
        if (guardian_ == address(0)) revert NotGuardian();
        if (protectedTreasury_ == address(0)) revert InvalidThresholds();
        if (warningFloor_ <= criticalFloor_) revert InvalidThresholds();
        guardian = guardian_;
        protectedTreasury = protectedTreasury_;
        warningFloor = warningFloor_;
        criticalFloor = criticalFloor_;
    }

    function currentSeverity() public view returns (uint8) {
        uint256 balance = protectedTreasury.balance;
        if (balance <= criticalFloor) return 2;
        if (balance <= warningFloor) return 1;
        return 0;
    }

    function raiseIncident(bytes32 incidentId, bytes32 deploymentId, uint8 severity, bytes32 policyHash) external {
        if (msg.sender != guardian) revert NotGuardian();
        uint8 objectiveSeverity = currentSeverity();
        if (objectiveSeverity == 0) revert NoObjectiveIncident();
        if (severity != objectiveSeverity) revert ObjectiveSeverityMismatch();
        if (severity <= lastRaisedSeverity) revert SeverityNotEscalated();
        lastRaisedSeverity = severity;
        emit IncidentRaised(incidentId, deploymentId, severity, policyHash);
    }

    function resolveIncident(bytes32 incidentId, bytes32 deploymentId, bytes32 policyHash) external {
        if (msg.sender != guardian) revert NotGuardian();
        if (currentSeverity() != 0) revert RiskStillActive();
        lastRaisedSeverity = 0;
        emit IncidentResolved(incidentId, deploymentId, policyHash);
    }
}

/// @notice Testable AIR state machine. Production wrapper supplies the real ASCProofVerifier.
contract AirResponderCore {
    enum Mode {
        NORMAL,
        LIMITED,
        FROZEN
    }

    struct Policy {
        bytes32 deploymentId;
        uint64 sourceChainKey;
        uint64 sourceChainId;
        address sourceEmitter;
        uint64 validFromSourceBlock;
        uint64 validUntilSourceBlock;
        uint64 recoveryGraceBlocks;
        uint64 maxSourceLagBlocks;
    }

    struct ActiveIncident {
        bool active;
        Mode mode;
        uint64 sourceBlock;
        uint64 txIndex;
        bytes32 fingerprint;
    }

    bytes4 public constant RAISE_SELECTOR = bytes4(keccak256("raiseIncident(bytes32,bytes32,uint8,bytes32)"));
    bytes4 public constant RESOLVE_SELECTOR = bytes4(keccak256("resolveIncident(bytes32,bytes32,bytes32)"));
    bytes32 public constant POLICY_DOMAIN = keccak256("AIR_POLICY_V1");
    bytes32 public constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant RECOMMENDATION_TYPEHASH = keccak256(
        "AIRRecommendation(bytes32 policyHash,bytes32 fingerprint,uint8 mode,bytes32 rationaleHash,uint64 validUntil)"
    );
    bytes32 public constant EIP712_NAME_HASH = keccak256("AIR");
    bytes32 public constant EIP712_VERSION_HASH = keccak256("1");
    uint256 private constant SECP256K1_HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    IASCProofVerifier public immutable verifier;
    IAirChainInfo public immutable chainInfo;
    IAirContainmentTarget public immutable target;
    address public immutable recommenderSigner;
    Policy public policy;
    bytes32 public immutable policyHash;
    /// @notice Exactly-once tombstone keyed by the ASC proof transaction locator `(chainKey, sourceBlock, txIndex)`.
    mapping(bytes32 => bool) public consumedProofLocator;
    mapping(bytes32 => bool) public incidentEverSeen;
    mapping(bytes32 => ActiveIncident) public incidents;
    uint256 public limitedCount;
    uint256 public frozenCount;
    bool private entered;

    error Reentrant();
    error WrongChainKey();
    error SourceBlockOutOfWindow();
    error RecoveryBlockOutOfWindow();
    error ProofLocatorReplay();
    error IncidentReplay();
    error IncidentNotActive();
    error WrongSourceChain();
    error SourceExecutionFailed();
    error WrongSourceContract();
    error ContractCreationNotAllowed();
    error NonZeroSourceValue();
    error MalformedIncidentCall();
    error MalformedResolutionCall();
    error WrongDeployment();
    error WrongPolicy();
    error InvalidSeverity();
    error ResolutionNotCausal();
    error SourceAttestationUnavailable();
    error SourceEvidenceStale();
    error AuthenticatedStrengtheningRequired();

    event ProofAccepted(bytes32 indexed proofLocatorId, uint64 indexed sourceBlock, uint64 txIndex);
    event RecommendationBound(
        bytes32 indexed incidentId, bytes32 indexed fingerprint, Mode mode, bool fallbackUsed, bytes32 rationaleHash
    );
    event ContainmentApplied(bytes32 indexed incidentId, Mode incidentMode, Mode effectiveMode, bytes32 proofLocatorId);
    event RecommendationStrengthened(
        bytes32 indexed incidentId, bytes32 indexed fingerprint, Mode effectiveMode, bytes32 rationaleHash
    );
    event RecoveryApplied(bytes32 indexed incidentId, Mode effectiveMode, bytes32 proofLocatorId);

    constructor(
        IASCProofVerifier verifier_,
        IAirChainInfo chainInfo_,
        IAirContainmentTarget target_,
        address recommenderSigner_,
        Policy memory policy_
    ) {
        require(address(verifier_) != address(0), "verifier=0");
        require(address(chainInfo_) != address(0), "chain-info=0");
        require(address(target_) != address(0), "target=0");
        require(recommenderSigner_ != address(0), "recommender=0");
        require(policy_.sourceEmitter != address(0), "emitter=0");
        require(policy_.sourceChainKey != 0, "chain-key=0");
        require(policy_.sourceChainId != 0, "chain=0");
        require(policy_.maxSourceLagBlocks != 0, "max-lag=0");
        require(policy_.validFromSourceBlock <= policy_.validUntilSourceBlock, "bad-window");
        verifier = verifier_;
        chainInfo = chainInfo_;
        target = target_;
        recommenderSigner = recommenderSigner_;
        policy = policy_;
        policyHash = keccak256(
            abi.encode(
                POLICY_DOMAIN,
                block.chainid,
                address(this),
                address(verifier_),
                address(chainInfo_),
                address(target_),
                recommenderSigner_,
                policy_.deploymentId,
                policy_.sourceChainKey,
                policy_.sourceChainId,
                policy_.sourceEmitter,
                policy_.validFromSourceBlock,
                policy_.validUntilSourceBlock,
                policy_.recoveryGraceBlocks,
                policy_.maxSourceLagBlocks
            )
        );
    }

    modifier nonReentrant() {
        if (entered) revert Reentrant();
        entered = true;
        _;
        entered = false;
    }

    function effectiveMode() public view returns (Mode) {
        if (frozenCount != 0) return Mode.FROZEN;
        if (limitedCount != 0) return Mode.LIMITED;
        return Mode.NORMAL;
    }

    /// @dev aiRecommendation is a fixed 224-byte ABI tuple:
    /// abi.encode(fingerprint,uint8 mode,bytes32 rationaleHash,uint64 validUntil,bytes32 r,bytes32 s,uint8 v).
    /// The ASC proof relay remains permissionless. Only an EIP-712 recommendation signed by recommenderSigner may
    /// strengthen a WARNING above its objective LIMITED floor. Missing, malformed, forged, or expired AI bytes never
    /// block a valid proof and never let the relayer choose containment: the source-severity floor is applied instead.
    function processIncident(
        uint64 chainKey,
        uint64 sourceBlock,
        BlockProverTypes.InclusionProof calldata inclusionProof,
        BlockProverTypes.ContinuityProof calldata continuityProof,
        bytes calldata aiRecommendation
    ) external nonReentrant returns (bytes32 incidentId, Mode appliedMode, bool fallbackUsed) {
        if (chainKey != policy.sourceChainKey) revert WrongChainKey();
        if (sourceBlock < policy.validFromSourceBlock || sourceBlock > policy.validUntilSourceBlock) {
            revert SourceBlockOutOfWindow();
        }
        _validateFreshness(sourceBlock);
        // ASC derives txIndex from the inclusion proof; together with chainKey+block it is the exact physical proof locator.
        uint64 txIndex = verifier.calculateTxIndex(inclusionProof);
        bytes32 locatorId = proofLocatorId(chainKey, sourceBlock, txIndex);
        if (consumedProofLocator[locatorId]) revert ProofLocatorReplay();

        bytes memory encodedTx =
            verifier.verifyProofs(bytes32(uint256(chainKey)), sourceBlock, inclusionProof, continuityProof);
        ASCSdkV1TxBytesLib.ProofTx memory txFields = ASCSdkV1TxBytesLib.decodeMemory(encodedTx);
        EvmV1Decoder.ReceiptFields memory receipt = EvmV1Decoder.decodeReceiptFields(encodedTx);
        _validateSourceTransaction(txFields, receipt);

        bytes32 deploymentId;
        uint8 severity;
        bytes32 sourcePolicyHash;
        (incidentId, deploymentId, severity, sourcePolicyHash) = _decodeIncident(txFields.data);
        if (deploymentId != policy.deploymentId) revert WrongDeployment();
        if (sourcePolicyHash != policyHash) revert WrongPolicy();
        if (severity == 0 || severity > 2) revert InvalidSeverity();
        if (incidentEverSeen[incidentId]) revert IncidentReplay();

        bytes32 fingerprint =
            keccak256(abi.encode(POLICY_DOMAIN, locatorId, incidentId, deploymentId, severity, sourcePolicyHash));
        bytes32 rationaleHash;
        (appliedMode, fallbackUsed, rationaleHash) = _boundedRecommendation(aiRecommendation, fingerprint, severity);

        consumedProofLocator[locatorId] = true;
        incidentEverSeen[incidentId] = true;
        incidents[incidentId] = ActiveIncident(true, appliedMode, sourceBlock, txIndex, fingerprint);
        _increment(appliedMode);
        Mode nextEffective = effectiveMode();
        // Target failure reverts all marks, so a valid proof cannot be burned by failed containment.
        target.applyMode(uint8(nextEffective));
        emit ProofAccepted(locatorId, sourceBlock, txIndex);
        emit RecommendationBound(incidentId, fingerprint, appliedMode, fallbackUsed, rationaleHash);
        emit ContainmentApplied(incidentId, appliedMode, nextEffective, locatorId);
    }

    /// @notice Authenticated post-proof escalation for an already-active WARNING.
    /// @dev This path is intentionally proof-independent: a permissionless relay that lands the verified WARNING first
    /// cannot consume or veto a later authentic AI strengthening. Only LIMITED -> FROZEN is allowed; recovery remains
    /// source-proof-only through processResolution.
    function strengthenIncident(bytes32 incidentId, bytes calldata aiRecommendation)
        external
        nonReentrant
        returns (Mode nextEffective)
    {
        ActiveIncident memory active = incidents[incidentId];
        if (!active.active) revert IncidentNotActive();
        if (active.mode != Mode.LIMITED) revert AuthenticatedStrengtheningRequired();

        (Mode proposed, bool fallbackUsed, bytes32 rationaleHash) =
            _boundedRecommendation(aiRecommendation, active.fingerprint, 1);
        if (fallbackUsed || proposed != Mode.FROZEN) revert AuthenticatedStrengtheningRequired();

        _decrement(Mode.LIMITED);
        _increment(Mode.FROZEN);
        incidents[incidentId].mode = Mode.FROZEN;
        nextEffective = effectiveMode();
        // Target failure reverts the mode/count update, so the same authorization remains retryable.
        target.applyMode(uint8(nextEffective));
        emit RecommendationBound(incidentId, active.fingerprint, Mode.FROZEN, false, rationaleHash);
        emit RecommendationStrengthened(incidentId, active.fingerprint, nextEffective, rationaleHash);
    }

    function processResolution(
        uint64 chainKey,
        uint64 sourceBlock,
        BlockProverTypes.InclusionProof calldata inclusionProof,
        BlockProverTypes.ContinuityProof calldata continuityProof
    ) external nonReentrant returns (bytes32 incidentId, Mode nextEffective) {
        if (chainKey != policy.sourceChainKey) revert WrongChainKey();
        // New incidents stop being admitted at validUntilSourceBlock, but an incident that is already active must
        // remain recoverable later. Recovery still requires a fresh native attestation, an authenticated source
        // transaction bound to this deployment/policy, and a strictly causal source position below.
        if (sourceBlock < policy.validFromSourceBlock) revert RecoveryBlockOutOfWindow();
        _validateFreshness(sourceBlock);
        // ASC derives txIndex from the inclusion proof; together with chainKey+block it is the exact physical proof locator.
        uint64 txIndex = verifier.calculateTxIndex(inclusionProof);
        bytes32 locatorId = proofLocatorId(chainKey, sourceBlock, txIndex);
        if (consumedProofLocator[locatorId]) revert ProofLocatorReplay();

        bytes memory encodedTx =
            verifier.verifyProofs(bytes32(uint256(chainKey)), sourceBlock, inclusionProof, continuityProof);
        ASCSdkV1TxBytesLib.ProofTx memory txFields = ASCSdkV1TxBytesLib.decodeMemory(encodedTx);
        EvmV1Decoder.ReceiptFields memory receipt = EvmV1Decoder.decodeReceiptFields(encodedTx);
        _validateSourceTransaction(txFields, receipt);
        bytes32 deploymentId;
        bytes32 sourcePolicyHash;
        (incidentId, deploymentId, sourcePolicyHash) = _decodeResolution(txFields.data);
        if (deploymentId != policy.deploymentId) revert WrongDeployment();
        if (sourcePolicyHash != policyHash) revert WrongPolicy();
        ActiveIncident memory active = incidents[incidentId];
        if (!active.active) revert IncidentNotActive();
        if (sourceBlock < active.sourceBlock || (sourceBlock == active.sourceBlock && txIndex <= active.txIndex)) {
            revert ResolutionNotCausal();
        }

        consumedProofLocator[locatorId] = true;
        delete incidents[incidentId];
        _decrement(active.mode);
        nextEffective = effectiveMode();
        target.applyMode(uint8(nextEffective));
        emit ProofAccepted(locatorId, sourceBlock, txIndex);
        emit RecoveryApplied(incidentId, nextEffective, locatorId);
    }

    /// @notice Canonical exactly-once key for one ASC-proved source transaction position.
    function proofLocatorId(uint64 chainKey, uint64 sourceBlock, uint64 txIndex) public pure returns (bytes32) {
        return keccak256(abi.encode(chainKey, sourceBlock, txIndex));
    }

    function recommendationFingerprint(bytes32 locatorId, bytes32 incidentId, uint8 severity)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(POLICY_DOMAIN, locatorId, incidentId, policy.deploymentId, severity, policyHash));
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(EIP712_DOMAIN_TYPEHASH, EIP712_NAME_HASH, EIP712_VERSION_HASH, block.chainid, address(this))
        );
    }

    function recommendationDigest(bytes32 fingerprint, Mode mode, bytes32 rationaleHash, uint64 validUntil)
        public
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(RECOMMENDATION_TYPEHASH, policyHash, fingerprint, uint8(mode), rationaleHash, validUntil)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function _validateFreshness(uint64 sourceBlock) internal view {
        (uint64 latestHeight,,, bool exists) = chainInfo.get_latest_attestation_height_and_hash(policy.sourceChainKey);
        if (!exists || latestHeight < sourceBlock) revert SourceAttestationUnavailable();
        if (uint256(latestHeight) - uint256(sourceBlock) > uint256(policy.maxSourceLagBlocks)) {
            revert SourceEvidenceStale();
        }
    }

    function _validateSourceTransaction(
        ASCSdkV1TxBytesLib.ProofTx memory txFields,
        EvmV1Decoder.ReceiptFields memory receipt
    ) internal view {
        if (txFields.chainId != policy.sourceChainId) {
            revert WrongSourceChain();
        }
        if (receipt.receiptStatus != 1) revert SourceExecutionFailed();
        if (txFields.toIsNull) revert ContractCreationNotAllowed();
        if (txFields.to != policy.sourceEmitter) revert WrongSourceContract();
        if (txFields.value != 0) revert NonZeroSourceValue();
    }

    function _boundedRecommendation(bytes calldata raw, bytes32 fingerprint, uint8 severity)
        internal
        view
        returns (Mode selected, bool fallbackUsed, bytes32 rationaleHash)
    {
        Mode floorMode = severity == 1 ? Mode.LIMITED : Mode.FROZEN;
        if (raw.length != 224) return (floorMode, true, bytes32(0));

        bytes32 boundFingerprint;
        uint256 proposedWord;
        uint256 validUntilWord;
        bytes32 r;
        bytes32 s;
        uint256 vWord;
        assembly {
            boundFingerprint := calldataload(raw.offset)
            proposedWord := calldataload(add(raw.offset, 32))
            rationaleHash := calldataload(add(raw.offset, 64))
            validUntilWord := calldataload(add(raw.offset, 96))
            r := calldataload(add(raw.offset, 128))
            s := calldataload(add(raw.offset, 160))
            vWord := calldataload(add(raw.offset, 192))
        }

        if (
            boundFingerprint != fingerprint || proposedWord > uint256(uint8(Mode.FROZEN))
                || validUntilWord > type(uint64).max || vWord > type(uint8).max || rationaleHash == bytes32(0)
                || r == bytes32(0) || s == bytes32(0)
        ) {
            return (floorMode, true, bytes32(0));
        }

        Mode proposed = Mode(uint8(proposedWord));
        if (uint8(proposed) < uint8(floorMode)) return (floorMode, true, bytes32(0));

        uint64 validUntil = uint64(validUntilWord);
        uint8 v = uint8(vWord);
        if (validUntil < block.timestamp || (v != 27 && v != 28) || uint256(s) > SECP256K1_HALF_N) {
            return (floorMode, true, bytes32(0));
        }

        bytes32 digest = recommendationDigest(fingerprint, proposed, rationaleHash, validUntil);
        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0) || recovered != recommenderSigner) {
            return (floorMode, true, bytes32(0));
        }
        return (proposed, false, rationaleHash);
    }

    function _decodeIncident(bytes memory data)
        internal
        pure
        returns (bytes32 incidentId, bytes32 deploymentId, uint8 severity, bytes32 sourcePolicyHash)
    {
        if (data.length != 132 || _selector(data) != RAISE_SELECTOR) revert MalformedIncidentCall();
        uint256 severityWord = _word(data, 68);
        if (severityWord > type(uint8).max) revert MalformedIncidentCall();
        incidentId = bytes32(_word(data, 4));
        deploymentId = bytes32(_word(data, 36));
        severity = uint8(severityWord);
        sourcePolicyHash = bytes32(_word(data, 100));
    }

    function _decodeResolution(bytes memory data)
        internal
        pure
        returns (bytes32 incidentId, bytes32 deploymentId, bytes32 sourcePolicyHash)
    {
        if (data.length != 100 || _selector(data) != RESOLVE_SELECTOR) revert MalformedResolutionCall();
        incidentId = bytes32(_word(data, 4));
        deploymentId = bytes32(_word(data, 36));
        sourcePolicyHash = bytes32(_word(data, 68));
    }

    function _increment(Mode mode_) internal {
        if (mode_ == Mode.FROZEN) ++frozenCount;
        else if (mode_ == Mode.LIMITED) ++limitedCount;
    }

    function _decrement(Mode mode_) internal {
        if (mode_ == Mode.FROZEN) --frozenCount;
        else if (mode_ == Mode.LIMITED) --limitedCount;
    }

    function _selector(bytes memory data) private pure returns (bytes4 result) {
        assembly { result := mload(add(data, 32)) }
    }

    function _word(bytes memory data, uint256 offset) private pure returns (uint256 result) {
        assembly { result := mload(add(add(data, 32), offset)) }
    }
}

/// @notice Production AIR: the caller cannot substitute a verifier. ASCProofVerifier delegates to Creditcoin native 0xFD2.
/// The recommender signer is explicit and immutable; it authenticates discretionary AI strengthening but never proof truth.
contract AttestedIncidentResponder is AirResponderCore {
    constructor(IAirContainmentTarget target_, address recommenderSigner_, Policy memory policy_)
        AirResponderCore(
            IASCProofVerifier(address(new ASCProofVerifier())),
            IAirChainInfo(address(uint160(0xFD3))),
            target_,
            recommenderSigner_,
            policy_
        )
    {}
}
