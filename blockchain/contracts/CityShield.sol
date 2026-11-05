// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CityShield {
    uint public constant K = 2;              // reports needed for consensus
    uint public constant STAKE = 1 ether;    // stake per node
    uint public constant WINDOW = 60;        // seconds to get a 2nd report

    struct Threat {
        uint count;
        uint firstAt;
        bool confirmed;
        bool settled;       // slashing already done
        bytes32 ja3;
        address[] reporters;
        uint confirmedAt;   // v3: when consensus was reached (used for block expiry)
        bool overruled;     // v3: cancelled by governance (collusion / false positive)
    }

    // v2: only addresses approved by the owner (the deployer) may register as nodes.
    address public owner;
    mapping(address => bool) public approved;
    event NodeApproved(address indexed node);
    event NodeRevoked(address indexed node, uint forfeited);

    constructor() {
        owner = msg.sender;
        approved[msg.sender] = true;   // the owner can anchor clean states from its own account
        governor[msg.sender] = true;   // v3: the deployer is the first governor ...
        govCount = 1;
        govThreshold = 1;              // ... and with threshold 1 everything behaves exactly as before
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "owner only");
        _;
    }

    // Single-owner mode (threshold 1): the owner may still approve/revoke nodes directly, as in v2.
    // Once the governors raise the threshold above 1, the same actions need M-of-N governor approval.
    modifier ownerWhileSingle() {
        require(msg.sender == owner && govThreshold == 1, "owner only");
        _;
    }

    function addNode(address node) external ownerWhileSingle {
        _addNode(node);
    }

    // Removes the right to vote at once; any stake is forfeited into slashedPool.
    function revokeNode(address node) external ownerWhileSingle {
        _revokeNode(node);
    }

    function _addNode(address node) internal {
        approved[node] = true;
        emit NodeApproved(node);
    }

    function _revokeNode(address node) internal {
        approved[node] = false;
        uint amt = stakes[node];
        if (amt > 0) {
            stakes[node] = 0;
            slashedPool += amt;
            nodeCount--;
        }
        emit NodeRevoked(node, amt);
    }

    mapping(address => uint) public stakes;
    uint public nodeCount;
    uint public slashedPool;  // slashed funds stay in the contract (prototype)

    mapping(bytes32 => Threat) private threats;
    mapping(bytes32 => mapping(address => bool)) private voted;

    event ThreatReported(address indexed node, string ip, uint count);
    event ThreatConsensusReached(string ip, bytes32 ja3, uint count);
    event NodeSlashed(address indexed node, string ip, uint amount);

    // ---- v3: hardening (all off or neutral by default, so existing behaviour is unchanged) ----
    uint public quorumPct;                    // 0 = off (use K). Else required = max(K, ceil(nodeCount * pct / 100))
    uint public maxReportsPerHour;            // 0 = unlimited. Else per-node cap on reports per hour
    mapping(bytes32 => bool) private protectedIps;                 // city infrastructure that may never be blocked
    mapping(address => mapping(uint => uint)) private reportsInHour;
    event ThreatOverruled(string ip, uint slashedNodes);
    event IpProtected(string ip, bool on);
    event ParamChanged(string name, uint value);

    // Number of reports needed. Default K (=2). With quorumPct set (say 67) it grows with the network.
    function required() public view returns (uint) {
        if (quorumPct == 0) return K;
        uint r = (nodeCount * quorumPct + 99) / 100;
        return r < K ? K : r;
    }

    function isProtected(string calldata ip) external view returns (bool) {
        return protectedIps[keccak256(bytes(ip))];
    }

    // True while consensus stands (not overruled). Clients apply their own block expiry from confirmedAt.
    function blockInfo(string calldata ip) external view returns (bool active, uint confirmedAt) {
        Threat storage t = threats[keccak256(bytes(ip))];
        return (t.confirmed && !t.overruled, t.confirmedAt);
    }

    // ---- v3: multi-signature governance ----
    uint8 public constant P_OVERRULE = 1;
    uint8 public constant P_PROTECT = 2;
    uint8 public constant P_UNPROTECT = 3;
    uint8 public constant P_ADD_NODE = 4;
    uint8 public constant P_REVOKE_NODE = 5;
    uint8 public constant P_ADD_GOVERNOR = 6;
    uint8 public constant P_REMOVE_GOVERNOR = 7;
    uint8 public constant P_SET_THRESHOLD = 8;
    uint8 public constant P_SET_QUORUM = 9;
    uint8 public constant P_SET_RATE_LIMIT = 10;

    struct Proposal {
        uint8 kind;
        string ip;        // for OVERRULE / PROTECT / UNPROTECT
        address node;     // for ADD_NODE / REVOKE_NODE / ADD_GOVERNOR / REMOVE_GOVERNOR
        uint value;       // for SET_THRESHOLD / SET_QUORUM / SET_RATE_LIMIT
        uint approvals;
        bool executed;
        mapping(address => bool) signed;
    }
    Proposal[] private proposals;
    mapping(address => bool) public governor;
    uint public govCount;
    uint public govThreshold;     // M of the N governors
    event ProposalCreated(uint indexed id, uint8 kind, address indexed by);
    event ProposalApproved(uint indexed id, address indexed by, uint approvals);
    event ProposalExecuted(uint indexed id, uint8 kind);

    modifier onlyGovernor() {
        require(governor[msg.sender], "governor only");
        _;
    }

    function proposalCount() external view returns (uint) {
        return proposals.length;
    }

    function getProposal(uint id) external view returns (uint8 kind, string memory ip, address node, uint value, uint approvals, bool executed) {
        Proposal storage p = proposals[id];
        return (p.kind, p.ip, p.node, p.value, p.approvals, p.executed);
    }

    function propose(uint8 kind, string calldata ip, address node, uint value) external onlyGovernor returns (uint id) {
        require(kind >= 1 && kind <= 10, "bad kind");
        id = proposals.length;
        Proposal storage p = proposals.push();
        p.kind = kind;
        p.ip = ip;
        p.node = node;
        p.value = value;
        emit ProposalCreated(id, kind, msg.sender);
        _sign(id, p);
    }

    function approve(uint id) external onlyGovernor {
        require(id < proposals.length, "no such proposal");
        _sign(id, proposals[id]);
    }

    function _sign(uint id, Proposal storage p) internal {
        require(!p.executed, "already executed");
        require(!p.signed[msg.sender], "already signed");
        p.signed[msg.sender] = true;
        p.approvals++;
        emit ProposalApproved(id, msg.sender, p.approvals);
        if (p.approvals >= govThreshold) {
            p.executed = true;
            _execute(p);
            emit ProposalExecuted(id, p.kind);
        }
    }

    function _execute(Proposal storage p) internal {
        uint8 k = p.kind;
        if (k == P_OVERRULE) {
            _overrule(p.ip);
        } else if (k == P_PROTECT || k == P_UNPROTECT) {
            protectedIps[keccak256(bytes(p.ip))] = (k == P_PROTECT);
            emit IpProtected(p.ip, k == P_PROTECT);
        } else if (k == P_ADD_NODE) {
            _addNode(p.node);
        } else if (k == P_REVOKE_NODE) {
            _revokeNode(p.node);
        } else if (k == P_ADD_GOVERNOR) {
            require(!governor[p.node], "already governor");
            governor[p.node] = true;
            govCount++;
        } else if (k == P_REMOVE_GOVERNOR) {
            require(governor[p.node] && govCount - 1 >= govThreshold, "cannot remove");
            governor[p.node] = false;
            govCount--;
        } else if (k == P_SET_THRESHOLD) {
            require(p.value >= 1 && p.value <= govCount, "bad threshold");
            govThreshold = p.value;
            emit ParamChanged("govThreshold", p.value);
        } else if (k == P_SET_QUORUM) {
            require(p.value <= 100, "percent");
            quorumPct = p.value;
            emit ParamChanged("quorumPct", p.value);
        } else if (k == P_SET_RATE_LIMIT) {
            maxReportsPerHour = p.value;
            emit ParamChanged("maxReportsPerHour", p.value);
        }
    }

    // A confirmed block that governance judges to be false (collusion, compromised nodes): cancel it and
    // slash everyone who voted for it. Clients remove the block when they see ThreatOverruled.
    function _overrule(string memory ip) internal {
        Threat storage t = threats[keccak256(bytes(ip))];
        require(t.confirmed && !t.overruled, "nothing to overrule");
        t.overruled = true;
        t.settled = true;
        uint n;
        for (uint i = 0; i < t.reporters.length; i++) {
            address r = t.reporters[i];
            uint amt = stakes[r];
            if (amt > 0) {
                stakes[r] = 0;
                slashedPool += amt;
                nodeCount--;
                n++;
                emit NodeSlashed(r, ip, amt);
            }
        }
        emit ThreatOverruled(ip, n);
    }

    function registerNode() external payable {
        require(approved[msg.sender], "not approved by owner");
        require(msg.value == STAKE, "send exactly STAKE");
        require(stakes[msg.sender] == 0, "already registered");
        stakes[msg.sender] = msg.value;
        nodeCount++;
    }

    function reportThreat(string calldata ip, bytes32 ja3) external {
        require(stakes[msg.sender] > 0, "not staked");
        bytes32 id = keccak256(bytes(ip));
        require(!protectedIps[id], "protected IP");
        if (maxReportsPerHour > 0) {
            require(++reportsInHour[msg.sender][block.timestamp / 3600] <= maxReportsPerHour, "rate limit");
        }
        Threat storage t = threats[id];
        require(!t.settled, "threat settled");
        require(!voted[id][msg.sender], "already reported");

        if (t.count == 0) {
            t.firstAt = block.timestamp;
            t.ja3 = ja3;
        } else if (!t.confirmed) {
            require(block.timestamp <= t.firstAt + WINDOW, "window expired");
        }

        voted[id][msg.sender] = true;
        t.reporters.push(msg.sender);
        t.count++;
        emit ThreatReported(msg.sender, ip, t.count);

        if (!t.confirmed && t.count >= required()) {
            t.confirmed = true;
            t.confirmedAt = block.timestamp;
            emit ThreatConsensusReached(ip, t.ja3, t.count);  // fires once
        }
    }

    // M4 uses this for the tally. Unknown IP returns (0, K, false).
    function getTally(string calldata ip)
        external view returns (uint count, uint k, bool confirmed)
    {
        Threat storage t = threats[keccak256(bytes(ip))];
        return (t.count, required(), t.confirmed);
    }

    // A threat that never got a 2nd report in time counts as a false report.
    function slashExpired(string calldata ip) external {
        bytes32 id = keccak256(bytes(ip));
        Threat storage t = threats[id];
        require(t.count > 0, "no such threat");
        require(!t.confirmed, "already confirmed");
        require(!t.settled, "already settled");
        require(block.timestamp > t.firstAt + WINDOW, "window still open");

        t.settled = true;
        for (uint i = 0; i < t.reporters.length; i++) {
            address r = t.reporters[i];
            uint amt = stakes[r];
            if (amt > 0) {
                stakes[r] = 0;
                slashedPool += amt;
                emit NodeSlashed(r, ip, amt);
            }
        }
    }

    // ---- Clean-state anchor (M3), keyed by attacker IP ----
    struct CleanState {
        bytes32 merkleRoot;
        uint256 tAttack;
        bool anchored;
    }
    mapping(bytes32 => CleanState) private cleanStates;

    event CleanStateAnchored(string ip, bytes32 merkleRoot, uint256 tAttack);

    // M3 calls this once rollback.py has restored and verified the clean state.
    // merkleRoot comes from snapshot.py's output; tAttack is the detection timestamp.
    function anchorCleanState(string calldata ip, bytes32 merkleRoot, uint256 tAttack) external {
        bytes32 id = keccak256(bytes(ip));
        require(stakes[msg.sender] > 0, "not staked");
        cleanStates[id] = CleanState({merkleRoot: merkleRoot, tAttack: tAttack, anchored: true});
        emit CleanStateAnchored(ip, merkleRoot, tAttack);
    }

    // M4 dashboard reads this to show the anchored root and attack time for an IP.
    function getCleanState(string calldata ip) external view returns (bytes32 merkleRoot, uint256 tAttack, bool anchored) {
        CleanState storage r = cleanStates[keccak256(bytes(ip))];
        return (r.merkleRoot, r.tAttack, r.anchored);
    }
}
