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
    }

    mapping(address => uint) public stakes;
    uint public nodeCount;
    uint public slashedPool;  // slashed funds stay in the contract (prototype)

    mapping(bytes32 => Threat) private threats;
    mapping(bytes32 => mapping(address => bool)) private voted;

    event ThreatReported(address indexed node, string ip, uint count);
    event ThreatConsensusReached(string ip, bytes32 ja3, uint count);
    event NodeSlashed(address indexed node, string ip, uint amount);

    function registerNode() external payable {
        require(msg.value == STAKE, "send exactly STAKE");
        require(stakes[msg.sender] == 0, "already registered");
        stakes[msg.sender] = msg.value;
        nodeCount++;
    }

    function reportThreat(string calldata ip, bytes32 ja3) external {
        require(stakes[msg.sender] > 0, "not staked");
        bytes32 id = keccak256(bytes(ip));
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

        if (!t.confirmed && t.count >= K) {
            t.confirmed = true;
            emit ThreatConsensusReached(ip, t.ja3, t.count);  // fires once
        }
    }

    // M4 uses this for the tally. Unknown IP returns (0, K, false).
    function getTally(string calldata ip)
        external view returns (uint count, uint k, bool confirmed)
    {
        Threat storage t = threats[keccak256(bytes(ip))];
        return (t.count, K, t.confirmed);
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
