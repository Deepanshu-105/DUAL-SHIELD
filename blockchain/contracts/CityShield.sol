// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CityShield {
    // How many distinct addresses must report an IP before it's confirmed
    uint256 public constant K_THRESHOLD = 2;

    // ip (as a string) => set of addresses that reported it
    mapping(string => mapping(address => bool)) private hasReported;
    mapping(string => uint256) public reportCount;
    mapping(string => bool) public isConfirmed;

    event ThreatReported(string ip, address reporter, uint256 count);
    event ThreatConsensusReached(string ip, uint256 finalCount);

    function reportThreat(string calldata ip, string calldata ja3Hash) external {
        require(!hasReported[ip][msg.sender], "Already reported by this address");

        hasReported[ip][msg.sender] = true;
        reportCount[ip] += 1;

        emit ThreatReported(ip, msg.sender, reportCount[ip]);

        if (!isConfirmed[ip] && reportCount[ip] >= K_THRESHOLD) {
            isConfirmed[ip] = true;
            emit ThreatConsensusReached(ip, reportCount[ip]);
        }
    }
}
