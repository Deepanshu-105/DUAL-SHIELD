const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("CityShield", function () {
  let shield, a, b, c;
  const IP = "203.0.113.50";
  const GOOD_IP = "198.51.100.7";
  const JA3 = ethers.id("ja3-test");
  const STAKE = ethers.parseEther("1");

  beforeEach(async function () {
    [, a, b, c] = await ethers.getSigners();
    shield = await (await ethers.getContractFactory("CityShield")).deploy();
    await shield.waitForDeployment();
    for (const s of [a, b, c]) {
      await shield.addNode(s.address);
      await shield.connect(s).registerNode({ value: STAKE });
    }
  });

  it("confirms a threat when K=2 nodes report", async function () {
    await shield.connect(a).reportThreat(IP, JA3);
    let [count, k, confirmed] = await shield.getTally(IP);
    expect(count).to.equal(1n);
    expect(k).to.equal(2n);
    expect(confirmed).to.equal(false);

    await expect(shield.connect(b).reportThreat(IP, JA3))
      .to.emit(shield, "ThreatConsensusReached")
      .withArgs(IP, JA3, 2n);

    [count, , confirmed] = await shield.getTally(IP);
    expect(count).to.equal(2n);
    expect(confirmed).to.equal(true);

    await expect(shield.connect(c).reportThreat(IP, JA3))
      .to.not.emit(shield, "ThreatConsensusReached");
  });

  it("rejects a lone false report and slashes the reporter", async function () {
    await expect(shield.connect(c).reportThreat(GOOD_IP, JA3))
      .to.not.emit(shield, "ThreatConsensusReached");

    await expect(shield.slashExpired(GOOD_IP)).to.be.revertedWith("window still open");

    await time.increase(61);

    await expect(shield.slashExpired(GOOD_IP))
      .to.emit(shield, "NodeSlashed")
      .withArgs(c.address, GOOD_IP, STAKE);

    expect(await shield.stakes(c.address)).to.equal(0n);
    expect(await shield.stakes(a.address)).to.equal(STAKE);
    expect(await shield.stakes(b.address)).to.equal(STAKE);

    const [, , confirmed] = await shield.getTally(GOOD_IP);
    expect(confirmed).to.equal(false);
  });

  it("reverts a double report from the same node", async function () {
    await shield.connect(a).reportThreat(IP, JA3);
    await expect(shield.connect(a).reportThreat(IP, JA3))
      .to.be.revertedWith("already reported");
  });

  describe("v2: owner-approved registration", function () {
    it("rejects registration from an address the owner has not approved", async function () {
      const [, , , , rogue] = await ethers.getSigners();
      await expect(shield.connect(rogue).registerNode({ value: STAKE }))
        .to.be.revertedWith("not approved by owner");
    });

    it("only the owner can approve or revoke nodes", async function () {
      const [, , , , rogue] = await ethers.getSigners();
      await expect(shield.connect(rogue).addNode(rogue.address)).to.be.revertedWith("owner only");
      await expect(shield.connect(a).revokeNode(b.address)).to.be.revertedWith("owner only");
    });

    it("a revoked node loses its stake and can no longer vote", async function () {
      await expect(shield.revokeNode(a.address)).to.emit(shield, "NodeRevoked").withArgs(a.address, STAKE);
      expect(await shield.stakes(a.address)).to.equal(0n);
      await expect(shield.connect(a).reportThreat(IP, JA3)).to.be.revertedWith("not staked");
      await expect(shield.connect(a).registerNode({ value: STAKE })).to.be.revertedWith("not approved by owner");
    });

    it("a fake report from an unapproved address cannot reach consensus", async function () {
      const [, , , , rogue] = await ethers.getSigners();
      await shield.connect(a).reportThreat(GOOD_IP, JA3);
      await expect(shield.connect(rogue).reportThreat(GOOD_IP, JA3)).to.be.revertedWith("not staked");
      const [count, , confirmed] = await shield.getTally(GOOD_IP);
      expect(count).to.equal(1n);
      expect(confirmed).to.equal(false);
    });
  });
});
