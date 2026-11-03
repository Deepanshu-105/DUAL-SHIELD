const { expect } = require("chai");
const { ethers } = require("hardhat");

// v3: protected IPs, report limit, scaling quorum, overrule, multi-signature governance.
// None of these change the default behaviour (see CityShield.test.js, which still passes unchanged).
describe("CityShield v3 hardening", function () {
  let shield, owner, g2, g3, n1, n2, n3, n4, stranger;
  const IP = "203.0.113.50", JA3 = ethers.id("fp");
  const STAKE = ethers.parseEther("1");

  beforeEach(async function () {
    [owner, g2, g3, n1, n2, n3, n4, stranger] = await ethers.getSigners();
    shield = await (await ethers.getContractFactory("CityShield")).deploy();
    for (const n of [n1, n2, n3, n4]) {
      await shield.addNode(n.address);
      await shield.connect(n).registerNode({ value: STAKE });
    }
  });

  it("defaults: threshold 1, quorum off, no limits, so v2 behaviour is unchanged", async function () {
    expect(await shield.govThreshold()).to.equal(1n);
    expect(await shield.quorumPct()).to.equal(0n);
    expect(await shield.required()).to.equal(2n);
    await shield.connect(n1).reportThreat(IP, JA3);
    await shield.connect(n2).reportThreat(IP, JA3);
    expect((await shield.getTally(IP))[2]).to.equal(true);
  });

  it("protected IP cannot be reported (city infrastructure stays reachable)", async function () {
    await shield.propose(2, "172.30.0.1", ethers.ZeroAddress, 0);          // P_PROTECT
    expect(await shield.isProtected("172.30.0.1")).to.equal(true);
    await expect(shield.connect(n1).reportThreat("172.30.0.1", JA3)).to.be.revertedWith("protected IP");
    await shield.propose(3, "172.30.0.1", ethers.ZeroAddress, 0);          // P_UNPROTECT
    await shield.connect(n1).reportThreat("172.30.0.1", JA3);
  });

  it("per-node report limit stops a hacked node from spamming", async function () {
    await shield.propose(10, "", ethers.ZeroAddress, 2);                   // P_SET_RATE_LIMIT = 2 per hour
    await shield.connect(n1).reportThreat("198.51.100.1", JA3);
    await shield.connect(n1).reportThreat("198.51.100.2", JA3);
    await expect(shield.connect(n1).reportThreat("198.51.100.3", JA3)).to.be.revertedWith("rate limit");
    await shield.connect(n2).reportThreat("198.51.100.3", JA3);            // other nodes unaffected
  });

  it("quorum scales with the network: 67% of 4 nodes needs 3 reports", async function () {
    await shield.propose(9, "", ethers.ZeroAddress, 67);                   // P_SET_QUORUM
    expect(await shield.required()).to.equal(3n);
    await shield.connect(n1).reportThreat(IP, JA3);
    await shield.connect(n2).reportThreat(IP, JA3);
    expect((await shield.getTally(IP))[2]).to.equal(false);                // 2 colluding nodes are no longer enough
    await shield.connect(n3).reportThreat(IP, JA3);
    expect((await shield.getTally(IP))[2]).to.equal(true);
  });

  it("overrule cancels a confirmed block and slashes the colluders", async function () {
    await shield.connect(n1).reportThreat(IP, JA3);
    await shield.connect(n2).reportThreat(IP, JA3);
    expect((await shield.blockInfo(IP))[0]).to.equal(true);
    await expect(shield.propose(1, IP, ethers.ZeroAddress, 0)).to.emit(shield, "ThreatOverruled").withArgs(IP, 2n);
    expect((await shield.blockInfo(IP))[0]).to.equal(false);
    expect(await shield.stakes(n1.address)).to.equal(0n);
    expect(await shield.stakes(n3.address)).to.equal(STAKE);               // honest node untouched
    await expect(shield.propose(1, IP, ethers.ZeroAddress, 0)).to.be.revertedWith("nothing to overrule");
  });

  describe("multi-signature (2 of 3 governors)", function () {
    beforeEach(async function () {
      await shield.propose(6, "", g2.address, 0);                          // add governors
      await shield.propose(6, "", g3.address, 0);
      await shield.propose(8, "", ethers.ZeroAddress, 2);                  // threshold 2 (still executes: 1 >= 1)
    });

    it("one governor alone can no longer act", async function () {
      expect(await shield.govThreshold()).to.equal(2n);
      await shield.connect(n1).reportThreat(IP, JA3);
      await shield.connect(n2).reportThreat(IP, JA3);
      await shield.propose(1, IP, ethers.ZeroAddress, 0);                  // owner signs: 1 of 2, not executed
      expect((await shield.blockInfo(IP))[0]).to.equal(true);
      const id = (await shield.proposalCount()) - 1n;
      await expect(shield.approve(id)).to.be.revertedWith("already signed");
      await expect(shield.connect(g2).approve(id)).to.emit(shield, "ThreatOverruled");   // 2 of 2 executes
      expect((await shield.blockInfo(IP))[0]).to.equal(false);
    });

    it("direct owner addNode/revokeNode are closed once threshold > 1", async function () {
      await expect(shield.addNode(stranger.address)).to.be.revertedWith("owner only");
      await shield.propose(4, "", stranger.address, 0);
      expect(await shield.approved(stranger.address)).to.equal(false);
      await shield.connect(g3).approve((await shield.proposalCount()) - 1n);
      expect(await shield.approved(stranger.address)).to.equal(true);
    });

    it("non-governors cannot propose or approve", async function () {
      await expect(shield.connect(stranger).propose(2, "1.2.3.4", ethers.ZeroAddress, 0)).to.be.revertedWith("governor only");
      await expect(shield.connect(stranger).approve(0)).to.be.revertedWith("governor only");
    });

    it("a proposal executes only once", async function () {
      const id = (await shield.proposalCount()) - 1n;
      await expect(shield.connect(g2).approve(id)).to.be.revertedWith("already executed");
    });
  });
});
