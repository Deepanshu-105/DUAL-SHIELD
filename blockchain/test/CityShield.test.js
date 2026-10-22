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
});

describe("CityShield anchorCleanState", function () {
  it("stores and returns a merkle root + attack timestamp for a staked reporter", async function () {
    const [addr1] = await ethers.getSigners();
    const CityShield = await ethers.getContractFactory("CityShield");
    const contract = await CityShield.deploy();

    await contract.connect(addr1).registerNode({ value: ethers.parseEther("1") });

    const fakeRoot = ethers.keccak256(ethers.toUtf8Bytes("test-merkle-root"));
    const tAttack = Math.floor(Date.now() / 1000);

    await contract.connect(addr1).anchorCleanState("172.30.0.12", fakeRoot, tAttack);

    const [root, t, anchored] = await contract.getRecovery("172.30.0.12");
    expect(root).to.equal(fakeRoot);
    expect(t).to.equal(tAttack);
    expect(anchored).to.equal(true);
  });

  it("rejects an anchor from an address with no stake", async function () {
    const [, addr2] = await ethers.getSigners();
    const CityShield = await ethers.getContractFactory("CityShield");
    const contract = await CityShield.deploy();

    const fakeRoot = ethers.keccak256(ethers.toUtf8Bytes("x"));
    await expect(
      contract.connect(addr2).anchorCleanState("1.2.3.4", fakeRoot, 0)
    ).to.be.revertedWith("not staked");
  });
});
