const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Recovery anchor", function () {
  async function setup() {
    const [, a, b] = await ethers.getSigners();
    const c = await (await ethers.getContractFactory("CityShield")).deploy();
    await c.waitForDeployment();
    await c.connect(a).registerNode({ value: ethers.parseEther("1") });
    return { c, a, b };
  }
  const hash = ethers.keccak256(ethers.toUtf8Bytes("clean-state"));
  const tAttack = 1792600000123456n;

  it("stores the clean hash and Tattack from a staked node", async function () {
    const { c, a } = await setup();
    await (await c.connect(a).anchorRecovery(hash, tAttack)).wait();
    expect(await c.recoveryCount()).to.equal(1n);
    const r = await c.getRecovery(0);
    expect(r[0]).to.equal(hash);
    expect(r[1]).to.equal(tAttack);
    expect(r[2]).to.equal(a.address);
  });

  it("rejects an unstaked caller", async function () {
    const { c, b } = await setup();
    let ok = false;
    try { await c.connect(b).anchorRecovery(hash, tAttack); }
    catch (e) { ok = /not staked/.test(e.message); }
    expect(ok).to.equal(true);
    expect(await c.recoveryCount()).to.equal(0n);
  });
});
