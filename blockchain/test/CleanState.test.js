const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("CityShield anchorCleanState", function () {
  it("stores and returns a merkle root + attack timestamp for a staked reporter", async function () {
    const [, addr1] = await ethers.getSigners();
    const CityShield = await ethers.getContractFactory("CityShield");
    const contract = await CityShield.deploy();
    await contract.waitForDeployment();

    await contract.connect(addr1).registerNode({ value: ethers.parseEther("1") });

    const fakeRoot = ethers.keccak256(ethers.toUtf8Bytes("test-merkle-root"));
    const tAttack = Math.floor(Date.now() / 1000);

    await contract.connect(addr1).anchorCleanState("172.30.0.12", fakeRoot, tAttack);

    const [root, t, anchored] = await contract.getCleanState("172.30.0.12");
    expect(root).to.equal(fakeRoot);
    expect(t).to.equal(tAttack);
    expect(anchored).to.equal(true);
  });

  it("rejects an anchor from an address with no stake", async function () {
    const [, , addr2] = await ethers.getSigners();
    const CityShield = await ethers.getContractFactory("CityShield");
    const contract = await CityShield.deploy();
    await contract.waitForDeployment();

    const fakeRoot = ethers.keccak256(ethers.toUtf8Bytes("x"));
    await expect(
      contract.connect(addr2).anchorCleanState("1.2.3.4", fakeRoot, 0)
    ).to.be.revertedWith("not staked");
  });
});
