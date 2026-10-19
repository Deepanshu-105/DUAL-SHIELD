const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("CityShield", function () {
  it("confirms a threat once 2 different addresses report it", async function () {
    const [addr1, addr2] = await ethers.getSigners();
    const CityShield = await ethers.getContractFactory("CityShield");
    const contract = await CityShield.deploy();

    await contract.connect(addr1).reportThreat("172.30.0.12", "hassh-abc123");
    expect(await contract.isConfirmed("172.30.0.12")).to.equal(false);

    await contract.connect(addr2).reportThreat("172.30.0.12", "hassh-abc123");
    expect(await contract.isConfirmed("172.30.0.12")).to.equal(true);
  });

  it("does not confirm from a single report alone", async function () {
    const [addr1] = await ethers.getSigners();
    const CityShield = await ethers.getContractFactory("CityShield");
    const contract = await CityShield.deploy();

    await contract.connect(addr1).reportThreat("1.2.3.4", "hassh-xyz");
    expect(await contract.isConfirmed("1.2.3.4")).to.equal(false);
  });
});
