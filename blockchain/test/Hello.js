const { expect } = require("chai");

describe("Hello", function () {
  it("stores and updates the message", async function () {
    const Hello = await ethers.getContractFactory("Hello");
    const hello = await Hello.deploy("hello dual-shield");
    expect(await hello.message()).to.equal("hello dual-shield");

    await hello.setMessage("updated");
    expect(await hello.message()).to.equal("updated");
  });
});
