const hre = require("hardhat");
const fs = require("fs");
async function main() {
  const { ethers } = hre;
  const signers = await ethers.getSigners();
  const dep = JSON.parse(fs.readFileSync("../deployments/localhost.json"));
  const c = new ethers.Contract(dep.address, dep.abi, ethers.provider);
  console.log("accounts:", signers.length, "  block:", await ethers.provider.getBlockNumber());
  for (let i = 0; i < 6; i++) {
    const a = signers[i].address;
    const bal = ethers.formatEther(await ethers.provider.getBalance(a));
    const stake = ethers.formatEther(await c.stakes(a));
    const role = i === 0 ? "deployer" : i <= 3 ? "city node" : "unused";
    console.log(i, a, bal + " ETH", " stake " + stake, " " + role);
  }
  console.log("contract:", dep.address);
}
main().catch((e) => { console.error(e); process.exit(1); });
