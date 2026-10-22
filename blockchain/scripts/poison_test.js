const { ethers, network } = require("hardhat");
async function main() {
  const dep = require("../../deployments/localhost.json");
  const s = await ethers.getSigners();
  const c = await ethers.getContractAt(dep.abi, dep.address);
  const ip = "172.30.0.11";                       // a legitimate address (the peer)
  const ja3 = ethers.keccak256(ethers.toUtf8Bytes("poison-test"));
  await (await c.connect(s[3]).reportThreat(ip, ja3)).wait();   // node C lies
  let t = await c.getTally(ip);
  console.log("after 1 report: count", t[0].toString(), "k", t[1].toString(), "confirmed", t[2]);
  await network.provider.send("evm_increaseTime", [61]);        // skip the 60 s window
  await network.provider.send("evm_mine");
  await (await c.connect(s[1]).slashExpired(ip)).wait();
  console.log("stake of node C after slash:", (await c.stakes(s[3].address)).toString());
}
main().catch(e => { console.error(e); process.exit(1); });
