const { ethers } = require("hardhat");
async function main() {
  const dep = require("../../deployments/localhost.json");
  const s = await ethers.getSigners();
  const who = parseInt(process.env.WHO || "1");
  const c = await ethers.getContractAt(dep.abi, dep.address, s[who]);
  const hash = process.env.HASH || ethers.keccak256(ethers.toUtf8Bytes("demo-clean-state"));
  const t = BigInt(process.env.TATTACK || Date.now() * 1000);
  const rc = await (await c.anchorRecovery(hash, t)).wait();
  const n = await c.recoveryCount();
  const r = await c.getRecovery(n - 1n);
  console.log("ANCHORED index", (n - 1n).toString(), "hash", r[0], "tAttack", r[1].toString(), "by", r[2], "gas", rc.gasUsed.toString());
}
main().catch(e => { console.error(e); process.exit(1); });
