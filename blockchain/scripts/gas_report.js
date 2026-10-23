// Gas per operation on a fresh in-process chain (does not touch the running lab).
//   cd blockchain && npx hardhat run scripts/gas_report.js
const { ethers } = require("hardhat");

async function main() {
  const [deployer, a, b, c, d] = await ethers.getSigners();
  const F = await ethers.getContractFactory("CityShield");
  const s = await F.deploy();
  await s.waitForDeployment();
  const gas = async (txp) => (await (await txp).wait()).gasUsed;
  const stake = { value: ethers.parseEther("1") };
  const ja3 = ethers.keccak256(ethers.toUtf8Bytes("fp"));
  const rows = [];

  rows.push(["registerNode (stake 1 ETH)", await gas(s.connect(a).registerNode(stake))]);
  await gas(s.connect(b).registerNode(stake));
  await gas(s.connect(c).registerNode(stake));
  await gas(s.connect(d).registerNode(stake));

  rows.push(["reportThreat, first report", await gas(s.connect(a).reportThreat("203.0.113.1", ja3))]);
  rows.push(["reportThreat, second report (consensus)", await gas(s.connect(b).reportThreat("203.0.113.1", ja3))]);

  // poisoning: a lone report, then the window expires and the reporter is slashed
  await gas(s.connect(c).reportThreat("203.0.113.2", ja3));
  await ethers.provider.send("evm_increaseTime", [61]);
  await ethers.provider.send("evm_mine", []);
  rows.push(["slashExpired (lone reporter slashed)", await gas(s.connect(deployer).slashExpired("203.0.113.2"))]);

  const root = ethers.keccak256(ethers.toUtf8Bytes("clean"));
  rows.push(["anchorCleanState (per IP)", await gas(s.connect(a).anchorCleanState("172.30.0.12", root, 1700000000))]);

  console.log("operation | gas");
  for (const [n, g] of rows) console.log(n + " | " + g.toString());
}
main().catch((e) => { console.error(e); process.exit(1); });
