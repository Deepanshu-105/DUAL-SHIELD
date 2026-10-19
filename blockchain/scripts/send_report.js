const hre = require("hardhat");
const dep = require("../../deployments/localhost.json");

async function main() {
  const ip = process.env.IP || "203.0.113.50";
  const idx = Number(process.env.WHO || 1);   // 1=A, 2=B, 3=C
  const signers = await hre.ethers.getSigners();
  const signer = signers[idx];
  if (!signer) { console.error("Bad WHO value. Use WHO=1, 2 or 3."); process.exit(1); }
  console.log(`Reporting as account #${idx}: ${signer.address}`);

  const shield = await hre.ethers.getContractAt("CityShield", dep.address, signer);
  if ((await shield.stakes(signer.address)) === 0n) {
    console.error("This account is not staked. Use WHO=1, 2 or 3.");
    process.exit(1);
  }

  const tx = await shield.reportThreat(ip, hre.ethers.id(process.env.JA3 || "manual-test"));
  await tx.wait();

  const [count, k, confirmed] = await shield.getTally(ip);
  console.log(`IP ${ip}: ${count}/${k} reports, confirmed=${confirmed}`);
}

main().catch((e) => { console.error(e.shortMessage || e.message || e); process.exit(1); });
