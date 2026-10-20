const hre = require("hardhat");

async function main() {
  const CityShield = await hre.ethers.getContractFactory("CityShield");
  const contract = await CityShield.deploy();
  await contract.waitForDeployment();
  console.log("CityShield deployed to:", await contract.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
