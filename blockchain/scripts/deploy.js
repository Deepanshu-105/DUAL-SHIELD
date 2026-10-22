const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const [deployer, nodeA, nodeB, nodeC] = await hre.ethers.getSigners();

  const Shield = await hre.ethers.getContractFactory("CityShield");
  const shield = await Shield.deploy();
  await shield.waitForDeployment();
  const address = await shield.getAddress();

  // register the 3 city nodes (accounts 1, 2, 3)
  for (const s of [nodeA, nodeB, nodeC]) {
    await (await shield.connect(s).registerNode({
      value: hre.ethers.parseEther("1"),
    })).wait();
  }

  const artifact = await hre.artifacts.readArtifact("CityShield");
  const out = {
    address,
    abi: artifact.abi,
    http: "http://127.0.0.1:8545",
    ws: "ws://127.0.0.1:8545",
    accounts: { A_target: 1, B_peer: 2, C_third: 3 },
    K: 2,
    N: 3,
  };

  const dir = path.join(__dirname, "..", "..", "deployments");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "localhost.json"), JSON.stringify(out, null, 2));
  console.log("CityShield deployed at", address);
}

main().catch((e) => { console.error(e); process.exit(1); });
