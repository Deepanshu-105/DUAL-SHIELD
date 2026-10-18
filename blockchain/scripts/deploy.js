const fs = require("fs");

async function main() {
  const Hello = await ethers.getContractFactory("Hello");
  const hello = await Hello.deploy("hello from the blockchain");
  await hello.waitForDeployment();
  const address = await hello.getAddress();
  console.log("Hello deployed to:", address);
  fs.writeFileSync("deployed.json", JSON.stringify({ address }));
}

main().catch((e) => { console.error(e); process.exit(1); });
