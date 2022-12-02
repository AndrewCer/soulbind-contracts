import { ethers } from "hardhat";

enum BurnAuth {
  IssuerOnly,
  OwnerOnly,
  Both,
  Neither,
}

async function main() {
  const Soulbind = await ethers.getContractFactory("Soulbind");
  const soulbind = await Soulbind.deploy();

  console.log('deploying...');

  await soulbind.deployed();

  console.log(`Soulbind deployed to ${soulbind.address}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
