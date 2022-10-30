import { ethers } from "hardhat";

enum BurnAuth {
  IssuerOnly,
  OwnerOnly,
  Both,
  Neither,
}

async function main(burnAuth: BurnAuth) {
  const Soulbound = await ethers.getContractFactory("Soulbound");
  const soulbound = await Soulbound.deploy(burnAuth);

  await soulbound.deployed();

  console.log(`Soulbound with burnAuth ${burnAuth} deployed to ${soulbound.address}`);
}

main(BurnAuth.Both).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
