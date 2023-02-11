import { ethers } from "hardhat";

async function main() {
    const addresses = Array.from({ length: 21 }, () => (ethers.Wallet.createRandom()).address);

    console.log(addresses);
    addresses.forEach(address => {
        console.log(address + ',');
    });
}

main();
