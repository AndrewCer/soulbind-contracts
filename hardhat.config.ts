import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import * as dotenv from 'dotenv';

dotenv.config();

const config: HardhatUserConfig = {
  networks: {
    polygon_mumbai: {
      url: "https://rpc-mumbai.maticvigil.com",
      accounts: [process.env.SIGNER_KEY || '']
    },
    polygon_main_net: {
      url: "https://polygon-rpc.com",
      accounts: [process.env.SIGNER_KEY || '']
    }
  },
  solidity: {
    version: "0.8.17",
    settings: {
      optimizer: {
        enabled: true,
        runs: 1000
      }
    }
  },
  etherscan: {
    apiKey: process.env.POLYGONSCAN_KEY,
 }
};

export default config;
