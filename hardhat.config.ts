import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import * as dotenv from 'dotenv';

dotenv.config();

const config: HardhatUserConfig = {
  networks: {
    // Base testnet
    base_goerli: {
      url: 'https://goerli.base.org',
      accounts: [process.env.WALLET_KEY as string],
    },
    // Base local
    base_local: {
      url: 'http://localhost:8545',
      accounts: [process.env.WALLET_KEY as string],
    },
    // Polygon testnet
    polygon_mumbai: {
      url: "https://rpc-mumbai.maticvigil.com",
      accounts: [process.env.SIGNER_KEY || '']
    },
    // Polygon mainnet
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
    apiKey: {
      polygonMumbai: process.env.POLYGONSCAN_KEY!,
      polygon: process.env.POLYGONSCAN_KEY!,
      // No api key for basescan - fill in with random value
      'base-goerli': '12345'
    },
    customChains: [
      {
        network: "base-goerli",
        chainId: 84531,
        urls: {
          // Pick a block explorer and uncomment those lines

          // Blockscout
          // apiURL: "https://base-goerli.blockscout.com/api",
          // browserURL: "https://base-goerli.blockscout.com"

          // Basescan by Etherscan
          apiURL: "https://api-goerli.basescan.org/api",
          browserURL: "https://goerli.basescan.org"
        }
      }
    ]
  }
};

export default config;
