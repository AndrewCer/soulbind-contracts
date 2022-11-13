// TODO: Set this up to deploy to public networks: https://hardhat.org/tutorial/deploying-to-a-live-network

import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.17",
    settings: {
      optimizer: {
        enabled: true,
        runs: 1000
      }
    }
  },
};

export default config;
