import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
    solidity: "0.8.24",
    "networks": {
        "sepolia": {
            "url": "https://eth-sepolia.g.alchemy.com/v2/S7HHO8_vTrIuEEaosbqaEp5hZ0cRi0DC",
            "accounts": ["0x1ebce7965705e67c942d2874a97bd6ec64aa7462e862763227ec7b18bae6e523"],
        }
    }
};

export default config;
