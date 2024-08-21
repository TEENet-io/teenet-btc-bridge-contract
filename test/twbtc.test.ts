import hre from "hardhat";
import { Signer } from "ethers";
import { expect } from "chai";
import { TWBTC } from "../typechain-types";

describe("TWBTC", function () {
    let twbtc: TWBTC;
    let owner: Signer;
    let addr1: Signer;

    beforeEach(async function () {
        [owner, addr1] = await hre.ethers.getSigners();

        twbtc = await hre.ethers.deployContract("TWBTC", [await owner.getAddress()]);
    });

    it("should have correct name and symbol", async function () {
        expect(await twbtc.name()).to.equal("TEENet wrapped Bitcoin");
        expect(await twbtc.symbol()).to.equal("TWBTC");
    });

    it("should mint tokens", async function () {
        const amount = hre.ethers.parseUnits("100", 8);
        await twbtc.connect(owner).mint(await addr1.getAddress(), amount);

        expect(await twbtc.balanceOf(await addr1.getAddress())).to.equal(amount);
    });

    it("should burn tokens", async function () {
        const mintAmount = hre.ethers.parseUnits("50", 8);
        const burnAmount = hre.ethers.parseUnits("25", 8);
        const expectedAmount = mintAmount-burnAmount;

        await twbtc.connect(owner).mint(await addr1.getAddress(), mintAmount);

        await twbtc.connect(owner).burn(await addr1.getAddress(), burnAmount);

        expect(await twbtc.balanceOf(await addr1.getAddress())).to.equal(expectedAmount);
    });
});