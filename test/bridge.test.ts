import hre from "hardhat";
import { expect, assert } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";

const schnorr = require("bip-schnorr");
const ecurve = require("ecurve");
const BigInteger = require("bigi");
const Buffer = require('safe-buffer').Buffer;

const curve = ecurve.getCurveByName('secp256k1');
const G = curve.G;
const n = curve.n;

const { hexlify, randomBytes, getAddress } = hre.ethers;
const randomInt = (len: number) => BigInteger.fromBuffer(Buffer.from(randomBytes(len))).mod(n);
const randomBuffer = (len: number) => Buffer.from(randomBytes(len));
const getPubKey = (sk: any) => schnorr.convert.intToBuffer(G.multiply(sk).affineX);
const toHex = (buf: Buffer) => '0x' + buf.toString('hex');

// Generate a random private key and its corresponding public key
const sk = randomInt(32);
const pubKey = getPubKey(sk);
const pk = toHex(pubKey);

const sign = (msg: any, aux: any) => {
    const sig = schnorr.sign(sk, msg, aux);
    const rx = toHex(sig.slice(0, 32));
    const s = toHex(sig.slice(32, 64));

    return { rx, s };
} 

describe("TEENetBtcEvmBridge", function () {
    async function deployBridge() {
        const bridge = await hre.ethers.deployContract("TEENetBtcEvmBridge", [pk]); 
        
        return { bridge };
    };

    it("should deploy the contract with the correct pk value", async function () {
        const { bridge } = await loadFixture(deployBridge);
        
        expect(await bridge.pk()).to.equal(BigInt(pk));
    });

    it("should deploy the TWBTC contract with the bridge as the owner", async function () {
        const { bridge } = await loadFixture(deployBridge);

        const twbtcAddr = await bridge.twbtc();
        const twbtc = await hre.ethers.getContractAt("TWBTC", twbtcAddr);

        expect(await twbtc.owner()).to.equal(await bridge.getAddress());
    });

    it("should verify schnorr signature", async function () {
        const { bridge } = await loadFixture(deployBridge);

        const sk = randomInt(32);
        const aux = Buffer.from(randomBytes(32));
        const pubKey = getPubKey(sk);
        const msg = randomBuffer(32);
        const sig = schnorr.sign(sk, msg, aux);

        try {
            schnorr.verify(pubKey, msg, sig)
        } catch(e: any) {
            assert.fail(e);
        };

        const bip340 = await hre.ethers.getContractAt("Bip340Ecrec", await bridge.bip340());

        const pk = toHex(pubKey);
        const rx = toHex(sig.slice(0, 32));
        const s = toHex(sig.slice(32, 64));
        const m = toHex(msg);

        expect(await bip340.verify(pk, rx, s, m)).to.equal(true);
    });
    it('should mint TWBTC tokens and emit Minted event', async () => {
        const { bridge } = await loadFixture(deployBridge);

        const evmAddress = hexlify(randomBytes(20));
        const amount = 100;
        const msg = randomBuffer(32);
        const aux = randomBuffer(32);
        const btcTxId = toHex(msg);
        const { rx, s } = sign(msg, aux);

        await expect(bridge.mint(evmAddress, amount, btcTxId, rx, s))
            .to.emit(bridge, 'Minted')
            .withArgs(getAddress(evmAddress), amount, btcTxId);

        const twbtc = await hre.ethers.getContractAt("TWBTC", await bridge.twbtc());
        const balance = await twbtc.balanceOf(evmAddress);
        expect(balance).to.equal(amount);
    });
    it('should revert if evmAddress is zero address', async () => {
        const { bridge } = await loadFixture(deployBridge);

        const evmAddress = '0x' + '0'.repeat(40);
        const amount = 100;
        const btcTxId = hexlify(randomBytes(32));
        const rx = hexlify(randomBytes(32));
        const s = hexlify(randomBytes(32));

        await expect(bridge.mint(evmAddress, amount, btcTxId, rx, s)).to.be.revertedWithCustomError(bridge, 'InvalidEvmAddress');
    });
});

// import { ethers } from 'hardhat';
// import { expect } from 'chai';
// import { hexlify } from "ethers";

// describe('TEENetBtcEvmBridge', () => {
//     let bridge;
//     let twbtc;
//     let bip340;

//     beforeEach(async () => {
//         const Bridge = await ethers.getContractFactory('TEENetBtcEvmBridge');
//         bridge = await Bridge.deploy(123456789); // Replace with actual pk value
//         await bridge.deployed();

//         twbtc = await ethers.getContractAt('TWBTC', await bridge.twbtc());
//         bip340 = await ethers.getContractAt('Bip340Ecrec', await bridge.bip340());
//     });


//     it('should revert if amount is zero', async () => {
//         const evmAddress = '0x1234567890abcdef1234567890abcdef12345678'; // Replace with actual EVM address
//         const amount = 0;
//         const btcTxId = ethers.utils.formatBytes32String('0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef');
//         const rx = 123456789; // Replace with actual rx value
//         const s = 987654321; // Replace with actual s value

//         await expect(bridge.mint(evmAddress, amount, btcTxId, rx, s)).to.be.revertedWith('AmountMustBeGreaterThanZero');
//     });

//     it('should revert if signature is invalid', async () => {
//         const evmAddress = '0x1234567890abcdef1234567890abcdef12345678'; // Replace with actual EVM address
//         const amount = 100;
//         const btcTxId = ethers.utils.formatBytes32String('0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef');
//         const rx = 123456789; // Replace with actual rx value
//         const s = 987654321; // Replace with actual s value

//         // Modify the signature to make it invalid
//         const modifiedS = s + 1;

//         await expect(bridge.mint(evmAddress, amount, btcTxId, rx, modifiedS)).to.be.revertedWith('InvalidSignature');
//     });
// });