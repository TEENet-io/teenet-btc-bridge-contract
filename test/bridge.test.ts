import hre from "hardhat";
import { expect, assert } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";

const schnorr = require("bip-schnorr");
const ecurve = require("ecurve");
const BigInteger = require("bigi");
const Buffer = require('safe-buffer').Buffer;
const randomBytes = require('randombytes');


const curve = ecurve.getCurveByName('secp256k1');
const G = curve.G;
const n = curve.n;

const randomInt = (len: any) => BigInteger.fromBuffer(Buffer.from(randomBytes(len))).mod(n);
const randomBuffer = (len: any) => Buffer.from(randomBytes(len));
const getPubKey = (sk: any) => schnorr.convert.intToBuffer(G.multiply(sk).affineX);

describe("TEENetBtcEvmBridge", function () {
    async function deployBridge() {
        const pk = hre.ethers.hexlify(hre.ethers.randomBytes(32));
        const bridge = await hre.ethers.deployContract("TEENetBtcEvmBridge", [pk]); 
        
        return { pk, bridge };
    };

    it("should deploy the contract with the correct pk value", async function () {
        const { pk, bridge } = await loadFixture(deployBridge);
        
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

        const toHex = (buf: Buffer) => '0x' + buf.toString('hex');

        const pk = toHex(pubKey);
        const rx = toHex(sig.slice(0, 32));
        const s = toHex(sig.slice(32, 64));
        const m = toHex(msg);

        expect(await bip340.verify(pk, rx, s, m)).to.equal(true);
    });
});