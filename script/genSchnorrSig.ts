import { ethers } from "ethers";
import path from "path";
import fs from "fs";

const schnorr = require("bip-schnorr");
const ecurve = require("ecurve");
const BigInteger = require("bigi");

const curve = ecurve.getCurveByName('secp256k1');
const G = curve.G;
const n = curve.n;

const { hexlify, randomBytes, getAddress } = ethers;
const randomInt = (len: number) => BigInteger.fromBuffer(Buffer.from(randomBytes(len))).mod(n);
const randomBuffer = (len: number) => Buffer.from(randomBytes(len));
const getPubKey = (sk: any) => schnorr.convert.intToBuffer(G.multiply(sk).affineX);
const toHex = (buf: Buffer) => '0x' + buf.toString('hex');

const sign = (sk: any, msg: any, aux: any) => {
    const sig = schnorr.sign(sk, msg, aux);
    const rx = toHex(sig.slice(0, 32));
    const s = toHex(sig.slice(32, 64));

    return { rx, s };
}

function genRandTestDataForMint(skHex: string, receiver: string, amount: number) {
    const sk = BigInteger.fromHex(skHex.substring(2));

    const btcTxId = hexlify(randomBytes(32));
    const msg = ethers.keccak256(ethers.solidityPacked(['bytes32', 'address', 'uint256'], [btcTxId, receiver, amount]));
    const aux = randomBuffer(32);
    const { rx, s } = sign(sk, Buffer.from(msg.substring(2), 'hex'), aux);

    return { btcTxId, receiver, amount, rx, s }
}

function genSK() {
    const sk = randomInt(32);
    const pubKey = getPubKey(sk);
    const pk = toHex(pubKey);

    return { sk: '0x' + sk.toHex(), pk }
}

(function () {
    const outputDir = path.join(__dirname, 'output');
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir);
    }

    // Generate schnorr key pair
    // const { sk, pk } = genSK();
    // fs.writeFileSync(path.join(outputDir, 'sk.txt'), JSON.stringify({ sk, pk }, null, 2));

    // load schnorr key pair
    const { sk, pk } = JSON.parse(fs.readFileSync(path.join(outputDir, 'sk.txt')).toString());

    console.log(sk)
    console.log(pk)
})();   