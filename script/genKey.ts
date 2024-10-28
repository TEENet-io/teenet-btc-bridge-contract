import { hexlify, randomBytes } from "ethers";

const schnorr = require("bip-schnorr");
const ecurve = require("ecurve");
const BigInteger = require("bigi");

const curve = ecurve.getCurveByName('secp256k1');
const G = curve.G;
const n = curve.n;

function main() {
    const randomInt = (len: number) => BigInteger.fromBuffer(Buffer.from(randomBytes(len))).mod(n);
    const getPubKey = (sk: any) => schnorr.convert.intToBuffer(G.multiply(sk).affineX);
    const toHex = (buf: any) => '0x' + buf.toString('hex');

    // Generate a random private key and its corresponding public key
    const sk = randomInt(32);
    const pubKey = getPubKey(sk);
    
    console.log(`sk: 0x${sk.toString(16)}`);
    console.log(`pk: ${toHex(pubKey)}`)
}   

main();