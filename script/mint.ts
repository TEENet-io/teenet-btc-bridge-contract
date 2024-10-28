import { Web3 } from 'web3';
import { keys, bridgeJson, twbtcJson } from './common';
import {hexlify, randomBytes, solidityPacked, keccak256} from 'ethers';

const schnorr = require("bip-schnorr");
const BigInteger = require("bigi");
const toHex = (buf: Buffer) => '0x' + buf.toString('hex');
const sign = (sk: any, msg: any, aux: any) => {
    const sig = schnorr.sign(sk, msg, aux);
    const rx = toHex(sig.slice(0, 32));
    const s = toHex(sig.slice(32, 64));

    return { rx, s };
}

//
// command: ts-node script/mint.ts <bridgeAddress> <receiver(0-9)> <amount> <sk>
//
async function main() {
    const bridgeAddress = process.argv[2];
    const i = parseInt(process.argv[3]);
    const amount = parseInt(process.argv[4]);
    const sk = process.argv[5];
    const pk = process.argv[6];

    const web3 = new Web3(
        new Web3.providers.HttpProvider('http://localhost:8545'),
    );

    const signer = web3.eth.accounts.privateKeyToAccount(keys[i]);
    const Bridge = new web3.eth.Contract(bridgeJson.abi, bridgeAddress);

    const receiver = signer.address;
    const btcTxId = hexlify(randomBytes(32));
    const encode = solidityPacked(['bytes32', 'address', 'uint256'], [btcTxId, receiver, amount]);
    const msg = keccak256(encode);
    const aux = randomBytes(32);
    const { rx, s } = sign(
        BigInteger.fromBuffer(Buffer.from(sk.substring(2), 'hex')),
        Buffer.from(msg.substring(2), 'hex'), 
        aux,
    );

    await Bridge.methods.mint(btcTxId, receiver, amount, rx, s)
        .send({ from: receiver })
        .once('transactionHash', hash => console.log(`Transaction hash: ${hash}`));

    const addr: string = await Bridge.methods.twbtc().call();
    const TWBTC = new web3.eth.Contract(twbtcJson.abi, addr);
    const balance = await TWBTC.methods.balanceOf(receiver).call();
    console.log(`Account: ${receiver}`);
    console.log(`Balance: ${balance}`);
}

main().catch(console.error);