import { Web3 } from 'web3';
import { keys, bridgeJson, twbtcJson } from './common';

//
// command: ts-node script/redeem.ts <bridgeAddress> <requester(0-9)> <amount>
//
async function main() {
    const bridgeAddress = process.argv[2];
    const i = parseInt(process.argv[3]);
    const amount = parseInt(process.argv[4]);

    const web3 = new Web3(
        new Web3.providers.HttpProvider('http://localhost:8545'),
    );

    const requester = web3.eth.accounts.privateKeyToAccount(keys[i]);
    const Bridge = new web3.eth.Contract(bridgeJson.abi, bridgeAddress);
    
    const addr: string = await Bridge.methods.twbtc().call();
    const TWBTC = new web3.eth.Contract(twbtcJson.abi, addr);
    
    await TWBTC.methods.approve(bridgeAddress, amount)
        .send({ from: requester.address })
        .once('transactionHash', hash => console.log(`Allowance approved: ${hash}`));

    await Bridge.methods.redeemRequest(amount, "receiver_btc_addr")
        .send({ from: requester.address })
        .once('transactionHash', hash => console.log(`Redeem requested: ${hash}`));
    
    const balance = await TWBTC.methods.balanceOf(requester.address).call();
    console.log(`Account: ${requester.address}`);
    console.log(`Balance: ${balance}`);
}

main().catch(console.error);