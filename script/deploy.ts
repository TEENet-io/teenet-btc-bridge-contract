import { Web3 } from 'web3';
import { keys, bridgeJson } from './common';

//
// command: ts-node script/deploy.ts <pk> <deployer(0-9)>
//
async function main() {
    const pk = process.argv[2];
    const i = parseInt(process.argv[3]);

    const web3 = new Web3(
        new Web3.providers.HttpProvider('http://localhost:8545'),
    );

    const deployer = web3.eth.accounts.privateKeyToAccount(keys[i]);

    const Bridge = new web3.eth.Contract(bridgeJson.abi);
    const deployTx = Bridge.deploy({
        data: bridgeJson.bytecode,
        arguments: [pk],
    });

    // const gas = '0x' + (await deployTx.estimateGas()).toString(16);
    const deployed = await deployTx
        .send({
            from: deployer.address,
            // gas: gas,
        })
        .once('transactionHash', hash => console.log(`Transaction hash: ${hash}`));

    console.log(`Deployed at: ${deployed.options.address}`);
}

main().catch(console.error);