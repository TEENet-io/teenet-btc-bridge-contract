import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, resolve } from 'path';

function main() {
    let contractName = 'TWBTC';
    let contractFile = join(resolve(__dirname, '..'), `artifacts/contracts/twbtc.sol/TWBTC.json`);
    writeFiles(contractName, contractFile);

    contractName = 'TEENetBtcBridge';
    contractFile = join(resolve(__dirname, '..'), `artifacts/contracts/bridge.sol/TEENetBtcBridge.json`);
    writeFiles(contractName, contractFile);
}

function writeFiles(contractName: string, contractFile: string) {
    const outputDir = join(__dirname, 'output');
    if (!existsSync(outputDir)) {
        mkdirSync(outputDir);
    }

    // Load the compiled contract JSON
    const contractJson = JSON.parse(readFileSync(contractFile, 'utf8'));

    // Extract ABI and bytecode
    const abi = contractJson.abi;
    const bytecode = contractJson.bytecode;

    // Write ABI to a separate file
    writeFileSync(join(outputDir, `${contractName}.abi`), JSON.stringify(abi, null, 2));

    // Write bytecode to a separate file
    writeFileSync(join(outputDir, `${contractName}.bin`), bytecode);
}

main();