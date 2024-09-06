import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, resolve } from 'path';

function main() {
    const contractName = 'TEENetBtcBridge';
    const contractPath = join(resolve(__dirname, '..'), `artifacts/contracts/bridge.sol/${contractName}.json`);
    const outputDir = join(__dirname, 'output');

    // Ensure the output directory exists
    if (!existsSync(outputDir)) {
        mkdirSync(outputDir);
    }

    // Load the compiled contract JSON
    const contractJson = JSON.parse(readFileSync(contractPath, 'utf8'));

    // Extract ABI and bytecode
    const abi = contractJson.abi;
    const bytecode = contractJson.bytecode;

    // Write ABI to a separate file
    writeFileSync(join(outputDir, `${contractName}.abi`), JSON.stringify(abi, null, 2));

    // Write bytecode to a separate file
    writeFileSync(join(outputDir, `${contractName}.bin`), bytecode);
}

main();