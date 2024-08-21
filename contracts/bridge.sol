// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import {TWBTC} from "./twbtc.sol";
import {Bip340Ecrec} from "./bip340-solidity@5a25f70/Bip340Ecrec.sol";

contract TEENetBtcEvmBridge {
    // Public key of the secret generated for the threshold Schnorr
    // signature scheme used by TEE bridge nodes
    uint256 private _pk;  

    address private _twbtc;
    address private _bip340;

    constructor(uint256 pk_) {
        _pk = pk_;

        // Set the deployed bridge as the owner of the TWBTC contract
        _twbtc = address(new TWBTC(address(this)));

        // Deploy Bip340 library
        _bip340 = address(new Bip340Ecrec());
    }

    // Get the registered public key
    function pk() public view returns (uint256) {
        return _pk;
    }

    // Get the deployed TWBTC contract address
    function twbtc() public view returns (address) {
        return _twbtc;
    }

    function bip340() public view returns (address) {
        return _bip340;
    }
}