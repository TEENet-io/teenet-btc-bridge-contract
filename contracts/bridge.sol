// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import "./twbtc.sol";
import "./errors.sol";
import {Bip340Ecrec} from "./bip340-solidity@5a25f70/Bip340Ecrec.sol";

contract TEENetBtcEvmBridge is ITEENetBtcEvmBridgeErrors {
    // Public key of the secret that is generated by the threshold Schnorr 
    // signature scheme. The partial secrets are used by bridge nodes to 
    // perform an m-out-of-n threshold signature.
    uint256 private _pk;  

    address private _twbtc;
    address private _bip340;

    event Minted(address indexed recipient, uint256 indexed amount, bytes32 indexed btcTxId);
    event RedeemRequested(address indexed sender, uint256 indexed amount, string indexed btcAddress);

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
    
    /// Mint TWBTC tokens and transfer to the receiver. 
    /// It requires a valid Schnorr signature generated by m (out of n) 
    /// bridge nodes via the threshold Schnorr signature scheme.
    ///
    /// @param evmAddress Receiver EVM address
    /// @param amount Amount of TWBTC to be minted
    /// @param btcTxId ID of the Bitcoin transaction that transfers the funds to the bridge BTC wallet
    /// @param rx (rx, s) defines the Schnorr signature
    /// @param s (rx, s) defines the Schnorr signature
    function mint(address evmAddress, uint256 amount, bytes32 btcTxId, uint256 rx, uint256 s) public {
        if(evmAddress == address(0)) {
            revert InvalidEvmAddress();
        }

        if(amount == 0) {
            revert AmountMustBeGreaterThanZero();
        }
        
        // Verify the threshold Schnorr signature
        if (!Bip340Ecrec(_bip340).verify(_pk, rx, s, btcTxId)) {
            revert InvalidSchnorrSignature(btcTxId, rx, s);
        }

        // Mint the TWBTC tokens
        TWBTC(_twbtc).mint(evmAddress, amount);

        emit Minted(evmAddress, amount, btcTxId);
    }

    /// Request to redeem BTC. It only emits an event to notify bridge nodes.  
    ///
    /// @param amount Amount of BTC to be redeemed (in satoshi)
    /// @param btcAddress Receivers's BTC address
    function redeemRequest(uint256 amount, string memory btcAddress) public {
        if(amount == 0) {
            revert AmountMustBeGreaterThanZero();
        }

        uint256 balance = TWBTC(_twbtc).balanceOf(msg.sender);
        if(balance < amount) {
            revert InsufficientBalance(msg.sender, amount, balance);
        }

        emit RedeemRequested(msg.sender, amount, btcAddress);
    }
}