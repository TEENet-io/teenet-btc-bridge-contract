// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

interface ITEENetBtcEvmBridgeErrors {
    error InvalidSchnorrSignature(bytes32 msg, uint256 rx, uint256 s);
    error AmountMustBeGreaterThanZero();
    error InvalidEvmAddress();
    error InsufficientBalance(address sender, uint256 redeemAmount, uint256 balance);
}