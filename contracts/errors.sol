// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

interface ITEENetBtcEvmBridgeErrors {
    error InvalidSignature(uint256 rx, uint256 s);
    error AmountMustBeGreaterThanZero();
    error InvalidEvmAddress();
}