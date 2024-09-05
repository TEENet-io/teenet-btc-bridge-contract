// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

interface ITEENetBtcEvmBridgeErrors {
    error ZeroAmount();
    error ZeroEvmAddress();
    error ZeroEvmTxHash();
    error ZeroBtcTxId();
    error ZeroOutpointTxId();
    error ZeroOutpointTxIdsArrayLength();
    error ZeroOutpointIdxsArrayLength();
    error OutpointTxIdsAndOutpointIdxsLengthMismatch();
    error InvalidSchnorrSignature(bytes32 txId, address addr, uint256 amount, uint256 rx, uint256 s);
}