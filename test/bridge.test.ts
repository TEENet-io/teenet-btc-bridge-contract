import hre from "hardhat";
import { expect, assert } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";

const schnorr = require("bip-schnorr");
const ecurve = require("ecurve");
const BigInteger = require("bigi");
const Buffer = require('safe-buffer').Buffer;

const curve = ecurve.getCurveByName('secp256k1');
const G = curve.G;
const n = curve.n;

const { hexlify, randomBytes, getAddress } = hre.ethers;
const randomInt = (len: number) => BigInteger.fromBuffer(Buffer.from(randomBytes(len))).mod(n);
const randomBuffer = (len: number) => Buffer.from(randomBytes(len));
const getPubKey = (sk: any) => schnorr.convert.intToBuffer(G.multiply(sk).affineX);
const toHex = (buf: Buffer) => '0x' + buf.toString('hex');

// Generate a random private key and its corresponding public key
const sk = randomInt(32);
const pubKey = getPubKey(sk);
const pk = toHex(pubKey);

const sign = (msg: any, aux: any) => {
    const sig = schnorr.sign(sk, msg, aux);
    const rx = toHex(sig.slice(0, 32));
    const s = toHex(sig.slice(32, 64));

    return { rx, s };
}

describe("TEENetBtcEvmBridge", function () {
    async function deployBridge() {
        const bridge = await hre.ethers.deployContract("TEENetBtcEvmBridge", [pk]);

        return { bridge };
    };

    describe("Deployment", function () {
        it("should deploy the contract with the correct pk value", async function () {
            const { bridge } = await loadFixture(deployBridge);

            expect(await bridge.pk()).to.equal(BigInt(pk));
        });

        it("should deploy the TWBTC contract with the bridge as the owner", async function () {
            const { bridge } = await loadFixture(deployBridge);

            const twbtcAddr = await bridge.twbtc();
            const twbtc = await hre.ethers.getContractAt("TWBTC", twbtcAddr);

            expect(await twbtc.owner()).to.equal(await bridge.getAddress());
        });
    });

    describe("Schnorr", function () {
        it("should verify schnorr signature", async function () {
            const { bridge } = await loadFixture(deployBridge);

            const sk = randomInt(32);
            const aux = Buffer.from(randomBytes(32));
            const pubKey = getPubKey(sk);
            const msg = randomBuffer(32);
            const sig = schnorr.sign(sk, msg, aux);

            try {
                schnorr.verify(pubKey, msg, sig)
            } catch (e: any) {
                assert.fail(e);
            };

            const bip340 = await hre.ethers.getContractAt("Bip340Ecrec", await bridge.bip340());

            const pk = toHex(pubKey);
            const rx = toHex(sig.slice(0, 32));
            const s = toHex(sig.slice(32, 64));
            const m = toHex(msg);

            expect(await bip340.verify(pk, rx, s, m)).to.equal(true);
        });
    });

    describe("Mint", function () {
        it('should mint TWBTC tokens and emit Minted event', async () => {
            const { bridge } = await loadFixture(deployBridge);

            const receiver = hexlify(randomBytes(20));
            const amount = 100;
            const btcTxId = hexlify(randomBytes(32));
            const msg = hre.ethers.keccak256(hre.ethers.solidityPacked(['bytes32', 'address', 'uint256'], [btcTxId, receiver, amount]));
            const aux = randomBuffer(32);
            const { rx, s } = sign(Buffer.from(msg.substring(2), 'hex'), aux);

            await expect(bridge.mint(btcTxId, receiver, amount, rx, s))
                .to.emit(bridge, 'Minted')
                .withArgs(btcTxId, getAddress(receiver), amount);

            const twbtc = await hre.ethers.getContractAt("TWBTC", await bridge.twbtc());
            const balance = await twbtc.balanceOf(receiver);
            expect(balance).to.equal(amount);
        });
        it('should revert if receiver is zero address', async () => {
            const { bridge } = await loadFixture(deployBridge);

            const receiver = '0x' + '0'.repeat(40);
            const amount = 100;
            const btcTxId = hexlify(randomBytes(32));
            const rx = hexlify(randomBytes(32));
            const s = hexlify(randomBytes(32));

            await expect(bridge.mint(btcTxId, receiver, amount, rx, s))
                .to.be.revertedWithCustomError(bridge, 'ZeroEvmAddress');
        });

        it('should revert if amount is zero', async () => {
            const { bridge } = await loadFixture(deployBridge);

            const receiver = hexlify(randomBytes(20));
            const amount = 0;
            const btcTxId = hexlify(randomBytes(32));
            const rx = hexlify(randomBytes(32));
            const s = hexlify(randomBytes(32));

            await expect(bridge.mint(btcTxId, receiver, amount, rx, s))
                .to.be.revertedWithCustomError(bridge, 'ZeroAmount');
        });

        it('should revert if signature is invalid', async () => {
            const { bridge } = await loadFixture(deployBridge);

            const receiver = hre.ethers.getAddress(hexlify(randomBytes(20)));
            const amount = 100;
            const btcTxId = hexlify(randomBytes(32));
            const msg = hre.ethers.keccak256(hre.ethers.solidityPacked(['bytes32', 'address', 'uint256'], [btcTxId, receiver, amount]));

            const aux = randomBuffer(32);
            const { rx, s } = sign(Buffer.from(msg.substring(2), 'hex'), aux);

            // Modify the signature to make it invalid
            const modifiedS = '0x' + (BigInt(s) + 1n).toString(16);

            await expect(bridge.mint(btcTxId, receiver, amount, rx, s))
                .to.emit(bridge, 'Minted')
                .withArgs(btcTxId, receiver, amount);
            await expect(bridge.mint(btcTxId, receiver, amount, rx, modifiedS))
                .to.be.revertedWithCustomError(bridge, 'InvalidSchnorrSignature')
                .withArgs(btcTxId, receiver, amount, rx, modifiedS);
        });
    });

    describe("Redeem", function () {
        describe("Request", function () {
            it('should emit RedeemRequested event', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const signer = await hre.ethers.provider.getSigner(9);

                const receiver = signer.address;
                const mintAmount = 100;
                const btcTxId = hexlify(randomBytes(32));
                const msg = hre.ethers.keccak256(hre.ethers.solidityPacked(['bytes32', 'address', 'uint256'], [btcTxId, receiver, mintAmount]));
                const aux = randomBuffer(32);
                const { rx, s } = sign(Buffer.from(msg.substring(2), 'hex'), aux);

                await expect(bridge.mint(btcTxId, receiver, mintAmount, rx, s))
                    .to.emit(bridge, 'Minted')
                    .withArgs(btcTxId, receiver, mintAmount);

                const redeemAmount = 100;
                const btcAddress = '34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo';

                await expect(bridge.connect(signer).redeemRequest(redeemAmount, btcAddress))
                    .to.emit(bridge, 'RedeemRequested')
                    .withArgs(receiver, redeemAmount, btcAddress);
            });
            it('should revert if amount is zero', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const amount = 0;
                const btcAddress = '34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo';

                await expect(bridge.redeemRequest(amount, btcAddress))
                    .to.be.revertedWithCustomError(bridge, 'ZeroAmount');
            });

            it('should revert if sender has insufficient balance', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const signer = await hre.ethers.provider.getSigner(9);

                const amount = 100;
                const btcAddress = '34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo';

                await expect(bridge.connect(signer).redeemRequest(amount, btcAddress))
                    .to.be.revertedWithCustomError(bridge, 'InsufficientBalance');
            });
        });
        describe("Prepare", function () {
            it('should emit RedeemPrepared event', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const signer = await hre.ethers.provider.getSigner(9);

                const receiver = signer.address;
                const mintAmount = 100;
                const btcTxId = hexlify(randomBytes(32));
                const mintMsg = hre.ethers.keccak256(hre.ethers.solidityPacked(
                    ['bytes32', 'address', 'uint256'], 
                    [btcTxId, receiver, mintAmount])
                );
                const aux1 = randomBuffer(32);
                const sig1 = sign(Buffer.from(mintMsg.substring(2), 'hex'), aux1);

                await expect(bridge.mint(btcTxId, receiver, mintAmount, sig1.rx, sig1.s))
                    .to.emit(bridge, 'Minted')
                    .withArgs(btcTxId, receiver, mintAmount);

                const requester = receiver;
                const redeemAmount = 100;
                const redeemRequestTxHash = hexlify(randomBytes(32));
                const outpointTxIds = [hexlify(randomBytes(32)), hexlify(randomBytes(32))];
                const outpointIdxs = [0, 4];
        
                const prepareMsg = hre.ethers.keccak256(hre.ethers.solidityPacked(
                    ['bytes32', 'address', 'uint256', 'bytes32[]', 'uint16[]'],
                    [redeemRequestTxHash, requester, redeemAmount, outpointTxIds, outpointIdxs])
                );
                const aux2 = randomBuffer(32);
                const sig2 = sign(Buffer.from(prepareMsg.substring(2), 'hex'), aux2);

                await expect(bridge.connect(signer)
                    .redeemPrepare(
                        redeemRequestTxHash, requester, redeemAmount, 
                        outpointTxIds, outpointIdxs, 
                        sig2.rx, sig2.s
                    ))
                    .to.emit(bridge, 'RedeemPrepared')
                    .withArgs(redeemRequestTxHash, requester, redeemAmount, outpointTxIds, outpointIdxs);
            });
            it('should revert if requester is zero address', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const requester = '0x' + '0'.repeat(40);
                const amount = 100;
                const btcTxId = hexlify(randomBytes(32));
                const rx = hexlify(randomBytes(32));
                const s = hexlify(randomBytes(32));

                await expect(bridge.redeemPrepare(btcTxId, requester, amount, [], [], rx, s))
                    .to.be.revertedWithCustomError(bridge, 'ZeroEvmAddress');
            });
            it('should revert if amount is zero', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const requester = hexlify(randomBytes(20));
                const amount = 0;
                const btcTxId = hexlify(randomBytes(32));
                const rx = hexlify(randomBytes(32));
                const s = hexlify(randomBytes(32));

                await expect(bridge.redeemPrepare(btcTxId, requester, amount, [], [], rx, s))
                    .to.be.revertedWithCustomError(bridge, 'ZeroAmount');
            });

            it('should revert if outpointTxIds is empty', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const requester = hexlify(randomBytes(20));
                const amount = 100;
                const btcTxId = hexlify(randomBytes(32));
                const rx = hexlify(randomBytes(32));
                const s = hexlify(randomBytes(32));

                await expect(bridge.redeemPrepare(btcTxId, requester, amount, [], [0], rx, s))
                    .to.be.revertedWithCustomError(bridge, 'ZeroOutpointTxIdsArrayLength');
            });
            
            it('should revert if outpointIdxs is empty', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const requester = hexlify(randomBytes(20));
                const amount = 100;
                const btcTxId = hexlify(randomBytes(32));
                const rx = hexlify(randomBytes(32));
                const s = hexlify(randomBytes(32));

                await expect(bridge.redeemPrepare(
                    btcTxId, requester, amount, [hexlify(randomBytes(32))], [], rx, s))
                    .to.be.revertedWithCustomError(bridge, 'ZeroOutpointIdxsArrayLength');
            });

            it('should revert if outpointTxIds and outpointIdxs have different lengths', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const requester = hexlify(randomBytes(20));
                const amount = 100;
                const btcTxId = hexlify(randomBytes(32));
                const rx = hexlify(randomBytes(32));
                const s = hexlify(randomBytes(32));
        
                const outpointTxIds = [hexlify(randomBytes(32)), hexlify(randomBytes(32))];    
                const outpointIdxs = [0];

                await expect(bridge.redeemPrepare(
                    btcTxId, requester, amount, outpointTxIds, outpointIdxs, rx, s))
                    .to.be.revertedWithCustomError(bridge, 'OutpointTxIdsAndOutpointIdxsLengthMismatch');
            });

            it('should revert if there is any zero outpointTxId', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const requester = hexlify(randomBytes(20));
                const amount = 100;
                const btcTxId = hexlify(randomBytes(32));
                const rx = hexlify(randomBytes(32));
                const s = hexlify(randomBytes(32));
        
                const outpointTxIds = [hexlify(randomBytes(32)), '0x' + '0'.repeat(64)];    
                const outpointIdxs = [0, 4];

                await expect(bridge.redeemPrepare(
                    btcTxId, requester, amount, outpointTxIds, outpointIdxs, rx, s))
                    .to.be.revertedWithCustomError(bridge, 'ZeroOutpointTxId');
            });
        });
    });
});