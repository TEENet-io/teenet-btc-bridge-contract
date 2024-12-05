import { ethers } from "hardhat";
import { expect, assert } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";

const schnorr = require("bip-schnorr");
const ecurve = require("ecurve");
const BigInteger = require("bigi");

const curve = ecurve.getCurveByName('secp256k1');
const G = curve.G;
const n = curve.n;

const { hexlify, randomBytes, getAddress } = ethers;
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

describe("TEENetBtcBridge", function () {
    async function deployBridge() {
        const feeAccount = hexlify(randomBytes(20));

        // const Bridge = await ethers.getContractFactory("TEENetBtcBridge");
        // const bridge = await Bridge.deploy(pk, feeAccount, 10);
        // await bridge.deployed();

        const bridge = await ethers.deployContract("TEENetBtcBridge", [pk, feeAccount, 10]);

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
            const twbtc = await ethers.getContractAt("TWBTC", twbtcAddr);

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

            const bip340 = await ethers.getContractAt("Bip340Ecrec", await bridge.bip340());

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

            const fee = await bridge.fee();
            const feeAccount = await bridge.feeAccount();

            const receiver = hexlify(randomBytes(20));
            const amount = 100n;
            const btcTxId = hexlify(randomBytes(32));
            const encode = ethers.solidityPacked(['bytes32', 'address', 'uint256'], [btcTxId, receiver, amount]);
            const msg = ethers.keccak256(encode);
            const aux = randomBuffer(32);
            const { rx, s } = sign(Buffer.from(msg.substring(2), 'hex'), aux);

            await expect(bridge.mint(btcTxId, receiver, amount, rx, s))
                .to.emit(bridge, 'Minted')
                .withArgs(btcTxId, getAddress(receiver), amount - fee);

            const twbtc = await ethers.getContractAt("TWBTC", await bridge.twbtc());

            expect(await twbtc.balanceOf(receiver)).to.equal(BigInt(amount) - fee);
            expect(await twbtc.balanceOf(feeAccount)).to.equal(fee);
        });
        it('should revert if receiver is zero address', async () => {
            const { bridge } = await loadFixture(deployBridge);

            const receiver = '0x' + '0'.repeat(40);
            const amount = 100;
            const btcTxId = hexlify(randomBytes(32));
            const rx = hexlify(randomBytes(32));
            const s = hexlify(randomBytes(32));

            await expect(bridge.mint(btcTxId, receiver, amount, rx, s))
                .to.be.revertedWithCustomError(bridge, 'ZeroEthAddress');
        });

        it('should revert if amount is no larger than fee', async () => {
            const { bridge } = await loadFixture(deployBridge);

            const receiver = hexlify(randomBytes(20));
            const amount = 5;
            const btcTxId = hexlify(randomBytes(32));
            const rx = hexlify(randomBytes(32));
            const s = hexlify(randomBytes(32));

            await expect(bridge.mint(btcTxId, receiver, amount, rx, s))
                .to.be.revertedWithCustomError(bridge, 'InsufficientAmount');
        });

        it('should revert if signature is invalid', async () => {
            const { bridge } = await loadFixture(deployBridge);

            const receiver = ethers.getAddress(hexlify(randomBytes(20)));
            const amount = 100;
            const btcTxId = hexlify(randomBytes(32));
            const msg = ethers.keccak256(ethers.solidityPacked(['bytes32', 'address', 'uint256'], [btcTxId, receiver, amount]));

            const aux = randomBuffer(32);
            const { rx, s } = sign(Buffer.from(msg.substring(2), 'hex'), aux);

            // modifiedS = s + 1
            const modifiedS = '0x' + (BigInt(s) + 1n).toString(16);

            const bip340 = await ethers.deployContract("Bip340Ecrec");
            expect(await bip340.verify(pk, rx, s, msg)).to.equal(true);

            await expect(bridge.mint(btcTxId, receiver, amount, rx, modifiedS))
                .to.be.revertedWithCustomError(bridge, 'InvalidSchnorrSignature')
                .withArgs(btcTxId, receiver, amount, rx, modifiedS);
        });
        it('should revert if the same btcTxId is used twice', async () => {
            const { bridge } = await loadFixture(deployBridge);

            const fee = await bridge.fee();

            const receiver = hexlify(randomBytes(20));
            const amount = 100n;
            const btcTxId = hexlify(randomBytes(32));
            const msg = ethers.keccak256(ethers.solidityPacked(
                ['bytes32', 'address', 'uint256'], [btcTxId, receiver, amount]));
            const aux = randomBuffer(32);
            const { rx, s } = sign(Buffer.from(msg.substring(2), 'hex'), aux);

            await expect(bridge.mint(btcTxId, receiver, amount, rx, s))
                .to.emit(bridge, 'Minted')
                .withArgs(btcTxId, getAddress(receiver), amount - fee);

            await expect(bridge.mint(btcTxId, receiver, amount, rx, s))
                .to.be.revertedWithCustomError(bridge, 'AlreadyMinted')
                .withArgs(btcTxId);
        });
    });

    describe("Redeem", function () {
        describe("Request", function () {
            it('should emit RedeemRequested event', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const twbtcAddr = await bridge.twbtc();
                const twbtc = await ethers.getContractAt("TWBTC", twbtcAddr);

                const fee = await bridge.fee();
                const feeAccount = await bridge.feeAccount();

                const receiver = await ethers.provider.getSigner(9);
                const mintAmount = 100n;
                const btcTxId = hexlify(randomBytes(32));
                const msg = ethers.keccak256(ethers.solidityPacked(
                    ['bytes32', 'address', 'uint256'], [btcTxId, receiver.address, mintAmount]));
                const aux = randomBuffer(32);
                const { rx, s } = sign(Buffer.from(msg.substring(2), 'hex'), aux);

                // Mint some TWBTC tokens
                await expect(bridge.mint(btcTxId, receiver, mintAmount, rx, s))
                    .to.emit(bridge, 'Minted')
                    .withArgs(btcTxId, receiver.address, mintAmount - fee);
                await expect(twbtc.balanceOf(receiver.address)).to.eventually.equal(mintAmount - fee);
                await expect(twbtc.balanceOf(feeAccount)).to.eventually.equal(fee);

                // Approve the bridge to spend the minted tokens
                await expect(twbtc.connect(receiver).approve(await bridge.getAddress(), mintAmount))
                    .to.emit(twbtc, 'Approval')
                    .withArgs(receiver.address, await bridge.getAddress(), mintAmount);

                const originalBalance = mintAmount - fee;
                const redeemAmount = 80n;
                const btcAddress = '34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo';

                // Request redeem
                await expect(bridge.connect(receiver).redeemRequest(redeemAmount, btcAddress))
                    .to.emit(bridge, 'RedeemRequested')
                    .withArgs(receiver.address, redeemAmount, btcAddress);

                expect(await twbtc.balanceOf(receiver.address)).to.equal(originalBalance - redeemAmount);
                expect(await twbtc.balanceOf(feeAccount)).to.equal(2n * fee);
            });
            it('should revert if amount is zero', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const fee = await bridge.fee();

                const btcAddress = '34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo';

                await expect(bridge.redeemRequest(fee, btcAddress))
                    .to.be.revertedWithCustomError(bridge, 'InsufficientAmount');
            });

            it('should revert if sender has insufficient balance', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const signer = await ethers.provider.getSigner(9);

                const amount = 100;
                const btcAddress = '34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo';

                await expect(bridge.connect(signer).redeemRequest(amount, btcAddress))
                    .to.be.reverted;
            });
        });
        describe("Prepare", function () {
            it('should emit RedeemPrepared event', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const signer = await ethers.provider.getSigner(9);

                const redeemRequestTxHash = hexlify(randomBytes(32));
                const requester = signer.address;
                const receiver = 'bc1qh2a5n8u9429seg9pu3x2te89z9yxk3pmxxc47z';
                const redeemAmount = 100;
                const outpointTxIds = [hexlify(randomBytes(32)), hexlify(randomBytes(32))];
                const outpointIdxs = [0, 4];

                const prepareMsg = ethers.solidityPacked(
                    ['bytes32', 'address', 'string', 'uint256', 'bytes32[]', 'uint16[]'],
                    [redeemRequestTxHash, requester, receiver, redeemAmount, outpointTxIds, outpointIdxs]);

                const signingHash = ethers.keccak256(prepareMsg);
                const aux2 = randomBuffer(32);
                const sig2 = sign(Buffer.from(signingHash.substring(2), 'hex'), aux2);

                await expect(bridge.connect(signer)
                    .redeemPrepare(
                        redeemRequestTxHash, requester, receiver, redeemAmount,
                        outpointTxIds, outpointIdxs,
                        sig2.rx, sig2.s
                    ))
                    .to.emit(bridge, 'RedeemPrepared')
                    .withArgs(redeemRequestTxHash, requester, receiver, redeemAmount, outpointTxIds, outpointIdxs);
            });
            it('should revert if requester is zero address', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const redeemRequestTxHash = hexlify(randomBytes(32));
                const requester = '0x' + '0'.repeat(40);
                const receiver = 'bc1qh2a5n8u9429seg9pu3x2te89z9yxk3pmxxc47z';
                const amount = 100;
                const rx = hexlify(randomBytes(32));
                const s = hexlify(randomBytes(32));

                await expect(bridge.redeemPrepare(
                    redeemRequestTxHash, requester, receiver, amount, [], [], rx, s)
                ).to.be.revertedWithCustomError(bridge, 'ZeroEthAddress');
            });
            it('should revert if receiver is empty', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const redeemRequestTxHash = hexlify(randomBytes(32));
                const requester = hexlify(randomBytes(20));
                const receiver = '';
                const amount = 100;

                const rx = hexlify(randomBytes(32));
                const s = hexlify(randomBytes(32));

                await expect(bridge.redeemPrepare(
                    redeemRequestTxHash, requester, receiver, amount, [], [], rx, s)
                ).to.be.revertedWithCustomError(bridge, 'EmptyString');
            });
            it('should revert if amount is zero', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const redeemRequestTxHash = hexlify(randomBytes(32));
                const requester = hexlify(randomBytes(20));
                const receiver = 'bc1qh2a5n8u9429seg9pu3x2te89z9yxk3pmxxc47z';
                const amount = 0;
                const rx = hexlify(randomBytes(32));
                const s = hexlify(randomBytes(32));

                await expect(bridge.redeemPrepare(
                    redeemRequestTxHash, requester, receiver, amount, [], [], rx, s)
                ).to.be.revertedWithCustomError(bridge, 'ZeroAmount');
            });

            it('should revert if outpointTxIds is empty', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const redeemRequestTxHash = hexlify(randomBytes(32));
                const requester = hexlify(randomBytes(20));
                const receiver = 'bc1qh2a5n8u9429seg9pu3x2te89z9yxk3pmxxc47z';
                const amount = 100;
                const rx = hexlify(randomBytes(32));
                const s = hexlify(randomBytes(32));

                await expect(bridge.redeemPrepare(
                    redeemRequestTxHash, requester, receiver, amount, [], [0], rx, s)
                ).to.be.revertedWithCustomError(bridge, 'EmptyOutpointTxIds');
            });

            it('should revert if outpointIdxs is empty', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const redeemRequestTxHash = hexlify(randomBytes(32));
                const requester = hexlify(randomBytes(20));
                const receiver = 'bc1qh2a5n8u9429seg9pu3x2te89z9yxk3pmxxc47z';
                const amount = 100;
                const rx = hexlify(randomBytes(32));
                const s = hexlify(randomBytes(32));

                await expect(bridge.redeemPrepare(
                    redeemRequestTxHash, requester, receiver, amount, [hexlify(randomBytes(32))], [], rx, s)
                ).to.be.revertedWithCustomError(bridge, 'EmptyOutpointIdxs');
            });

            it('should revert if outpointTxIds and outpointIdxs have different lengths', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const redeemRequestTxHash = hexlify(randomBytes(32));
                const requester = hexlify(randomBytes(20));
                const receiver = 'bc1qh2a5n8u9429seg9pu3x2te89z9yxk3pmxxc47z';
                const amount = 100;
                const rx = hexlify(randomBytes(32));
                const s = hexlify(randomBytes(32));

                const outpointTxIds = [hexlify(randomBytes(32)), hexlify(randomBytes(32))];
                const outpointIdxs = [0];

                await expect(bridge.redeemPrepare(
                    redeemRequestTxHash, requester, receiver, amount, outpointTxIds, outpointIdxs, rx, s)
                ).to.be.revertedWithCustomError(bridge, 'OutpointTxIdsAndOutpointIdxsLengthMismatch');
            });

            it('should revert if there is any zero outpointTxId', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const redeemRequestTxHash = hexlify(randomBytes(32));
                const requester = hexlify(randomBytes(20));
                const receiver = 'bc1qh2a5n8u9429seg9pu3x2te89z9yxk3pmxxc47z';
                const amount = 100;
                const rx = hexlify(randomBytes(32));
                const s = hexlify(randomBytes(32));

                const outpointTxIds = [hexlify(randomBytes(32)), '0x' + '0'.repeat(64)];
                const outpointIdxs = [0, 4];

                await expect(bridge.redeemPrepare(
                    redeemRequestTxHash, requester, receiver, amount, outpointTxIds, outpointIdxs, rx, s)
                ).to.be.revertedWithCustomError(bridge, 'ZeroOutpointTxId');
            });

            it('should revert if a redeem request has already been prepared', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const signer = await ethers.provider.getSigner(9);

                const redeemRequestTxHash = hexlify(randomBytes(32));
                const requester = signer.address;
                const receiver = 'bc1qh2a5n8u9429seg9pu3x2te89z9yxk3pmxxc47z';
                const redeemAmount = 100;
                const outpointTxIds = [hexlify(randomBytes(32)), hexlify(randomBytes(32))];
                const outpointIdxs = [0, 4];

                const prepareMsg = ethers.keccak256(ethers.solidityPacked(
                    ['bytes32', 'address', 'string', 'uint256', 'bytes32[]', 'uint16[]'],
                    [redeemRequestTxHash, requester, receiver, redeemAmount, outpointTxIds, outpointIdxs])
                );
                const aux2 = randomBuffer(32);
                const sig2 = sign(Buffer.from(prepareMsg.substring(2), 'hex'), aux2);

                await expect(bridge.connect(signer)
                    .redeemPrepare(
                        redeemRequestTxHash, requester, receiver, redeemAmount,
                        outpointTxIds, outpointIdxs,
                        sig2.rx, sig2.s
                    ))
                    .to.emit(bridge, 'RedeemPrepared')
                    .withArgs(redeemRequestTxHash, requester, receiver, redeemAmount, outpointTxIds, outpointIdxs);

                await expect(bridge.connect(signer)
                    .redeemPrepare(
                        redeemRequestTxHash, requester, receiver, redeemAmount,
                        outpointTxIds, outpointIdxs,
                        sig2.rx, sig2.s
                    ))
                    .to.be.revertedWithCustomError(bridge, 'AlreadyPrepared')
                    .withArgs(redeemRequestTxHash);
            });

            it('should revert if btcTxId is already used for prepare a redeem', async () => {
                const { bridge } = await loadFixture(deployBridge);

                const signer = await ethers.provider.getSigner(9);

                let redeemRequestTxHash = hexlify(randomBytes(32));
                let requester = signer.address;
                let receiver = 'bc1qh2a5n8u9429seg9pu3x2te89z9yxk3pmxxc47z';
                let redeemAmount = 100;
                let outpointTxIds = [hexlify(randomBytes(32)), hexlify(randomBytes(32))];
                let outpointIdxs = [0, 4];

                let prepareMsg = ethers.keccak256(ethers.solidityPacked(
                    ['bytes32', 'address', 'string', 'uint256', 'bytes32[]', 'uint16[]'],
                    [redeemRequestTxHash, requester, receiver, redeemAmount, outpointTxIds, outpointIdxs])
                );
                let aux = randomBuffer(32);
                let sig = sign(Buffer.from(prepareMsg.substring(2), 'hex'), aux);

                await expect(bridge.connect(signer)
                    .redeemPrepare(
                        redeemRequestTxHash, requester, receiver, redeemAmount,
                        outpointTxIds, outpointIdxs,
                        sig.rx, sig.s
                    ))
                    .to.emit(bridge, 'RedeemPrepared')
                    .withArgs(redeemRequestTxHash, requester, receiver, redeemAmount, outpointTxIds, outpointIdxs);

                for (let i = 0; i < outpointIdxs.length; i++) {
                    expect(await bridge.isUsed(outpointTxIds[i])).to.be.true;
                }

                await expect(bridge.connect(signer)
                    .redeemPrepare(
                        hexlify(randomBytes(32)), requester, receiver, redeemAmount,
                        [hexlify(randomBytes(32)), outpointTxIds[1]], outpointIdxs,
                        hexlify(randomBytes(32)), hexlify(randomBytes(32))
                    ))
                    .to.be.revertedWithCustomError(bridge, 'BtcTxIdAlreadyUsed')
                    .withArgs(outpointTxIds[1]);
            });
        });
    });
});