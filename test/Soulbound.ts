import { time, loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { expect } from "chai";
import { ethers } from "hardhat";

enum BurnAuth {
  IssuerOnly,
  OwnerOnly,
  Both,
  Neither
}

describe("Soulbound", function () {
  // We define a fixture to reuse the same setup in every test.
  // We use loadFixture to run this setup once, snapshot that state,
  // and reset Hardhat Network to that snapshot in every test.
  async function deploySoulboundFixture() {
    // Contracts are deployed using the first signer/account by default
    const [owner, addr1, addr2, addr3] = await ethers.getSigners();

    const burnAuth = BurnAuth.Both;

    const Soulbound = await ethers.getContractFactory("Soulbound");
    const soulbound = await Soulbound.deploy();

    return { soulbound, burnAuth, owner, addr1, addr2, addr3 };
  }

  xdescribe("Deployment", function () {
    it("Should set the right burnAuth rule", async function () {
      const { soulbound, burnAuth } = await loadFixture(deploySoulboundFixture);

      expect(await soulbound.burnAuth()).to.equal(burnAuth);
    });

    it("Should set the right owner", async function () {
      const { soulbound, owner } = await loadFixture(deploySoulboundFixture);

      expect(await soulbound.owner()).to.equal(owner.address);
    });

    it("Should fail if the burnAuth is not valid", async function () {
      const burnAuth = 4; // NOTE: 4 should be outside of the BurnAuth enum.
      const Soulbound = await ethers.getContractFactory("Soulbound");
      await expect(Soulbound.deploy(burnAuth)).to.be.reverted;
    });
  });

  describe("Claiming", function () {
    it("Should only allow the signer to claim a token", async function () {
      const { soulbound, addr1, addr2 } = await loadFixture(deploySoulboundFixture);

      let messageHash = ethers.utils.solidityKeccak256(
        ["address"],
        [addr1.address]
      );

      let messageHashBinary = ethers.utils.arrayify(messageHash);

      let signature = await addr1.signMessage(messageHashBinary);

      const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));

      const tokenCreationData = {
        boe: true,
        eventId,
        _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
        from: addr1.address,
        limit: 2,
        signature,
        toAddr: [],
        toCode: [],
        _tokenURI: '12345',
      }

      await soulbound.connect(addr2).createToken(tokenCreationData);

      await expect(soulbound.connect(addr2).claimToken(eventId, addr1.address, signature)).to.emit(soulbound, 'TokenClaim').withArgs(eventId, 1);
    });
  });

  describe("Create", function () {

    describe("createToken", function () {
      it("Should create a token with a limit", async function () {
        const { soulbound, addr1, addr2 } = await loadFixture(deploySoulboundFixture);

        let messageHash = ethers.utils.solidityKeccak256(
          ["address"],
          [addr1.address]
        );

        let messageHashBinary = ethers.utils.arrayify(messageHash);

        let signature = await addr1.signMessage(messageHashBinary);

        const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));

        const tokenCreationData = {
          boe: true,
          eventId,
          _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
          from: addr1.address,
          limit: 2,
          signature,
          toAddr: [],
          toCode: [],
          _tokenURI: '12345',
        }

        await soulbound.connect(addr2).createToken(tokenCreationData);

        const token = await soulbound.createdTokens(eventId);
        expect(token.owner).to.equal(addr1.address);
      });
    });

    describe("createTokenFromAddresses", function () {
      it("Should create a token with pre issued addresses", async function () {
        const { soulbound, addr1, addr2, addr3 } = await loadFixture(deploySoulboundFixture);

        let messageHash = ethers.utils.solidityKeccak256(
          ["address"],
          [addr1.address]
        );

        let messageHashBinary = ethers.utils.arrayify(messageHash);

        let signature = await addr1.signMessage(messageHashBinary);

        const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));

        const tokenCreationData = {
          boe: true,
          eventId,
          _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
          from: addr1.address,
          limit: 2,
          signature,
          toAddr: [addr2.address, addr3.address],
          toCode: [],
          _tokenURI: '12345',
        }

        await soulbound.connect(addr2).createTokenFromAddresses(tokenCreationData);

        const token = await soulbound.createdTokens(eventId);
        expect(token.owner).to.equal(addr1.address);
      });
    });

    describe("createTokenFromCode", function () {
      it("Should create a token with pre issued codes", async function () {
        const { soulbound, addr1, addr2, addr3 } = await loadFixture(deploySoulboundFixture);

        let messageHash = ethers.utils.solidityKeccak256(
          ["address"],
          [addr1.address]
        );

        let messageHashBinary = ethers.utils.arrayify(messageHash);

        let signature = await addr1.signMessage(messageHashBinary);

        const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));
        const code1 = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234567'));
        const code2 = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('75674'));

        const tokenCreationData = {
          boe: true,
          eventId,
          _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
          from: addr1.address,
          limit: 2,
          signature,
          toAddr: [],
          toCode: [code1, code2],
          _tokenURI: '12345',
        }

        await soulbound.connect(addr2).createTokenFromCode(tokenCreationData);

        const token = await soulbound.createdTokens(eventId);
        expect(token.owner).to.equal(addr1.address);
        expect(await soulbound.issuedCodeTokens(code1)).to.equal(eventId);
        expect(await soulbound.issuedCodeTokens(code2)).to.equal(eventId);
      });
    });

    describe("createTokenFromBoth", function () {
      it("Should create a token with both pre issued codes and addresses", async function () {
        const { soulbound, addr1, addr2 } = await loadFixture(deploySoulboundFixture);

        let messageHash = ethers.utils.solidityKeccak256(
          ["address"],
          [addr1.address]
        );
        let messageHashBinary = ethers.utils.arrayify(messageHash);
        let signature = await addr1.signMessage(messageHashBinary);
        const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));


        const code1 = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234567'));
        const code2 = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('75674'));

        const tokenCreationData = {
          boe: true,
          eventId,
          _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
          from: addr1.address,
          limit: 2,
          signature,
          toAddr: [addr1.address, addr2.address],
          toCode: [code1, code2],
          _tokenURI: '12345',
        }

        await soulbound.connect(addr2).createTokenFromBoth(tokenCreationData);

        const token = await soulbound.createdTokens(eventId);
        expect(token.owner).to.equal(addr1.address);
        expect(await soulbound.issuedCodeTokens(code1)).to.equal(eventId);
        expect(await soulbound.issuedCodeTokens(code2)).to.equal(eventId);
        expect(await soulbound.issuedTokens(eventId, addr1.address)).to.equal(true);
        expect(await soulbound.issuedTokens(eventId, addr2.address)).to.equal(true);
      });
    });
  });

  describe("BoE", function () {
    it("Allow users to create a BoE token", async function () {
      const { soulbound, addr1, addr2 } = await loadFixture(deploySoulboundFixture);

      let messageHash = ethers.utils.solidityKeccak256(
        ["address"],
        [addr1.address]
      );

      let messageHashBinary = ethers.utils.arrayify(messageHash);

      let signature = await addr1.signMessage(messageHashBinary);

      const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));

      const tokenCreationData = {
        boe: true,
        eventId,
        _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
        from: addr1.address,
        limit: 2,
        signature,
        toAddr: [],
        toCode: [],
        _tokenURI: '12345',
      }

      await soulbound.connect(addr2).createToken(tokenCreationData);
      const token = await soulbound.createdTokens(eventId);
      expect(token.boe).to.equal(true);
    });

    it("Allow the owner of a BoE token to transfer it", async function () {
      const { soulbound, addr1, addr2, addr3 } = await loadFixture(deploySoulboundFixture);

      let messageHash = ethers.utils.solidityKeccak256(
        ["address"],
        [addr1.address]
      );

      let messageHashBinary = ethers.utils.arrayify(messageHash);

      let signature = await addr1.signMessage(messageHashBinary);

      const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));

      const tokenCreationData = {
        boe: true,
        eventId,
        _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
        from: addr1.address,
        limit: 2,
        signature,
        toAddr: [],
        toCode: [],
        _tokenURI: '12345',
      }

      // Create token
      await soulbound.connect(addr2).createToken(tokenCreationData);

      // Claim token
      messageHash = ethers.utils.solidityKeccak256(
        ["address"],
        [addr3.address]
      );
      messageHashBinary = ethers.utils.arrayify(messageHash);
      signature = await addr3.signMessage(messageHashBinary);
      await soulbound.connect(addr2).claimToken(eventId, addr3.address, signature)
      // Verify current owner
      expect(await soulbound.ownerOf(1)).to.equal(addr3.address);
      // Connect to owners address and transfer token owenership
      await soulbound.connect(addr3).transferFrom(addr3.address, addr2.address, 1);
      // Verify new owner
      expect(await soulbound.ownerOf(1)).to.equal(addr2.address);
    });

    it("Allow the owner of of BoE token to claim and bind it and not transfer it", async function () {
      const { soulbound, addr1, addr2, addr3 } = await loadFixture(deploySoulboundFixture);

      let messageHash = ethers.utils.solidityKeccak256(
        ["address"],
        [addr1.address]
      );

      let messageHashBinary = ethers.utils.arrayify(messageHash);

      let signature = await addr1.signMessage(messageHashBinary);

      const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));

      const tokenCreationData = {
        boe: true,
        eventId,
        _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
        from: addr1.address,
        limit: 2,
        signature,
        toAddr: [],
        toCode: [],
        _tokenURI: '12345',
      }

      // Create token
      await soulbound.connect(addr2).createToken(tokenCreationData);
      // Claim token
      messageHash = ethers.utils.solidityKeccak256(
        ["address"],
        [addr3.address]
      );
      messageHashBinary = ethers.utils.arrayify(messageHash);
      signature = await addr3.signMessage(messageHashBinary);
      await soulbound.connect(addr2).claimToken(eventId, addr3.address, signature);
      // Verify current owner
      expect(await soulbound.ownerOf(1)).to.equal(addr3.address);
      // Transfer token ownership
      await soulbound.connect(addr3).transferFrom(addr3.address, addr2.address, 1);
      // Verify new owner
      expect(await soulbound.ownerOf(1)).to.equal(addr2.address);
      // New owner soulbinds token
      messageHash = ethers.utils.solidityKeccak256(
        ["address"],
        [addr2.address]
      );
      messageHashBinary = ethers.utils.arrayify(messageHash);
      signature = await addr2.signMessage(messageHashBinary);
      await soulbound.soulbind(1, addr2.address, signature);
      // Verify that token is bound
      expect(await soulbound.isBoe(1)).to.equal(false);
      // Verify they may not transfer token
      await expect(soulbound.connect(addr2).transferFrom(addr2.address, addr1.address, 1)).to.revertedWith('This token is soulbound and cannot be transfered');
    });
  })



  describe("Burning", function () {

    describe("IssuerOnly", function () {
      it("Should only burn if issuer requests it", async function () {
      });
    });
    describe("OwnerOnly", function () {
      it("Should only burn if owner requests it", async function () {

      });
    });
    describe("Both", function () {
      it("Should burn for either owner or issuer", async function () {
        const { soulbound, addr1, addr2, addr3 } = await loadFixture(deploySoulboundFixture);

        let messageHash = ethers.utils.solidityKeccak256(
          ["address"],
          [addr1.address]
        );

        let messageHashBinary = ethers.utils.arrayify(messageHash);

        let signature = await addr1.signMessage(messageHashBinary);

        const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));

        const tokenCreationData = {
          boe: true,
          eventId,
          _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
          from: addr1.address,
          limit: 2,
          signature,
          toAddr: [],
          toCode: [],
          _tokenURI: '12345',
        }

        tokenCreationData._burnAuth

        // Create token
        await soulbound.connect(addr2).createToken(tokenCreationData);
        // Claim token
        messageHash = ethers.utils.solidityKeccak256(
          ["address"],
          [addr3.address]
        );
        messageHashBinary = ethers.utils.arrayify(messageHash);
        signature = await addr3.signMessage(messageHashBinary);
        await soulbound.connect(addr2).claimToken(eventId, addr3.address, signature);

        expect(await soulbound.ownerOf(1)).to.equal(addr3.address);

        await soulbound.connect(addr2).burnToken(1, eventId, addr3.address, signature);

        await expect(soulbound.ownerOf(1)).to.revertedWith('ERC721: invalid token ID');
      });
    });
    describe("Neither", function () {
      it("Should never burn", async function () {

      });
    });
  });
});
