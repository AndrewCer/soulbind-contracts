import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { randomBytes } from 'crypto';
import { expect } from "chai";
import { ethers } from "hardhat";

enum BurnAuth {
  IssuerOnly,
  OwnerOnly,
  Both,
  Neither
}

describe("Soulbind", function () {
  // We define a fixture to reuse the same setup in every test.
  // We use loadFixture to run this setup once, snapshot that state,
  // and reset Hardhat Network to that snapshot in every test.
  async function deploySoulbindFixture() {
    // Contracts are deployed using the first signer/account by default
    const [owner, addr1, addr2, addr3] = await ethers.getSigners();

    const burnAuth = BurnAuth.Both;

    const Soulbind = await ethers.getContractFactory("Soulbind");
    const soulbind = await Soulbind.deploy();

    return { soulbind, burnAuth, owner, addr1, addr2, addr3 };
  }

  describe("Claiming", function () {
    it("Should only allow the signer to claim a token", async function () {
      const { soulbind, addr1, addr2 } = await loadFixture(deploySoulbindFixture);

      const randomValues = randomBytes(32).toString("base64");
      const rawMessage = `Signing confirms that you own this address:\n${addr1.address}\n~~Security~~\nTimestamp: ${Date.now()}\nNonce: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(randomValues))}`;
      const message = `${rawMessage}\nHash: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(rawMessage))}`;
      const msgHash = ethers.utils.hashMessage(message);

      let signature = await addr1.signMessage(message);

      const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));

      const tokenCreationData = {
        boe: true,
        eventId,
        _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
        from: addr1.address,
        limit: 2,
        msgHash,
        signature,
        toAddr: [],
        toCode: [],
        updatable: false,
        _tokenURI: '12345',
      }

      await soulbind.connect(addr2).createToken(tokenCreationData);

      await expect(soulbind.connect(addr2).claimToken(eventId, addr1.address, signature, msgHash)).to.emit(soulbind, 'TokenClaim').withArgs(eventId, 1);
    });
  });

  describe("Create", function () {

    describe("createToken", function () {
      it("Should create a token with a limit", async function () {
        const { soulbind, addr1, addr2 } = await loadFixture(deploySoulbindFixture);

        const randomValues = randomBytes(32).toString("base64");
        const rawMessage = `Signing confirms that you own this address:\n${addr1.address}\n~~Security~~\nTimestamp: ${Date.now()}\nNonce: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(randomValues))}`;
        const message = `${rawMessage}\nHash: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(rawMessage))}`;
        const msgHash = ethers.utils.hashMessage(message);

        let signature = await addr1.signMessage(message);

        const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));

        const tokenCreationData = {
          boe: true,
          eventId,
          _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
          from: addr1.address,
          limit: 2,
          msgHash,
          signature,
          toAddr: [],
          toCode: [],
          updatable: false,
          _tokenURI: '12345',
        }

        await soulbind.connect(addr2).createToken(tokenCreationData);

        const token = await soulbind.createdTokens(eventId);
        expect(token.owner).to.equal(addr1.address);
      });
    });

    describe("createTokenFromAddresses", function () {
      it("Should create a token with pre issued addresses", async function () {
        const { soulbind, addr1, addr2, addr3 } = await loadFixture(deploySoulbindFixture);

        const randomValues = randomBytes(32).toString("base64");
        const rawMessage = `Signing confirms that you own this address:\n${addr1.address}\n~~Security~~\nTimestamp: ${Date.now()}\nNonce: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(randomValues))}`;
        const message = `${rawMessage}\nHash: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(rawMessage))}`;
        const msgHash = ethers.utils.hashMessage(message);

        let signature = await addr1.signMessage(message);

        const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));

        const tokenCreationData = {
          boe: true,
          eventId,
          _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
          from: addr1.address,
          limit: 2,
          msgHash,
          signature,
          toAddr: [addr2.address, addr3.address],
          toCode: [],
          updatable: false,
          _tokenURI: '12345',
        }

        await soulbind.connect(addr2).createTokenFromAddresses(tokenCreationData);

        const token = await soulbind.createdTokens(eventId);
        expect(token.owner).to.equal(addr1.address);
      });
    });

    describe("createTokenFromCode", function () {
      it("Should create a token with pre issued codes", async function () {
        const { soulbind, addr1, addr2, addr3 } = await loadFixture(deploySoulbindFixture);

        const randomValues = randomBytes(32).toString("base64");
        const rawMessage = `Signing confirms that you own this address:\n${addr1.address}\n~~Security~~\nTimestamp: ${Date.now()}\nNonce: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(randomValues))}`;
        const message = `${rawMessage}\nHash: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(rawMessage))}`;
        const msgHash = ethers.utils.hashMessage(message);

        let signature = await addr1.signMessage(message);

        const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));
        const code1 = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234567'));
        const code2 = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('75674'));

        const tokenCreationData = {
          boe: true,
          eventId,
          _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
          from: addr1.address,
          limit: 2,
          msgHash,
          signature,
          toAddr: [],
          toCode: [code1, code2],
          updatable: false,
          _tokenURI: '12345',
        }

        await soulbind.connect(addr2).createTokenFromCode(tokenCreationData);

        const token = await soulbind.createdTokens(eventId);
        expect(token.owner).to.equal(addr1.address);
        expect(await soulbind.issuedCodeTokens(code1)).to.equal(eventId);
        expect(await soulbind.issuedCodeTokens(code2)).to.equal(eventId);
      });
    });

    describe("createTokenFromBoth", function () {
      it("Should create a token with both pre issued codes and addresses", async function () {
        const { soulbind, addr1, addr2 } = await loadFixture(deploySoulbindFixture);

        const randomValues = randomBytes(32).toString("base64");
        const rawMessage = `Signing confirms that you own this address:\n${addr1.address}\n~~Security~~\nTimestamp: ${Date.now()}\nNonce: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(randomValues))}`;
        const message = `${rawMessage}\nHash: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(rawMessage))}`;
        const msgHash = ethers.utils.hashMessage(message);

        let signature = await addr1.signMessage(message);
        const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));


        const code1 = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234567'));
        const code2 = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('75674'));

        const tokenCreationData = {
          boe: true,
          eventId,
          _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
          from: addr1.address,
          limit: 2,
          msgHash,
          signature,
          toAddr: [addr1.address, addr2.address],
          toCode: [code1, code2],
          updatable: false,
          _tokenURI: '12345',
        }

        await soulbind.connect(addr2).createTokenFromBoth(tokenCreationData);

        const token = await soulbind.createdTokens(eventId);
        expect(token.owner).to.equal(addr1.address);
        expect(await soulbind.issuedCodeTokens(code1)).to.equal(eventId);
        expect(await soulbind.issuedCodeTokens(code2)).to.equal(eventId);
        expect(await soulbind.issuedTokens(eventId, addr1.address)).to.equal(true);
        expect(await soulbind.issuedTokens(eventId, addr2.address)).to.equal(true);
      });
    });
  });

  describe("Update", function () {
    it("should allow a single tokens to be updated", async function () {
      const { soulbind, addr1, addr2 } = await loadFixture(deploySoulbindFixture);

      const randomValues = randomBytes(32).toString("base64");
      const rawMessage = `Signing confirms that you own this address:\n${addr1.address}\n~~Security~~\nTimestamp: ${Date.now()}\nNonce: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(randomValues))}`;
      const message = `${rawMessage}\nHash: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(rawMessage))}`;
      const msgHash = ethers.utils.hashMessage(message);

      let signature = await addr1.signMessage(message);

      const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));

      const tokenCreationData = {
        boe: true,
        eventId,
        _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
        from: addr1.address,
        limit: 2,
        msgHash,
        signature,
        toAddr: [],
        toCode: [],
        updatable: true,
        _tokenURI: '12345',
      }

      await soulbind.connect(addr2).createToken(tokenCreationData);
      await soulbind.connect(addr2).claimToken(eventId, addr1.address, signature, msgHash);

      const newTokenURI = '54321';

      await soulbind.connect(addr2).updateTokenURI(1, eventId, newTokenURI, addr1.address, signature, msgHash);

      const createdToken = await soulbind.createdTokens(eventId);
      const tokenURI = await soulbind.tokenURI(1);

      expect(tokenURI).to.equal(newTokenURI);
    });

    it("should not update the root token event", async function () {
      const { soulbind, addr1, addr2 } = await loadFixture(deploySoulbindFixture);

      const randomValues = randomBytes(32).toString("base64");
      const rawMessage = `Signing confirms that you own this address:\n${addr1.address}\n~~Security~~\nTimestamp: ${Date.now()}\nNonce: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(randomValues))}`;
      const message = `${rawMessage}\nHash: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(rawMessage))}`;
      const msgHash = ethers.utils.hashMessage(message);

      let signature = await addr1.signMessage(message);

      const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));

      const tokenCreationData = {
        boe: true,
        eventId,
        _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
        from: addr1.address,
        limit: 2,
        msgHash,
        signature,
        toAddr: [],
        toCode: [],
        updatable: true,
        _tokenURI: '12345',
      }

      await soulbind.connect(addr2).createToken(tokenCreationData);
      await soulbind.connect(addr2).claimToken(eventId, addr1.address, signature, msgHash);

      const newTokenURI = '54321';

      await soulbind.connect(addr2).updateTokenURI(1, eventId, newTokenURI, addr1.address, signature, msgHash);

      const createdToken = await soulbind.createdTokens(eventId);

      expect(createdToken.uri).to.equal('12345');
    });

    it("should not allow an update of an non updatable token", async function () {
      const { soulbind, addr1, addr2 } = await loadFixture(deploySoulbindFixture);

      const randomValues = randomBytes(32).toString("base64");
      const rawMessage = `Signing confirms that you own this address:\n${addr1.address}\n~~Security~~\nTimestamp: ${Date.now()}\nNonce: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(randomValues))}`;
      const message = `${rawMessage}\nHash: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(rawMessage))}`;
      const msgHash = ethers.utils.hashMessage(message);

      let signature = await addr1.signMessage(message);

      const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));

      const tokenCreationData = {
        boe: true,
        eventId,
        _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
        from: addr1.address,
        limit: 2,
        msgHash,
        signature,
        toAddr: [],
        toCode: [],
        updatable: false,
        _tokenURI: '12345',
      }

      await soulbind.connect(addr2).createToken(tokenCreationData);
      await soulbind.connect(addr2).claimToken(eventId, addr1.address, signature, msgHash);

      const newTokenURI = '54321';

      await expect(soulbind.connect(addr2).updateTokenURI(1, eventId, newTokenURI, addr1.address, signature, msgHash)).to.revertedWith('Not updatable');
    });
  });

  describe("BoE", function () {
    it("Allow users to create a BoE token", async function () {
      const { soulbind, addr1, addr2 } = await loadFixture(deploySoulbindFixture);

      const randomValues = randomBytes(32).toString("base64");
      const rawMessage = `Signing confirms that you own this address:\n${addr1.address}\n~~Security~~\nTimestamp: ${Date.now()}\nNonce: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(randomValues))}`;
      const message = `${rawMessage}\nHash: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(rawMessage))}`;
      const msgHash = ethers.utils.hashMessage(message);

      let signature = await addr1.signMessage(message);

      const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));

      const tokenCreationData = {
        boe: true,
        eventId,
        _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
        from: addr1.address,
        limit: 2,
        msgHash,
        signature,
        toAddr: [],
        toCode: [],
        updatable: false,
        _tokenURI: '12345',
      }

      await soulbind.connect(addr2).createToken(tokenCreationData);
      const token = await soulbind.createdTokens(eventId);
      expect(token.boe).to.equal(true);
    });

    it("Allow the owner of a BoE token to transfer it", async function () {
      const { soulbind, addr1, addr2, addr3 } = await loadFixture(deploySoulbindFixture);

      let randomValues = randomBytes(32).toString("base64");
      let rawMessage = `Signing confirms that you own this address:\n${addr1.address}\n~~Security~~\nTimestamp: ${Date.now()}\nNonce: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(randomValues))}`;
      let message = `${rawMessage}\nHash: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(rawMessage))}`;
      let msgHash = ethers.utils.hashMessage(message);

      let signature = await addr1.signMessage(message);

      const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));

      const tokenCreationData = {
        boe: true,
        eventId,
        _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
        from: addr1.address,
        limit: 2,
        msgHash,
        signature,
        toAddr: [],
        toCode: [],
        updatable: false,
        _tokenURI: '12345',
      }

      // Create token
      await soulbind.connect(addr2).createToken(tokenCreationData);

      // Claim token
      randomValues = randomBytes(32).toString("base64");
      rawMessage = `Signing confirms that you own this address:\n${addr3.address}\n~~Security~~\nTimestamp: ${Date.now()}\nNonce: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(randomValues))}`;
      message = `${rawMessage}\nHash: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(rawMessage))}`;
      msgHash = ethers.utils.hashMessage(message);

      signature = await addr3.signMessage(message);
      await soulbind.connect(addr2).claimToken(eventId, addr3.address, signature, msgHash);
      // Verify current owner
      expect(await soulbind.ownerOf(1)).to.equal(addr3.address);
      // Connect to owners address and transfer token owenership
      await soulbind.connect(addr3).transferFrom(addr3.address, addr2.address, 1);
      // Verify new owner
      expect(await soulbind.ownerOf(1)).to.equal(addr2.address);
    });

    it("Allow the owner of of BoE token to claim and bind it and not transfer it", async function () {
      const { soulbind, addr1, addr2, addr3 } = await loadFixture(deploySoulbindFixture);

      let randomValues = randomBytes(32).toString("base64");
      let rawMessage = `Signing confirms that you own this address:\n${addr1.address}\n~~Security~~\nTimestamp: ${Date.now()}\nNonce: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(randomValues))}`;
      let message = `${rawMessage}\nHash: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(rawMessage))}`;
      let msgHash = ethers.utils.hashMessage(message);

      let signature = await addr1.signMessage(message);

      const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));

      const tokenCreationData = {
        boe: true,
        eventId,
        _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
        from: addr1.address,
        limit: 2,
        signature,
        msgHash,
        toAddr: [],
        toCode: [],
        updatable: false,
        _tokenURI: '12345',
      }

      // Create token
      await soulbind.connect(addr2).createToken(tokenCreationData);
      // Claim token
      randomValues = randomBytes(32).toString("base64");
      rawMessage = `Signing confirms that you own this address:\n${addr3.address}\n~~Security~~\nTimestamp: ${Date.now()}\nNonce: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(randomValues))}`;
      message = `${rawMessage}\nHash: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(rawMessage))}`;
      msgHash = ethers.utils.hashMessage(message);

      signature = await addr3.signMessage(message);
      await soulbind.connect(addr2).claimToken(eventId, addr3.address, signature, msgHash);
      // Verify current owner
      expect(await soulbind.ownerOf(1)).to.equal(addr3.address);
      // Transfer token ownership
      await soulbind.connect(addr3).transferFrom(addr3.address, addr2.address, 1);
      // Verify new owner
      expect(await soulbind.ownerOf(1)).to.equal(addr2.address);
      // New owner soulbinds token
      randomValues = randomBytes(32).toString("base64");
      rawMessage = `Signing confirms that you own this address:\n${addr3.address}\n~~Security~~\nTimestamp: ${Date.now()}\nNonce: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(randomValues))}`;
      message = `${rawMessage}\nHash: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(rawMessage))}`;
      msgHash = ethers.utils.hashMessage(message);

      signature = await addr2.signMessage(message);
      await soulbind.soulbind(1, addr2.address, signature, msgHash);
      // Verify that token is bound
      expect(await soulbind.isBoe(1)).to.equal(false);
      // Verify they may not transfer token
      await expect(soulbind.connect(addr2).transferFrom(addr2.address, addr1.address, 1)).to.revertedWith('This token is soulbind and cannot be transfered');
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
        const { soulbind, addr1, addr2, addr3 } = await loadFixture(deploySoulbindFixture);

        let randomValues = randomBytes(32).toString("base64");
        let rawMessage = `Signing confirms that you own this address:\n${addr1.address}\n~~Security~~\nTimestamp: ${Date.now()}\nNonce: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(randomValues))}`;
        let message = `${rawMessage}\nHash: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(rawMessage))}`;
        let msgHash = ethers.utils.hashMessage(message);

        let signature = await addr1.signMessage(message);

        const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));

        const tokenCreationData = {
          boe: true,
          eventId,
          _burnAuth: ethers.BigNumber.from(BurnAuth.Both),
          from: addr1.address,
          limit: 2,
          signature,
          msgHash,
          toAddr: [],
          toCode: [],
          updatable: false,
          _tokenURI: '12345',
        }

        tokenCreationData._burnAuth

        // Create token
        await soulbind.connect(addr2).createToken(tokenCreationData);
        // Claim token
        randomValues = randomBytes(32).toString("base64");
        rawMessage = `Signing confirms that you own this address:\n${addr3.address}\n~~Security~~\nTimestamp: ${Date.now()}\nNonce: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(randomValues))}`;
        message = `${rawMessage}\nHash: ${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(rawMessage))}`;
        msgHash = ethers.utils.hashMessage(message);

        signature = await addr3.signMessage(message);
        await soulbind.connect(addr2).claimToken(eventId, addr3.address, signature, msgHash);

        expect(await soulbind.ownerOf(1)).to.equal(addr3.address);

        await soulbind.connect(addr2).burnToken(1, eventId, addr3.address, signature, msgHash);

        await expect(soulbind.ownerOf(1)).to.revertedWith('ERC721: invalid token ID');
      });
    });
    describe("Neither", function () {
      it("Should never burn", async function () {

      });
    });
  });
});
