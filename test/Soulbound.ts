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

  xdescribe("Issuance", function () {

    it("Should only allow owner to issue tokens", async function () {
      const { soulbound, addr1, addr2 } = await loadFixture(deploySoulboundFixture);

      await expect(soulbound.connect(addr1).issueToken(addr1.address)).to.be.revertedWith("Ownable: caller is not the owner");
      await expect(soulbound.connect(addr1).bulkIssue([addr1.address, addr2.address])).to.be.revertedWith("Ownable: caller is not the owner");
    });

    describe("Singular", function () {
      it("Should issue a token to the address", async function () {
        const { soulbound, addr1, addr2 } = await loadFixture(deploySoulboundFixture);

        await soulbound.issueToken(addr2.address);

        expect(await soulbound.issuedTokens(addr1.address)).to.equal(false);
        expect(await soulbound.issuedTokens(addr2.address)).to.equal(true);
      });
    });

    describe("Bulk", function () {
      it("Should issue a token to all received addresses", async function () {
        const { soulbound, addr1, addr2, addr3 } = await loadFixture(deploySoulboundFixture);

        await soulbound.bulkIssue([addr1.address, addr2.address]);

        expect(await soulbound.issuedTokens(addr1.address)).to.equal(true);
        expect(await soulbound.issuedTokens(addr2.address)).to.equal(true);
        expect(await soulbound.issuedTokens(addr3.address)).to.equal(false);
      });
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
      await soulbound.connect(addr2).createToken(eventId, '1234', 2, 2, addr1.address, signature);

      await expect(soulbound.connect(addr2).claimToken(eventId, addr1.address, signature)).to.emit(soulbound, 'EventToken').withArgs(eventId, 1);
    });
  });

  describe("Crate", function () {

    it("Should create a token with a limit", async function () {
      const { soulbound, addr1, addr2 } = await loadFixture(deploySoulboundFixture);

      let messageHash = ethers.utils.solidityKeccak256(
        ["address"],
        [addr1.address]
      );

      let messageHashBinary = ethers.utils.arrayify(messageHash);

      let signature = await addr1.signMessage(messageHashBinary);

      const eventId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('1234'));
      await soulbound.connect(addr2).createToken(eventId, '1234', 2, 2, addr1.address, signature);

      const token = await soulbound.createdTokens(eventId);
      expect(token.uri).to.equal('1234');
    });

    it("Should create a token with both codes and addresses", async function () {
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
      await soulbound.connect(addr2).createTokenFromBoth(
        eventId,
        '1234',
        [addr1.address, addr2.address],
        [code1, code2],
        2,
        addr1.address,
        signature);

      expect(await soulbound.issuedCodeTokens(code1)).to.equal(eventId);
      expect(await soulbound.issuedCodeTokens(code2)).to.equal(eventId);
      expect(await soulbound.issuedTokens(eventId, addr1.address)).to.equal(true);
      expect(await soulbound.issuedTokens(eventId, addr2.address)).to.equal(true);
    });
  });

  xdescribe("Burning", function () {
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

      });
    });
    describe("Neither", function () {
      it("Should never burn", async function () {

      });
    });
  });
});
