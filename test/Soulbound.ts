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
    // https://storage.googleapis.com/external-testing/eth-sf.json
    it("Should only allow issued tokens to be claimed by accounts that were issued to", async function () {
      const { soulbound, addr1, addr2 } = await loadFixture(deploySoulboundFixture);

      // Issuer sets recievers address
      const ipfsUri = 'bafyreiakiduy5t3jtjvkz2zg2eu4uyirqfavosquhc2l57dpkhbk2bcvhm'
      await soulbound["createToken(string,uint256,uint8)"](ipfsUri, 10, 2);

      await expect(soulbound.connect(addr1).claimToken(1)).to.emit(soulbound, 'EventToken').withArgs(1, 1);
      await expect(soulbound.connect(addr2).claimToken(1)).to.emit(soulbound, 'EventToken').withArgs(1, 2);
    });
  });

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

      });
    });
    describe("Neither", function () {
      it("Should never burn", async function () {

      });
    });
  });
});
