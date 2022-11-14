// SPDX-License-Identifier: AGPL-3.0

// TODO: polygons implementation of SBTs https://polygonscan.com/address/0x42c091743f7b73b2f0043b1fb822b63aaa05041b#code

pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "./Enums.sol";

import "hardhat/console.sol";

// Entities:
// creator/issuer
// url
// claimer

/**
 * @dev Soulbound (aka non-transferable) ERC721 token with storage based token URI management.
 */
contract Soulbound is ERC721URIStorage, ERC721Enumerable {
    using ECDSA for bytes32;

    event TokenClaim(bytes32 eventId, uint256 tokenId);
    event SoulBind(address owner, uint256 tokenId);

    struct Token {
        BurnAuth burnAuth;
        bool boe;
        uint256 count;
        uint256 limit;
        address owner;
        bool restricted;
        string uri;
    }

    struct TokenCreationData {
        bool boe;
        BurnAuth _burnAuth;
        bytes32 eventId;
        address from;
        uint256 limit;
        bytes signature;
        address[] toAddr;
        bytes32[] toCode;
        string _tokenURI;
    }

    using Counters for Counters.Counter;
    Counters.Counter private _eventIds;
    Counters.Counter private _tokenIds;
    uint256 private _limitMax = 10000;

    // Issued tokens by code - hash associated to any form of identity off chain
    // hash of code => Event Id hash
    mapping(bytes32 => bytes32) public issuedCodeTokens;

    // Issued tokens by address
    // Event Id hash => address => Bool
    mapping(bytes32 => mapping(address => bool)) public issuedTokens;
    // Event Id hash => Token
    mapping(bytes32 => Token) public createdTokens;
    // Token Id => Bool - check before every transfer
    mapping(uint256 => bool) public isBoe;

    constructor() ERC721("Soulbound", "Bound") {}

    modifier eventExists(bytes32 eventId) {
        require(createdTokens[eventId].owner == address(0x0), "EventId taken");
        _;
    }

    // Used while claiming. Allows a person to claim for themselves and not others
    modifier isValidSignature(bytes memory signature, address addr) {
        bytes32 msgHash = keccak256(abi.encodePacked(addr));
        bytes32 signedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash)
        );

        require(signedHash.recover(signature) == addr, "Invalid signature");
        _;
    }

    modifier onlyBurnAuth(uint256 tokenId, bytes32 eventId) {
        if (createdTokens[eventId].burnAuth == BurnAuth.OwnerOnly) {
            require(msg.sender == ownerOf(tokenId), "Only owner may burn");
        }
        if (createdTokens[eventId].burnAuth == BurnAuth.IssuerOnly) {
            require(
                msg.sender == createdTokens[eventId].owner,
                "Only issuer may burn"
            );
        }
        if (createdTokens[eventId].burnAuth == BurnAuth.Both) {
            require(
                msg.sender == createdTokens[eventId].owner ||
                    msg.sender == ownerOf(tokenId),
                "Only issuer or owner may burn"
            );
        }
        if (createdTokens[eventId].burnAuth == BurnAuth.Neither) {
            revert("Burn not allowed");
        }
        _;
    }

    // Convert BoE token into SBT
    function soulbind(
        uint256 tokenId,
        address owner,
        bytes memory signature
    ) public isValidSignature(signature, owner) {
        require(owner == ownerOf(tokenId), "Only owner may bind");
        isBoe[tokenId] = false;

        emit SoulBind(owner, tokenId);
    }

    // Non pre-issued tokens with limit
    function createToken(TokenCreationData calldata tcd)
        public
        eventExists(tcd.eventId)
        isValidSignature(tcd.signature, tcd.from)
    {
        require(tcd.limit > 0, "Increase limit");
        require(tcd.limit <= _limitMax, "Reduce limit");

        _createToken(tcd);
        createdTokens[tcd.eventId].limit = tcd.limit;
        createdTokens[tcd.eventId].restricted = false;
    }

    // Pre-issued tokens from addresses
    function createTokenFromAddresses(TokenCreationData calldata tcd)
        public
        eventExists(tcd.eventId)
        isValidSignature(tcd.signature, tcd.from)
    {
        require(tcd.toAddr.length > 0, "Requires receiver array");

        _createToken(tcd);
        createdTokens[tcd.eventId].restricted = true;

        _issueTokens(tcd.toAddr, tcd.eventId);
    }

    // Pre-issued tokens from codes
    function createTokenFromCode(TokenCreationData calldata tcd)
        public
        eventExists(tcd.eventId)
        isValidSignature(tcd.signature, tcd.from)
    {
        require(tcd.toCode.length > 0, "Requires receiver array");

        _createToken(tcd);
        createdTokens[tcd.eventId].restricted = true;

        _issueCodeTokens(tcd.toCode, tcd.eventId);
    }

    // Pre-issued tokens from codes and addresses
    function createTokenFromBoth(TokenCreationData calldata tcd)
        public
        eventExists(tcd.eventId)
        isValidSignature(tcd.signature, tcd.from)
    {
        require(
            tcd.toAddr.length > 0 && tcd.toCode.length > 0,
            "Requires receiver array"
        );

        _createToken(tcd);
        createdTokens[tcd.eventId].restricted = true;

        _issueTokens(tcd.toAddr, tcd.eventId);
        _issueCodeTokens(tcd.toCode, tcd.eventId);
    }

    // Mint tokens
    function claimToken(
        bytes32 eventId,
        address to,
        bytes memory signature
    ) public isValidSignature(signature, to) returns (uint256) {
        require(createdTokens[eventId].restricted == false, "Restricted token");
        require(
            createdTokens[eventId].limit > createdTokens[eventId].count,
            "Token claim limit reached"
        );

        createdTokens[eventId].count += 1;

        _tokenIds.increment();
        uint256 tokenId = _tokenIds.current();
        _mint(to, tokenId);
        _setTokenURI(tokenId, createdTokens[eventId].uri);
        _setBoeState(eventId, tokenId);

        emit TokenClaim(eventId, tokenId);

        return tokenId;
    }

    // Mint issued token
    function claimIssuedToken(
        bytes32 eventId,
        address to,
        bytes memory signature
    ) public isValidSignature(signature, to) returns (uint256) {
        require(createdTokens[eventId].restricted, "Not a restricted token");
        require(issuedTokens[eventId][to], "Token must be issued to you");

        issuedTokens[eventId][to] = false;
        createdTokens[eventId].count += 1;

        _tokenIds.increment();
        uint256 tokenId = _tokenIds.current();
        _mint(to, tokenId);
        _setTokenURI(tokenId, createdTokens[eventId].uri);
        _setBoeState(eventId, tokenId);

        emit TokenClaim(eventId, tokenId);

        return tokenId;
    }

    // Mint issued token by code
    function claimIssuedTokenFromCode(
        bytes32 eventId,
        bytes32 code,
        address to,
        bytes memory signature
    ) public isValidSignature(signature, to) returns (uint256) {
        require(createdTokens[eventId].restricted, "Not a restricted token");
        require(
            issuedCodeTokens[code] == eventId,
            "Token must be issued to you"
        );

        delete issuedCodeTokens[code];

        createdTokens[eventId].count += 1;

        _tokenIds.increment();
        uint256 tokenId = _tokenIds.current();
        _mint(to, tokenId);
        _setTokenURI(tokenId, createdTokens[eventId].uri);
        _setBoeState(eventId, tokenId);

        emit TokenClaim(eventId, tokenId);

        return tokenId;
    }

    function incraseLimit(bytes32 eventId, uint256 limit) public {
        require(
            createdTokens[eventId].owner == msg.sender,
            "Must be event owner"
        );
        require(createdTokens[eventId].limit < limit, "Increase limit");
        require(limit <= _limitMax, "Reduce limit");

        createdTokens[eventId].limit = limit;
    }

    function burnToken(uint256 tokenId, bytes32 eventId)
        public
        onlyBurnAuth(tokenId, eventId)
    {
        _burn(tokenId);
    }

    function _createToken(TokenCreationData calldata tcd) private {
        createdTokens[tcd.eventId].uri = tcd._tokenURI;
        createdTokens[tcd.eventId].burnAuth = tcd._burnAuth;
        createdTokens[tcd.eventId].owner = tcd.from;
        createdTokens[tcd.eventId].boe = tcd.boe;
    }

    function _issueTokens(address[] calldata to, bytes32 eventId) private {
        for (uint256 i = 0; i < to.length; ++i) {
            issuedTokens[eventId][to[i]] = true;
        }
    }

    function _issueCodeTokens(bytes32[] calldata to, bytes32 eventId) private {
        for (uint256 i = 0; i < to.length; ++i) {
            issuedCodeTokens[to[i]] = eventId;
        }
    }

    function _setBoeState(bytes32 eventId, uint256 tokenId) private {
        isBoe[tokenId] = createdTokens[eventId].boe;
    }

    // Soulbound functionality
    function transferFrom(
        address from, //from,
        address to, //to,
        uint256 tokenId //tokenId
    ) public override(ERC721, IERC721) {
        require(
            isBoe[tokenId],
            "This token is soulbound and cannot be transfered"
        );

        super.transferFrom(from, to, tokenId);
    }

    function safeTransferFrom(
        address from, //from,
        address to, //to,
        uint256 tokenId //tokenId
    ) public override(ERC721, IERC721) {
        require(
            isBoe[tokenId],
            "This token is soulbound and cannot be transfered"
        );

        super.safeTransferFrom(from, to, tokenId);
    }

    function safeTransferFrom(
        address from, //from,
        address to, //to,
        uint256 tokenId, //tokenId
        bytes memory _data //_data
    ) public override(ERC721, IERC721) {
        require(
            isBoe[tokenId],
            "This token is soulbound and cannot be transfered"
        );

        super.safeTransferFrom(from, to, tokenId, _data);
    }

    // Required overrides from parent contracts
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal override(ERC721, ERC721Enumerable) {
        super._beforeTokenTransfer(from, to, tokenId);
    }

    function _burn(uint256 tokenId)
        internal
        override(ERC721, ERC721URIStorage)
    {
        super._burn(tokenId);
    }

    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721, ERC721URIStorage)
        returns (string memory)
    {
        return super.tokenURI(tokenId);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, ERC721Enumerable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
