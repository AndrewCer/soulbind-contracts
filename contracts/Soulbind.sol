// SPDX-License-Identifier: AGPL-3.0

pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "./Enums.sol";

import "hardhat/console.sol";

/**
 * @dev Soulbound (aka non-transferable) ERC721 token with storage based token URI management.
 */
contract Soulbind is ERC721URIStorage, ERC721Enumerable {
    using ECDSA for bytes32;

    event TokenBind(address owner, uint256 tokenId);
    event TokenClaim(bytes32 eventId, uint256 tokenId);
    event TokenCreate(address owner, bytes32 eventId);

    struct Token {
        BurnAuth burnAuth;
        bool boe;
        uint256 count;
        uint256 limit;
        address owner;
        bool restricted;
        bool updatable;
        string uri;
    }

    struct TokenCreationData {
        bool boe;
        BurnAuth _burnAuth;
        bytes32 eventId;
        address from;
        uint256 limit;
        bytes32 msgHash;
        bytes signature;
        address[] toAddr;
        bytes32[] toCode;
        bool updatable;
        string _tokenURI;
    }

    using Counters for Counters.Counter;
    Counters.Counter private _eventIds;
    Counters.Counter private _tokenIds;
    uint256 private _limitMax = 500000;

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

    constructor() ERC721("Soulbind V0.8", "Soulbind") {}

    modifier eventExists(bytes32 eventId) {
        require(createdTokens[eventId].owner == address(0x0), "EventId taken");
        _;
    }

    // Used for all of our gasless txn. Signed addr must match received addr
    modifier isValidSignature(
        bytes memory signature,
        address addr,
        bytes32 msgHash
    ) {
        require(msgHash.recover(signature) == addr, "Invalid signature");
        _;
    }

    modifier onlyBurnAuth(
        uint256 tokenId,
        bytes32 eventId,
        address sender
    ) {
        require(createdTokens[eventId].owner != address(0x0), "Invalid Id");

        if (createdTokens[eventId].burnAuth == BurnAuth.OwnerOnly) {
            require(sender == ownerOf(tokenId), "Only owner may burn");
        }
        if (createdTokens[eventId].burnAuth == BurnAuth.IssuerOnly) {
            require(
                sender == createdTokens[eventId].owner,
                "Only issuer may burn"
            );
        }
        if (createdTokens[eventId].burnAuth == BurnAuth.Both) {
            require(
                sender == createdTokens[eventId].owner ||
                    sender == ownerOf(tokenId),
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
        bytes memory signature,
        bytes32 msgHash
    ) public isValidSignature(signature, owner, msgHash) {
        require(owner == ownerOf(tokenId), "Only owner may bind");
        isBoe[tokenId] = false;

        emit TokenBind(owner, tokenId);
    }

    function burnToken(
        uint256 tokenId,
        bytes32 eventId,
        address sender,
        bytes memory signature,
        bytes32 msgHash
    )
        public
        onlyBurnAuth(tokenId, eventId, sender)
        isValidSignature(signature, sender, msgHash)
    {
        _burn(tokenId);
    }

    // Non restricted token with limit
    function createToken(TokenCreationData calldata tcd)
        public
        eventExists(tcd.eventId)
        isValidSignature(tcd.signature, tcd.from, tcd.msgHash)
    {
        require(tcd.limit > 0, "Increase limit");
        require(tcd.limit <= _limitMax, "Reduce limit");

        _createToken(tcd);
        createdTokens[tcd.eventId].limit = tcd.limit;
        createdTokens[tcd.eventId].restricted = false;
    }

    // Create restricted token
    function createRestrictedToken(TokenCreationData calldata tcd)
        public
        eventExists(tcd.eventId)
        isValidSignature(tcd.signature, tcd.from, tcd.msgHash)
    {
        require(
            tcd.toAddr.length > 0 || tcd.toCode.length > 0,
            "Requires receiver array"
        );

        _createToken(tcd);
        createdTokens[tcd.eventId].restricted = true;

        if (tcd.toAddr.length > 0) {
            _issueTokens(tcd.toAddr, tcd.eventId);
        }
        if (tcd.toCode.length > 0) {
            _issueCodeTokens(tcd.toCode, tcd.eventId);
        }
    }

    // Mint tokens
    function claimToken(
        bytes32 eventId,
        address to,
        bytes memory signature,
        bytes32 msgHash
    ) public isValidSignature(signature, to, msgHash) returns (uint256) {
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
        bytes memory signature,
        bytes32 msgHash
    ) public isValidSignature(signature, to, msgHash) returns (uint256) {
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
        bytes memory signature,
        bytes32 msgHash
    ) public isValidSignature(signature, to, msgHash) returns (uint256) {
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

    // Update issued addresses/codes for restricted tokens
    function addIssuedTo(
        bytes32 eventId,
        address[] calldata toAddr,
        bytes32[] calldata toCode,
        address from,
        bytes memory signature,
        bytes32 msgHash
    ) public isValidSignature(signature, from, msgHash) {
        require(createdTokens[eventId].restricted, "Must be restricted token");
        require(createdTokens[eventId].owner == from, "Must be event owner");
        if (toAddr.length > 0) {
            _issueTokens(toAddr, eventId);
        }
        if (toCode.length > 0) {
            _issueCodeTokens(toCode, eventId);
        }
    }

    // Update token limit for non restricted tokens
    function incraseLimit(
        bytes32 eventId,
        uint256 limit,
        address from,
        bytes memory signature,
        bytes32 msgHash
    ) public isValidSignature(signature, from, msgHash) {
        require(!createdTokens[eventId].restricted, "Must not be restricted token");
        require(createdTokens[eventId].owner == from, "Must be event owner");
        require(createdTokens[eventId].limit < limit, "Increase limit");
        require(limit <= _limitMax, "Reduce limit");

        createdTokens[eventId].limit = limit;
    }

    // Update an individual tokens metadata
    function updateTokenURI(
        uint256 tokenId,
        bytes32 eventId,
        string memory _tokenURI,
        address from,
        bytes memory signature,
        bytes32 msgHash
    ) public isValidSignature(signature, from, msgHash) {
        require(createdTokens[eventId].owner == from, "Not owner");
        require(createdTokens[eventId].updatable, "Not updatable");
        require(_exists(tokenId), "Invalid token");

        _setTokenURI(tokenId, _tokenURI);
    }

    function _createToken(TokenCreationData calldata tcd) private {
        createdTokens[tcd.eventId].uri = tcd._tokenURI;
        createdTokens[tcd.eventId].burnAuth = tcd._burnAuth;
        createdTokens[tcd.eventId].owner = tcd.from;
        createdTokens[tcd.eventId].boe = tcd.boe;
        createdTokens[tcd.eventId].updatable = tcd.updatable;

        emit TokenCreate(tcd.from, tcd.eventId);
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

    // Overrides

    // Soulbind/BoE functionality
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public override(ERC721, IERC721) {
        require(
            isBoe[tokenId],
            "This token is soulbind and cannot be transfered"
        );

        super.transferFrom(from, to, tokenId);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public override(ERC721, IERC721) {
        require(
            isBoe[tokenId],
            "This token is soulbind and cannot be transfered"
        );

        super.safeTransferFrom(from, to, tokenId);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) public override(ERC721, IERC721) {
        require(
            isBoe[tokenId],
            "This token is soulbind and cannot be transfered"
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
