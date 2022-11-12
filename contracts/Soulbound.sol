// SPDX-License-Identifier: AGPL-3.0

// TODO: polygons implementation of SBTs https://polygonscan.com/address/0x42c091743f7b73b2f0043b1fb822b63aaa05041b#code

pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
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
//  TODO(nocs): validate if we need ERC721URIStorage aka tokenURI as we are already storing it manually.
contract Soulbound is ERC721URIStorage, ERC721Enumerable, Ownable {
    using ECDSA for bytes32;

    event EventToken(bytes32 eventId, uint256 tokenId);

    struct Token {
        BurnAuth burnAuth;
        uint256 count;
        uint256 limit;
        address owner;
        bool restricted;
        string uri;
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

    // Non pre-issued tokens with limit
    function createToken(
        bytes32 eventId,
        string calldata _tokenURI,
        uint256 limit,
        BurnAuth _burnAuth,
        address from,
        bytes memory signature
    ) public eventExists(eventId) isValidSignature(signature, from) {
        require(limit > 0, "Increase limit");
        require(limit <= _limitMax, "Reduce limit");

        _createToken(eventId, _tokenURI, _burnAuth, from);
        createdTokens[eventId].limit = limit;
        createdTokens[eventId].restricted = false;
    }

    // Pre-issued tokens from addresses
    function createTokenFromAddresses(
        bytes32 eventId,
        string calldata _tokenURI,
        address[] calldata to,
        BurnAuth _burnAuth,
        address from,
        bytes memory signature
    ) public eventExists(eventId) isValidSignature(signature, from) {
        require(to.length > 0, "Requires receiver array");

        _createToken(eventId, _tokenURI, _burnAuth, from);
        createdTokens[eventId].restricted = true;

        _issueTokens(to, eventId);
    }

    // Pre-issued tokens from codes
    function createTokenFromCode(
        bytes32 eventId,
        string calldata _tokenURI,
        bytes32[] calldata to,
        BurnAuth _burnAuth,
        address from,
        bytes memory signature
    ) public eventExists(eventId) isValidSignature(signature, from) {
        require(to.length > 0, "Requires receiver array");

        _createToken(eventId, _tokenURI, _burnAuth, from);
        createdTokens[eventId].restricted = true;

        _issueCodeTokens(to, eventId);
    }

    // Pre-issued tokens from codes and addresses
    function createTokenFromBoth(
        bytes32 eventId,
        string calldata _tokenURI,
        address[] calldata toAddr,
        bytes32[] calldata toCode,
        BurnAuth _burnAuth,
        address from,
        bytes memory signature
    ) public {
        bytes32 msgHash = keccak256(abi.encodePacked(from));
        bytes32 signedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash)
        );
        require(signedHash.recover(signature) == from, "Invalid signature");
        require(
            toAddr.length > 0 && toCode.length > 0,
            "Requires receiver array"
        );

        // TODO(nocs): solidity really doesnt like me adding 'from' to that function below...
        // _createToken(eventId, _tokenURI, _burnAuth);
        createdTokens[eventId].restricted = true;

        _issueTokens(toAddr, eventId);
        _issueCodeTokens(toCode, eventId);
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

        emit EventToken(eventId, tokenId);

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

        emit EventToken(eventId, tokenId);

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

        emit EventToken(eventId, tokenId);

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

    function _createToken(
        bytes32 eventId,
        string calldata _tokenURI,
        BurnAuth _burnAuth,
        address from
    ) private {
        createdTokens[eventId].owner = from;
        createdTokens[eventId].uri = _tokenURI;
        createdTokens[eventId].burnAuth = _burnAuth;
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

    // Soulbound functionality
    function transferFrom(
        address, //from,
        address, //to,
        uint256 //tokenId
    ) public pure override(ERC721, IERC721) {
        revert("This token is soulbound and cannot be transfered");
    }

    function safeTransferFrom(
        address, //from,
        address, //to,
        uint256 //tokenId
    ) public pure override(ERC721, IERC721) {
        revert("This token is soulbound and cannot be transfered");
    }

    function safeTransferFrom(
        address, //from,
        address, //to,
        uint256, //tokenId,
        bytes memory //_data
    ) public pure override(ERC721, IERC721) {
        revert("This token is soulbound and cannot be transfered");
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

    function safeMint(address to, uint256 tokenId) public onlyOwner {
        _mint(to, tokenId);
    }
}
