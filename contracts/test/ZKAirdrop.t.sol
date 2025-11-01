// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ZKAirdrop} from "../src/ZKAirdrop.sol";
import {IRiscZeroVerifier} from "../src/interfaces/IRiscZeroVerifier.sol";

/// @notice Mock verifier for testing
contract MockVerifier is IRiscZeroVerifier {
    bool public shouldFail;
    
    function setShouldFail(bool _shouldFail) external {
        shouldFail = _shouldFail;
    }
    
    function verify(
        bytes calldata,
        bytes32,
        bytes32
    ) external view override {
        require(!shouldFail, "Mock verification failed");
    }
}

contract ZKAirdropTest is Test {
    ZKAirdrop public airdrop;
    MockVerifier public verifier;
    
    bytes32 constant IMAGE_ID = bytes32(uint256(0x123456));
    bytes32 constant MERKLE_ROOT = bytes32(uint256(0xabcdef));
    uint256 constant REWARD_AMOUNT = 1 ether;
    
    address constant USER = address(0x1);
    
    function setUp() public {
        verifier = new MockVerifier();
        airdrop = new ZKAirdrop(
            address(verifier),
            IMAGE_ID,
            MERKLE_ROOT,
            REWARD_AMOUNT
        );
        
        // Fund the contract
        vm.deal(address(airdrop), 100 ether);
    }
    
    function testInitialState() public view {
        assertEq(address(airdrop.VERIFIER()), address(verifier));
        assertEq(airdrop.IMAGE_ID(), IMAGE_ID);
        assertEq(airdrop.merkleRoot(), MERKLE_ROOT);
        assertEq(airdrop.rewardAmount(), REWARD_AMOUNT);
        assertEq(airdrop.currentEpoch(), 1);
        assertEq(airdrop.paused(), false);
    }
    
    function testSuccessfulClaim() public {
        bytes32 nullifier = keccak256("test-nullifier");
        
        // Encode claim output: merkleRoot (32) + nullifier (32) + epochId (8)
        // Use abi.encode to ensure proper padding
        bytes memory claimOutput = abi.encodePacked(
            MERKLE_ROOT,      // 32 bytes
            nullifier,        // 32 bytes
            uint64(1)         // 8 bytes, will be padded correctly
        );
        
        bytes memory seal = hex"1234"; // Mock seal
        
        uint256 balanceBefore = USER.balance;
        
        vm.prank(USER);
        airdrop.claim(seal, claimOutput);
        
        assertEq(USER.balance, balanceBefore + REWARD_AMOUNT);
        assertTrue(airdrop.isNullifierUsed(nullifier));
    }
    
    function testCannotClaimTwice() public {
        bytes32 nullifier = keccak256("test-nullifier");
        
        bytes memory claimOutput = abi.encodePacked(
            MERKLE_ROOT,
            nullifier,
            uint64(1)
        );
        
        bytes memory seal = hex"1234";
        
        // First claim succeeds
        vm.prank(USER);
        airdrop.claim(seal, claimOutput);
        
        // Second claim fails
        vm.prank(USER);
        vm.expectRevert(ZKAirdrop.AlreadyClaimed.selector);
        airdrop.claim(seal, claimOutput);
    }
    
    function testInvalidProof() public {
        verifier.setShouldFail(true);
        
        bytes32 nullifier = keccak256("test-nullifier");
        bytes memory claimOutput = abi.encodePacked(
            MERKLE_ROOT,
            nullifier,
            uint64(1)
        );
        
        vm.prank(USER);
        vm.expectRevert(ZKAirdrop.InvalidProof.selector);
        airdrop.claim(hex"1234", claimOutput);
    }
    
    function testWrongEpoch() public {
        bytes32 nullifier = keccak256("test-nullifier");
        bytes memory claimOutput = abi.encodePacked(
            MERKLE_ROOT,
            nullifier,
            uint64(999) // Wrong epoch
        );
        
        vm.prank(USER);
        vm.expectRevert(ZKAirdrop.InvalidEpoch.selector);
        airdrop.claim(hex"1234", claimOutput);
    }
    
    function testSetEpoch() public {
        bytes32 newRoot = bytes32(uint256(0x999));
        
        airdrop.setEpoch(newRoot);
        
        assertEq(airdrop.currentEpoch(), 2);
        assertEq(airdrop.merkleRoot(), newRoot);
    }
    
    function testPauseUnpause() public {
        airdrop.togglePause();
        assertTrue(airdrop.paused());
        
        bytes32 nullifier = keccak256("test-nullifier");
        bytes memory claimOutput = abi.encodePacked(
            MERKLE_ROOT,
            nullifier,
            uint64(1)
        );
        
        vm.prank(USER);
        vm.expectRevert(ZKAirdrop.Paused.selector);
        airdrop.claim(hex"1234", claimOutput);
        
        airdrop.togglePause();
        assertFalse(airdrop.paused());
    }
}
