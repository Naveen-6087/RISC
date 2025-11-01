// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "./interfaces/IRiscZeroVerifier.sol";

/// @title ZKAirdrop
/// @notice Privacy-preserving token airdrop using RISC Zero zkVM
/// @dev Users prove eligibility without revealing their address on-chain
contract ZKAirdrop {
    /// @notice RISC Zero verifier contract
    IRiscZeroVerifier public immutable VERIFIER;
    
    /// @notice Image ID of the zkVM guest program
    bytes32 public immutable IMAGE_ID;
    
    /// @notice Current airdrop epoch
    uint64 public currentEpoch;
    
    /// @notice Merkle root for the current epoch
    bytes32 public merkleRoot;
    
    /// @notice Reward amount per claim
    uint256 public rewardAmount;
    
    /// @notice Contract owner
    address public owner;
    
    /// @notice Emergency pause state
    bool public paused;
    
    /// @notice Mapping of nullifiers to prevent double-claiming
    /// @dev nullifier => claimed status
    mapping(bytes32 => bool) public nullifiers;
    
    /// @notice Emitted when a successful claim is made
    event Claimed(
        bytes32 indexed nullifier,
        address indexed recipient,
        uint256 amount,
        uint64 epoch
    );
    
    /// @notice Emitted when epoch is updated
    event EpochUpdated(uint64 indexed epoch, bytes32 merkleRoot);
    
    /// @notice Emitted when contract is paused/unpaused
    event PauseToggled(bool paused);
    
    /// @notice Emitted when reward amount is updated
    event RewardAmountUpdated(uint256 newAmount);
    
    error InvalidProof();
    error AlreadyClaimed();
    error Paused();
    error Unauthorized();
    error InvalidMerkleRoot();
    error InvalidEpoch();
    error TransferFailed();
    
    modifier onlyOwner() {
        _onlyOwner();
        _;
    }
    
    modifier whenNotPaused() {
        _whenNotPaused();
        _;
    }
    
    /// @notice Constructor
    /// @param _verifier Address of RISC Zero verifier contract
    /// @param _imageId Image ID of the zkVM guest program
    /// @param _merkleRoot Initial Merkle root
    /// @param _rewardAmount Reward amount per claim
    constructor(
        address _verifier,
        bytes32 _imageId,
        bytes32 _merkleRoot,
        uint256 _rewardAmount
    ) {
        if (_merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        
        VERIFIER = IRiscZeroVerifier(_verifier);
        IMAGE_ID = _imageId;
        merkleRoot = _merkleRoot;
        rewardAmount = _rewardAmount;
        owner = msg.sender;
        currentEpoch = 1;
        
        emit EpochUpdated(currentEpoch, _merkleRoot);
    }
    
    /// @notice Claim airdrop tokens
    /// @param seal The RISC Zero proof
    /// @param claimOutput The claim output from the guest program
    /// @dev claimOutput contains: merkleRoot (32 bytes) + nullifier (32 bytes) + epochId (8 bytes)
    function claim(bytes calldata seal, bytes calldata claimOutput) 
        external 
        whenNotPaused 
    {
        // Decode claim output (72 bytes total: 32 + 32 + 8)
        require(claimOutput.length == 72, "Invalid claim output length");
        
        bytes32 proofMerkleRoot;
        bytes32 nullifier;
        uint64 epochId;
        
        assembly {
            // Load merkleRoot (first 32 bytes)
            proofMerkleRoot := calldataload(claimOutput.offset)
            // Load nullifier (next 32 bytes)
            nullifier := calldataload(add(claimOutput.offset, 32))
            // Load epochId (last 8 bytes)
            // calldataload loads 32 bytes, but we only want the first 8 bytes as uint64
            let epochData := calldataload(add(claimOutput.offset, 64))
            // Shift right to get the uint64 from the left-most 8 bytes
            epochId := shr(192, epochData)
        }
        
        // Verify epoch matches
        if (epochId != currentEpoch) revert InvalidEpoch();
        
        // Verify merkle root matches
        if (proofMerkleRoot != merkleRoot) revert InvalidMerkleRoot();
        
        // Check nullifier hasn't been used
        if (nullifiers[nullifier]) revert AlreadyClaimed();
        
        // Verify the proof
        bytes32 journalDigest = sha256(claimOutput);
        try VERIFIER.verify(seal, IMAGE_ID, journalDigest) {
            // Mark nullifier as used
            nullifiers[nullifier] = true;
            
            // Transfer reward
            (bool success,) = msg.sender.call{value: rewardAmount}("");
            if (!success) revert TransferFailed();
            
            emit Claimed(nullifier, msg.sender, rewardAmount, epochId);
        } catch {
            revert InvalidProof();
        }
    }
    
    /// @notice Set new epoch with new Merkle root
    /// @param _merkleRoot New Merkle root
    function setEpoch(bytes32 _merkleRoot) external onlyOwner {
        if (_merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        
        currentEpoch++;
        merkleRoot = _merkleRoot;
        
        emit EpochUpdated(currentEpoch, _merkleRoot);
    }
    
    /// @notice Update reward amount
    /// @param _rewardAmount New reward amount
    function setRewardAmount(uint256 _rewardAmount) external onlyOwner {
        rewardAmount = _rewardAmount;
        emit RewardAmountUpdated(_rewardAmount);
    }
    
    /// @notice Toggle pause state
    function togglePause() external onlyOwner {
        paused = !paused;
        emit PauseToggled(paused);
    }
    
    /// @notice Check if nullifier has been used
    /// @param nullifier The nullifier to check
    /// @return True if already claimed
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }
    
    /// @notice Withdraw contract balance
    function withdraw() external onlyOwner {
        (bool success,) = owner.call{value: address(this).balance}("");
        if (!success) revert TransferFailed();
    }
    
    /// @notice Receive ETH
    receive() external payable {}
    
    function _onlyOwner() internal view {
        if (msg.sender != owner) revert Unauthorized();
    }
    
    function _whenNotPaused() internal view {
        if (paused) revert Paused();
    }
}
