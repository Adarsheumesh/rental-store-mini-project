// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RentalHistory {
    address public admin;
    
    struct RentalRecord {
        address renter;
        string userId;        // Store original user ID
        string shippingAddress;
        string rentalDetails; // Store JSON string of rental details
        uint256 rentedAt;
        uint256 returnedAt;
        string condition;
        string notes;
        bool isReturned;
    }
    
    struct Product {
        string productId;
        string name;
        address owner;
        bool isRegistered;
        uint256 registeredAt;
        string currentCondition;
        address currentRenter;
        RentalRecord[] rentalHistory;
    }
    
    mapping(string => Product) public products;
    
    event ProductRegistered(string productId, string name, uint256 timestamp);
    event RentalRecorded(
        string productId, 
        address renter, 
        string userId,
        string shippingAddress, 
        string rentalDetails,
        uint256 timestamp
    );
    event ReturnRecorded(string productId, address renter, uint256 timestamp, string condition);
    event Debug(string message, string data);
    
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can call this function");
        _;
    }
    
    constructor() {
        admin = msg.sender;
    }
    
    function registerProduct(string memory productId, string memory name) public onlyAdmin {
        require(!products[productId].isRegistered, "Product already registered");
        
        products[productId].productId = productId;
        products[productId].name = name;
        products[productId].owner = msg.sender;
        products[productId].isRegistered = true;
        products[productId].registeredAt = block.timestamp;
        products[productId].currentCondition = "New";
        
        emit ProductRegistered(productId, name, block.timestamp);
    }
    
    function recordRental(
        string memory productId, 
        address renter,
        string memory userId,
        string memory shippingAddress,
        string memory rentalDetails
    ) public onlyAdmin {
        require(bytes(productId).length > 0, "Product ID cannot be empty");
        require(renter != address(0), "Invalid renter address");
        require(bytes(userId).length > 0, "User ID cannot be empty");
        
        RentalRecord memory newRental = RentalRecord({
            renter: renter,
            userId: userId,
            shippingAddress: shippingAddress,
            rentalDetails: rentalDetails,
            rentedAt: block.timestamp,
            returnedAt: 0,
            condition: "",
            notes: "",
            isReturned: false
        });
        
        products[productId].rentalHistory.push(newRental);
        products[productId].currentRenter = renter;
        
        emit RentalRecorded(
            productId, 
            renter, 
            userId,
            shippingAddress, 
            rentalDetails,
            block.timestamp
        );
    }
    
    function recordReturn(
        string memory productId, 
        address renter, 
        string memory condition,
        string memory notes
    ) public onlyAdmin {
        require(products[productId].isRegistered, "Product not registered");
        
        RentalRecord[] storage history = products[productId].rentalHistory;
        for (uint i = 0; i < history.length; i++) {
            if (history[i].renter == renter && !history[i].isReturned) {
                history[i].returnedAt = block.timestamp;
                history[i].condition = condition;
                history[i].notes = notes;
                history[i].isReturned = true;
                products[productId].currentCondition = condition;
                
                emit ReturnRecorded(productId, renter, block.timestamp, condition);
                break;
            }
        }
    }
    
    function getProductHistory(string memory productId) public view returns (
        bool isRegistered,
        string memory name,
        string memory currentCondition,
        RentalRecord[] memory history
    ) {
        Product storage product = products[productId];
        
        // Return empty array if no history
        if (!product.isRegistered) {
            return (false, "", "", new RentalRecord[](0));
        }
        
        return (
            product.isRegistered,
            product.name,
            product.currentCondition,
            product.rentalHistory
        );
    }
    
    function getRentalHistoryLength(string memory productId) public view returns (uint) {
        return products[productId].rentalHistory.length;
    }
} 