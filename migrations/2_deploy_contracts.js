const RentalHistory = artifacts.require("RentalHistory");

module.exports = function(deployer) {
  deployer.deploy(RentalHistory)
    .then(() => {
      console.log("Contract deployed to:", RentalHistory.address);
    });
}; 