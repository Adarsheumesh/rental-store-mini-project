module.exports = {
  networks: {
    development: {
      host: "127.0.0.1",
      port: 8545,
      network_id: "0x539",
      gas: 6721975,
      gasPrice: 20000000000
    }
  },
  contracts_directory: './contracts/',
  contracts_build_directory: './blockchain/build/contracts/',
  compilers: {
    solc: {
      version: "0.8.0",
      settings: {
        optimizer: {
          enabled: true,
          runs: 200
        }
      }
    }
  }
}; 