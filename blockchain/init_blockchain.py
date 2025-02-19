import os
from web3 import Web3
from dotenv import load_dotenv
import json
import logging
from eth_account import Account
import secrets

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def deploy_new_contract(w3, contract_data, admin_account, admin_key):
    # Deploy contract
    Contract = w3.eth.contract(
        abi=contract_data['abi'],
        bytecode=contract_data['bytecode']
    )
    
    # Build constructor transaction
    construct_txn = Contract.constructor().build_transaction({
        'from': admin_account.address,
        'nonce': w3.eth.get_transaction_count(admin_account.address),
        'gas': 2000000,
        'gasPrice': w3.eth.gas_price,
        'chainId': w3.eth.chain_id
    })
    
    # Sign and send transaction
    signed_txn = w3.eth.account.sign_transaction(construct_txn, admin_key)
    
    # Use rawTransaction instead of raw_transaction
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    
    # Wait for transaction receipt
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    # Verify contract deployment
    if tx_receipt.status != 1:
        raise Exception("Contract deployment failed")
    
    # Verify contract code exists
    contract_code = w3.eth.get_code(tx_receipt.contractAddress)
    if contract_code == b'' or contract_code == '0x':
        raise Exception("Contract code not found at deployed address")
        
    logger.info(f"Contract deployed successfully at {tx_receipt.contractAddress}")
    return tx_receipt.contractAddress, tx_hash.hex()

def init_blockchain():
    load_dotenv()
    
    # Connect to local blockchain
    w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
    
    if not w3.is_connected():
        raise Exception("Could not connect to Ethereum node")
    
    logger.debug("Connected to Ethereum node")
    
    try:
        # Generate a new admin account if none exists
        admin_key = os.getenv('ETHEREUM_ADMIN_KEY')
        if not admin_key:
            admin_key = "0x" + secrets.token_hex(32)
            logger.info("Generated new admin key")
        
        # Create account from private key
        admin_account = Account.from_key(admin_key)
        logger.debug(f"Admin account address: {admin_account.address}")

        # Fund admin account if needed
        admin_balance = w3.eth.get_balance(admin_account.address)
        if admin_balance < w3.to_wei(0.1, 'ether'):
            funding_account = w3.eth.accounts[0]
            funding_amount = w3.to_wei(1, 'ether')
            
            fund_tx = {
                'from': funding_account,
                'to': admin_account.address,
                'value': funding_amount,
                'gas': 21000,
                'gasPrice': w3.eth.gas_price,
                'nonce': w3.eth.get_transaction_count(funding_account),
                'chainId': w3.eth.chain_id
            }
            
            tx_hash = w3.eth.send_transaction(fund_tx)
            w3.eth.wait_for_transaction_receipt(tx_hash)
            logger.info(f"Funded admin account with {w3.from_wei(funding_amount, 'ether')} ETH")

        contract_path = os.path.join(
            os.path.dirname(__file__),
            'build',
            'contracts',
            'RentalHistory.json'
        )
        
        logger.debug(f"Looking for contract at: {contract_path}")
        
        with open(contract_path) as f:
            contract_data = json.load(f)
        
        # Always deploy a new contract for testing
        logger.info("Deploying new contract...")
        contract_address, tx_hash = deploy_new_contract(w3, contract_data, admin_account, admin_key)
        
        # Update contract data
        network_id = str(w3.eth.chain_id)
        contract_data['networks'] = {
            network_id: {
                'address': contract_address,
                'transactionHash': tx_hash
            }
        }
        
        # Save updated contract data
        with open(contract_path, 'w') as f:
            json.dump(contract_data, f, indent=2)
            
        # Update .env file
        env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
        env_vars = {}
        
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        env_vars[key] = value
        
        env_vars['RENTAL_HISTORY_CONTRACT'] = contract_address
        env_vars['ETHEREUM_NODE_URL'] = 'http://127.0.0.1:8545'
        env_vars['ETHEREUM_ADMIN_KEY'] = admin_key
        
        with open(env_path, 'w') as f:
            for key, value in env_vars.items():
                f.write(f'{key}={value}\n')
                
        print(f"Contract address updated in .env: {contract_address}")
        print("Blockchain initialization successful!")
        
    except Exception as e:
        logger.error(f"Error during initialization: {str(e)}")
        raise

if __name__ == "__main__":
    try:
        init_blockchain()
    except Exception as e:
        logger.error(f"Initialization failed: {str(e)}")
        raise 