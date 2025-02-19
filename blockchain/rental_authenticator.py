from web3 import Web3
from eth_account import Account
import json
import os
from dotenv import load_dotenv
import logging
import pyrebase
from datetime import datetime

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class RentalAuthenticator:
    def __init__(self):
        try:
            # Load environment variables
            load_dotenv()
            
            # Initialize Web3
            self.w3 = Web3(Web3.HTTPProvider(os.getenv('ETHEREUM_NODE_URL', 'http://127.0.0.1:7545')))
            
            # Set up admin account
            admin_private_key = os.getenv('ETHEREUM_PRIVATE_KEY')  # Changed from ADMIN_PRIVATE_KEY
            if not admin_private_key:
                raise ValueError("Admin private key not found in environment variables")
            
            self.admin_account = self.w3.eth.account.from_key(admin_private_key)
            
            # Check admin balance
            balance = self.w3.eth.get_balance(self.admin_account.address)
            if balance == 0:
                raise ValueError("Admin account has zero balance")
            
            logger.info(f"Admin account balance: {self.w3.from_wei(balance, 'ether')} ETH")
            
            # Load contract
            contract_address = os.getenv('RENTAL_HISTORY_CONTRACT')  # Changed from CONTRACT_ADDRESS
            if not contract_address:
                raise ValueError("Contract address not found in environment variables")
            
            with open('blockchain/RentalHistory.json') as f:
                contract_json = json.load(f)
            
            self.contract = self.w3.eth.contract(
                address=self.w3.to_checksum_address(contract_address),
                abi=contract_json['abi']
            )
            
            logger.info(f"RentalAuthenticator initialized with contract at {contract_address}")
            
        except Exception as e:
            logger.error(f"Failed to initialize RentalAuthenticator: {str(e)}")
            raise

    def register_product(self, product_id, name):
        try:
            logger.info(f"Attempting to register product: {product_id} - {name}")
            
            # Get nonce
            nonce = self.w3.eth.get_transaction_count(self.admin_account.address)
            
            # Build transaction
            transaction = self.contract.functions.registerProduct(
                product_id,
                name
            ).build_transaction({
                'chainId': self.w3.eth.chain_id,
                'gas': 2000000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': nonce,
                'from': self.admin_account.address
            })
            
            logger.debug(f"Transaction built: {transaction}")
            
            # Convert private key to bytes if needed
            if isinstance(self.admin_account.key, str):
                private_key = bytes.fromhex(self.admin_account.key.replace('0x', ''))
            else:
                private_key = self.admin_account.key
                
            # Sign transaction
            try:
                signed_txn = self.w3.eth.account.sign_transaction(transaction, private_key)
                raw_txn = signed_txn.raw_transaction  # For Web3.py v6
            except AttributeError:
                signed_txn = self.w3.eth.account.sign_transaction(transaction, private_key)
                raw_txn = signed_txn.rawTransaction  # For Web3.py v5
                
            logger.debug("Transaction signed")
            
            # Send raw transaction
            tx_hash = self.w3.eth.send_raw_transaction(raw_txn)
            logger.info(f"Transaction sent: {tx_hash.hex()}")
            
            # Wait for transaction receipt
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            logger.info(f"Transaction confirmed in block: {receipt['blockNumber']}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error registering product on blockchain:")
            logger.error(f"Product ID: {product_id}")
            logger.error(f"Name: {name}")
            logger.error(f"Admin address: {self.admin_account.address}")
            logger.error(f"Error details: {str(e)}")
            logger.error(f"Transaction data: {transaction if 'transaction' in locals() else 'Not built'}")
            raise

    def record_rental(self, product_id, renter_address, renter_name, shipping_address):
        try:
            logger.info(f"Recording rental for product {product_id}")
            logger.info(f"Renter: {renter_name} ({renter_address})")
            logger.info(f"Shipping Address: {shipping_address}")
            
            # Validate inputs
            if not product_id or not renter_name or not shipping_address:
                raise ValueError("Missing required rental information")
            
            # Convert None or empty address to zero address
            if not renter_address:
                renter_address = '0x0000000000000000000000000000000000000000'
            
            # Ensure renter_address is a valid Ethereum address
            if not self.w3.is_address(renter_address):
                if not renter_address.startswith('0x'):
                    renter_address = '0x' + renter_address
                if len(renter_address) < 42:
                    renter_address = renter_address[:2] + renter_address[2:].zfill(40)
            
            renter_address = self.w3.to_checksum_address(renter_address)
            
            txn = self.contract.functions.recordRental(
                product_id,
                renter_address,
                renter_name,
                shipping_address
            ).build_transaction({
                'from': self.admin_account.address,
                'nonce': self.w3.eth.get_transaction_count(self.admin_account.address),
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price,
                'chainId': self.w3.eth.chain_id
            })
            
            signed_txn = self.w3.eth.account.sign_transaction(txn, self.admin_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status != 1:
                raise Exception("Transaction failed")
            
            return True
            
        except Exception as e:
            logger.error(f"Error recording rental: {str(e)}")
            raise

    def record_return(self, product_id, shipping_address, condition, notes):
        try:
            logger.info(f"Recording return for product {product_id}")
            
            # First check if product exists and register if it doesn't
            product_data = self.get_product_history(product_id)
            if not product_data or not product_data[0]:  # product not registered
                logger.info(f"Product {product_id} not registered, attempting to register first...")
                try:
                    # Get product from Firebase
                    firebase = pyrebase.initialize_app({
                        "apiKey": os.getenv('FIREBASE_API_KEY'),
                        "authDomain": os.getenv('FIREBASE_AUTH_DOMAIN'),
                        "databaseURL": os.getenv('FIREBASE_DATABASE_URL'),
                        "storageBucket": os.getenv('FIREBASE_STORAGE_BUCKET')
                    })
                    db = firebase.database()
                    product = db.child("products").child(product_id).get().val()
                    if not product:
                        raise Exception(f"Product {product_id} not found in Firebase")
                    
                    # Register the product
                    self.register_product(product_id, product.get('product_name', 'Unknown Product'))
                    logger.info(f"Product {product_id} registered successfully")
                except Exception as e:
                    logger.error(f"Failed to register product: {str(e)}")
                    raise
            
            # Use a proper zero address format
            zero_address = '0x' + '0' * 40
            
            # If shipping_address is empty or None, use zero address
            if not shipping_address:
                renter_address = zero_address
            else:
                # Clean and format the address
                cleaned_address = shipping_address.replace('0x', '').replace('-', '')[:40]
                padded_address = cleaned_address.ljust(40, '0')
                renter_address = '0x' + padded_address
            
            # Validate the address format
            if not self.w3.is_address(renter_address):
                logger.error(f"Invalid address format: {renter_address}")
                raise ValueError("Invalid Ethereum address format")
            
            # Convert to checksum address
            renter_address = self.w3.to_checksum_address(renter_address)
            logger.debug(f"Using renter address: {renter_address}")
            
            # Build transaction
            txn = self.contract.functions.recordReturn(
                product_id,
                renter_address,
                condition,
                notes
            ).build_transaction({
                'from': self.admin_account.address,
                'nonce': self.w3.eth.get_transaction_count(self.admin_account.address),
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price,
                'chainId': self.w3.eth.chain_id
            })
            
            # Sign and send transaction
            signed_txn = self.w3.eth.account.sign_transaction(txn, self.admin_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status != 1:
                raise Exception("Transaction failed")
            
            return True
            
        except Exception as e:
            logger.error(f"Error recording return: {str(e)}")
            raise

    def get_product_history(self, product_id):
        try:
            logger.debug(f"Getting history for product: {product_id}")
            
            # Initialize Firebase
            firebase = pyrebase.initialize_app({
                "apiKey": os.getenv('FIREBASE_API_KEY'),
                "authDomain": os.getenv('FIREBASE_AUTH_DOMAIN'),
                "databaseURL": os.getenv('FIREBASE_DATABASE_URL'),
                "storageBucket": os.getenv('FIREBASE_STORAGE_BUCKET')
            })
            db = firebase.database()
            
            # First check if product exists and register if it doesn't
            result = self.contract.functions.getProductHistory(product_id).call()
            logger.debug(f"Raw blockchain result: {result}")
            
            is_registered, name, current_condition, rental_records = result
            
            if not is_registered:
                logger.info(f"Product {product_id} not registered, attempting to register first...")
                try:
                    product = db.child("products").child(product_id).get().val()
                    
                    if product:
                        # Register the product
                        self.register_product(
                            product_id=product_id,
                            name=product.get('product_name', 'Unknown Product')
                        )
                        logger.info(f"Product {product_id} registered successfully")
                        
                        # Get updated history after registration
                        result = self.contract.functions.getProductHistory(product_id).call()
                        is_registered, name, current_condition, rental_records = result
                    else:
                        logger.error(f"Product {product_id} not found in Firebase")
                except Exception as e:
                    logger.error(f"Error registering product: {str(e)}")
                    raise
            
            # Get latest condition from product_conditions table
            try:
                # Get all conditions and filter in memory instead of using orderBy
                conditions_ref = db.child("product_conditions").get()
                latest_condition = None
                latest_recorded_at = None
                
                if conditions_ref.each():
                    for condition_record in conditions_ref.each():
                        record = condition_record.val()
                        if record.get('product_id') == product_id:
                            recorded_at = record.get('recorded_at')
                            if not latest_recorded_at or recorded_at > latest_recorded_at:
                                latest_recorded_at = recorded_at
                                latest_condition = record.get('condition')
                
                if latest_condition:
                    current_condition = latest_condition
                    logger.debug(f"Updated condition from product_conditions: {current_condition}")
            except Exception as e:
                logger.error(f"Error getting condition from product_conditions: {str(e)}")
            
            formatted_records = []
            if rental_records:
                logger.debug(f"Found {len(rental_records)} rental records")
                for record in rental_records:
                    try:
                        formatted_record = {
                            'renter': record[0],
                            'renterName': record[1],
                            'shippingAddress': record[2],
                            'rentedAt': datetime.fromtimestamp(record[3]).strftime('%Y-%m-%d %H:%M:%S'),
                            'returnedAt': datetime.fromtimestamp(record[4]).strftime('%Y-%m-%d %H:%M:%S') if record[4] > 0 else None,
                            'condition': current_condition,  # Use the condition from product_conditions
                            'isReturned': record[7]
                        }
                        formatted_records.append(formatted_record)
                    except Exception as e:
                        logger.error(f"Error formatting record: {str(e)}")
                        continue
            
            return (is_registered, name, current_condition, formatted_records)
            
        except Exception as e:
            logger.error(f"Error getting product history: {str(e)}")
            return (False, '', '', [])