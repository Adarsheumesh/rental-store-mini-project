from web3 import Web3
from dotenv import load_dotenv
import os
from blockchain.rental_authenticator import RentalAuthenticator
import pyrebase

def test_blockchain_content():
    # Load environment variables
    load_dotenv()
    
    try:
        # Initialize Firebase
        config = {
            "apiKey": os.getenv('FIREBASE_API_KEY'),
            "authDomain": os.getenv('FIREBASE_AUTH_DOMAIN'),
            "databaseURL": os.getenv('FIREBASE_DATABASE_URL'),
            "storageBucket": os.getenv('FIREBASE_STORAGE_BUCKET')
        }
        
        firebase = pyrebase.initialize_app(config)
        db = firebase.database()
        
        # Connect to local blockchain
        w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
        
        # Check connection
        if w3.is_connected():
            print("\n✅ Successfully connected to blockchain")
            
            # Initialize rental authenticator
            authenticator = RentalAuthenticator()
            
            # Get products from Firebase
            products = db.child("products").get().val()
            
            print("\n🔍 Checking products on blockchain:")
            print("=" * 50)
            
            if products:
                for product_id, product_data in products.items():
                    print(f"\nProduct ID: {product_id}")
                    print(f"Name: {product_data.get('product_name', 'N/A')}")
                    
                    # Get blockchain data
                    try:
                        blockchain_data = authenticator.get_product_history(product_id)
                        
                        if blockchain_data and blockchain_data[0]:  # is_registered
                            print("Blockchain Status: ✅ Registered")
                            print(f"Blockchain Name: {blockchain_data[1]}")
                            print(f"Current Condition: {blockchain_data[2]}")
                            
                            # Display rental history
                            if blockchain_data[3]:  # rental_history
                                print("\nRental History:")
                                for record in blockchain_data[3]:
                                    print("-" * 30)
                                    print(f"Renter: {record[0]}")
                                    print(f"Rented At: {record[1]}")
                                    if record[5]:  # isReturned
                                        print(f"Returned At: {record[2]}")
                                        print(f"Return Condition: {record[3]}")
                                        print(f"Notes: {record[4]}")
                                    else:
                                        print("Status: Currently Rented")
                            else:
                                print("No rental history")
                        else:
                            print("Blockchain Status: ❌ Not Registered")
                            print("Attempting to register product...")
                            authenticator.register_product(product_id, product_data.get('product_name', 'Unknown Product'))
                            print("✅ Product registered successfully")
                            
                    except Exception as e:
                        print(f"Error getting blockchain data: {str(e)}")
                    
                    print("=" * 50)
            else:
                print("No products found in Firebase")
                
        else:
            print("❌ Failed to connect to blockchain")
            print("Make sure your blockchain node (like Ganache) is running on port 8545")
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        print("Make sure your .env file contains all required Firebase configuration:")
        print("- FIREBASE_API_KEY")
        print("- FIREBASE_AUTH_DOMAIN")
        print("- FIREBASE_DATABASE_URL")
        print("- FIREBASE_STORAGE_BUCKET")

if __name__ == "__main__":
    test_blockchain_content() 