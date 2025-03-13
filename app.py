from sqlite3 import Date
from weakref import ref
from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash, logging, send_file, abort
from networkx import is_path
import pyrebase
import re
import json
from oauthlib.oauth2 import WebApplicationClient
import requests
import os
import firebase_admin
from firebase_admin import credentials, db
from dotenv import load_dotenv  # type: ignore
from datetime import datetime  # Import datetime
from werkzeug.utils import secure_filename
import traceback
import logging
import stripe
import uuid
import random
import string
from decimal import Decimal
import pdfkit  # You'll need to install this: pip install pdfkit
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import google.generativeai as genai
from dotenv import load_dotenv
from blockchain.init_blockchain import init_blockchain

logging.basicConfig(level=logging.DEBUG)

load_dotenv()

# Allow insecure transport for development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Initialize Flask application
app = Flask(__name__)

from mlprice import get_all_product_suggestions, get_products

# Configure Gemini API
GOOGLE_API_KEY = 'AIzaSyBiPsei3KY2ftDpKr58k-Jy62IN4rNuH_c'  # Replace with your actual API key
genai.configure(api_key=GOOGLE_API_KEY)

# Initialize Gemini model 
model = genai.GenerativeModel('gemini-1.5-pro')

# Initialize blockchain before starting the app
try:
    init_blockchain()
except Exception as e:
    app.logger.error(f"Failed to initialize blockchain: {str(e)}")
    raise

@app.route('/analysis')
def analysis():
    try:
        suggestions = get_all_product_suggestions()
        app.logger.info(f"Generated {len(suggestions)} suggestions")

        for suggestion in suggestions:
            product_name = suggestion.get('product_name', 'Unknown')
            product_id = suggestion.get('product_id', 'Unknown')
            demand = suggestion.get('demand', 'Unknown')
            app.logger.info(f"Product: {product_name}, ID: {product_id}, Demand: {demand}")
        
        return render_template('analysis.html', suggestions=suggestions)
    except Exception as e:
        app.logger.error(f"Error in analysis route: {str(e)}", exc_info=True)
        return render_template('error.html', error="An error occurred while generating product suggestions."), 500

@app.route('/get_products')
def get_products_route():
    products = get_products()
    return jsonify({"products": products})

app.secret_key = 'turbolegion6282'

# Firebase configuration
config = {
    "apiKey": os.getenv('FIREBASE_API_KEY'),
    "authDomain": os.getenv('FIREBASE_AUTH_DOMAIN'),
    "databaseURL": os.getenv('FIREBASE_DATABASE_URL'),
    "storageBucket": os.getenv('FIREBASE_STORAGE_BUCKET'),
    "projectId": "project-dbebd",
    "messagingSenderId": "374516311348",
    "appId": "1:374516311348:web:d916facf6720a4e275f161"
}

firebase = pyrebase.initialize_app(config)
auth = firebase.auth()
db = firebase.database()

# OAuth 2 client setup
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = os.environ.get("GOOGLE_DISCOVERY_URL")
client = WebApplicationClient(GOOGLE_CLIENT_ID)

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

def is_valid_email(email):
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(regex, email)

def is_valid_password(password):
    regex = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    return re.match(regex, password)

def is_valid_phone(phone):
    regex = r'^\+?1?\d{9,15}$'
    return re.match(regex, phone)

def is_valid_name(name):
    regex = r'^[A-Za-z\s]+$'
    
    return re.match(regex, name)

def is_valid_district(district):
    regex = r'^[A-Za-z\s]+$'
    return re.match(regex, district)

@app.route('/')
def home():
    if 'email' in session and 'user_info' in session:
        email = session['email']
        user_info = session['user_info']
        return render_template('index.html', email=email, user_info=user_info)
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'email' in session and 'user_info' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email').lower()
        password = request.form.get('password')
        name = request.form.get('name')
        phone = request.form.get('phone')
        district = request.form.get('district')
        user_type = request.form.get('user_type')  # Get user type from form
        status = "active"    # Default status
        registration_date = datetime.now().date().strftime("%Y-%m-%d")  # Get current date

        if not is_valid_email(email):
            flash('Invalid email address.', 'danger')
            return render_template('register.html')

        if not is_valid_password(password):
            flash('Password must be at least 8 characters long and include one uppercase letter, one lowercase letter, one number, and one special character.', 'danger')
            return render_template('register.html')

        if not is_valid_phone(phone):
            flash('Invalid phone number.', 'danger')
            return render_template('register.html')

        if not is_valid_name(name):
            flash('Name cannot contain numbers or special characters.', 'danger')
            return render_template('register.html')

        if not is_valid_district(district):
            flash('District cannot contain numbers or special characters.', 'danger')
            return render_template('register.html')

        try:
            # Create user in Firebase Auth
            user = auth.create_user_with_email_and_password(email, password)
            user_id = user['localId']
            auth.send_email_verification(user['idToken'])

            # Store user data in Firebase Realtime Database
            db.child("users").child(user_id).set({
                "name": name,
                "phone": phone,
                "district": district,
                "email": email,
                "user_type": user_type,  # Save user type
                "status": status,  # Default status
                "registration_date": registration_date  # Save registration date (only date)
            })

            flash('Registration successful! Please verify your email before logging in.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            error = f"Unsuccessful registration: {str(e)}"
            flash(error, 'danger')
            return render_template('register.html')

    return render_template('register.html')


@app.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        try:
            user = auth.sign_in_with_email_and_password(email, password)
            auth.send_email_verification(user['idToken'])
            flash('Verification email sent.', 'success')
        except Exception as e:
            flash(f'Failed to send verification email: {str(e)}', 'danger')

    return render_template('resend_verification.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            email = request.form['email']
            password = request.form['password']

            # Authenticate with Firebase
            user = auth.sign_in_with_email_and_password(email, password)
            
            # Get user info from Firebase
            user_info = auth.get_account_info(user['idToken'])
            user_id = user_info['users'][0]['localId']

            # Get all users and find the matching one by firebase_uid
            all_users = db.child("users").get().val()
            user_data = None
            user_key = None

            for key, data in all_users.items():
                if data.get('firebase_uid') == user_id or data.get('email') == email:
                    user_data = data
                    user_key = key
                    break

            if not user_data:
                flash('User data not found', 'error')
                return redirect(url_for('login'))

            # Store user data in session
            session['user_id'] = user_key  # Store the database key
            session['email'] = email
            session['idToken'] = user['idToken']
            session['user_info'] = user_data

            # Get user type from user_data
            user_type = user_data.get('user_type')
            app.logger.debug(f"User type: {user_type}")  # Debug log

            # Redirect based on user type
            if user_type == 'Admin':
                flash('Welcome Admin!', 'success')
                return redirect(url_for('admin_dashboard'))
            elif user_type == 'vendor':
                flash('Welcome Vendor!', 'success')
                return redirect(url_for('vendor_dashboard'))
            elif user_type == 'delivery_agent':
                flash('Welcome Delivery Agent!', 'success')
                return redirect(url_for('delivery_dashboard'))
            else:  # customer
                flash('Welcome to ToolHive!', 'success')
                return redirect(url_for('index'))

        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            if "INVALID_PASSWORD" in str(e):
                flash('Invalid password', 'error')
            elif "EMAIL_NOT_FOUND" in str(e):
                flash('Email not found', 'error')
            else:
                flash('Login failed. Please try again.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/login/google')
def google_login():
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
        prompt="select_account"  # Force account selection
    )
    return redirect(request_uri)

@app.route('/login/google/callback')
def google_callback():
    code = request.args.get("code")
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Exchange authorization code for access token
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )
    token_json = token_response.json()

    client.parse_request_body_response(json.dumps(token_json))
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    userinfo = userinfo_response.json()

    if userinfo.get("email_verified"):
        users_email = userinfo["email"]
        users_name = userinfo["name"]
        picture = userinfo["picture"]

        session['email'] = users_email
        session['name'] = users_name
        session['picture'] = picture

        # Check if user already exists in Firebase
        try:
            user = auth.sign_in_with_email_and_password(users_email, users_email)
            user_id = user['localId']
        except:
            # If the user does not exist, create a new one
            try:
                user = auth.create_user_with_email_and_password(users_email, users_email)
                user_id = user['localId']
                # Save user info in Firebase
                db.child("users").child(user_id).set({
                    "name": users_name,
                    "phone": "",  # Default values if not provided
                    "district": "",
                    "email": users_email,
                    "user_type": "customer"  # Default user type
                })
            except Exception as e:
                flash(f"Error creating user: {str(e)}", 'danger')
                return redirect(url_for('login'))

        # Fetch user data from the database and update the session
        user_data = db.child("users").child(user_id).get().val()

        if user_data:
            session['user_id'] = user_id
            session['user_info'] = user_data
            flash('Logged in successfully with Google.', 'success')
            return redirect(url_for('index'))
        else:
            flash('User data not found after login.', 'danger')
            return redirect(url_for('login'))
    else:
        flash('User email not available or not verified by Google.', 'danger')
        return redirect(url_for('login'))

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        flash('Please log in first', 'error')
        return redirect(url_for('login'))

    try:
        user_id = session['user_id']
        user_info = session.get('user_info', {})

        # Verify user is admin
        if user_info.get('user_type') != 'Admin':
            flash('Unauthorized access', 'error')
            return redirect(url_for('index'))

        # Get all users from Firebase
        all_users = db.child("users").get().val() or {}
        
        # Initialize stats
        user_stats = {'active': 0, 'inactive': 0}
        vendor_stats = {'active': 0, 'pending': 0, 'rejected': 0}
        
        # Calculate statistics
        for user in all_users.values():
            if user.get('user_type') == 'vendor':
                vendor_status = user.get('vendor_status', 'pending')
                vendor_stats[vendor_status] = vendor_stats.get(vendor_status, 0) + 1
            
            if user.get('status') == 'active':
                user_stats['active'] += 1
            else:
                user_stats['inactive'] += 1

        return render_template('Admin/index.html',
                             user_info=user_info,
                             user_stats=user_stats,
                             vendor_stats=vendor_stats)

    except Exception as e:
        app.logger.error(f"Error in admin_dashboard: {str(e)}")
        flash('An error occurred while loading the dashboard', 'error')
        return redirect(url_for('login'))

@app.route('/index')
def index():
    if 'email' in session and 'user_info' in session:
        email = session['email']
        user_info = session['user_info']
    else:
        email = None
        user_info = None

    # Fetch data from the 'products' table
    try:
        products = db.child("products").get().val()  # Fetch all products from the 'products' table   
    except Exception as e:
        products = None
        flash(f"Failed to retrieve products: {str(e)}", 'danger')

    # Fetch best seller products
    try:
        # You might want to implement a logic to determine best sellers
        # For now, let's assume the first 5 products are best sellers
        best_seller_products = []
        if products:
            for product_id, product in list(products.items())[:5]:
                product['id'] = product_id
                best_seller_products.append(product)
    except Exception as e:
        best_seller_products = None

    wallet_balance = 0
    if 'user_id' in session:
        user_id = session['user_id']
        wallet_balance = get_user_wallet_balance(user_id)
    
    return render_template('index.html', 
                           email=email, 
                           user_info=user_info, 
                           products=products, 
                           best_seller_products=best_seller_products,
                           wallet_balance=wallet_balance)


@app.route('/vendor_dashboard')
def vendor_dashboard():
    if 'user_id' not in session or 'email' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    email = session['email']

    try:
        user_info = db.child("users").child(user_id).get().val()
        if not user_info:
            raise ValueError("User information not found")

        store_name = user_info.get('store_name')
        
        # Initialize statistics
        total_customers = 0
        total_orders = 0
        total_revenue = 0
        total_products = 0
        
        # Calculate total products for this store
        all_products = db.child("products").get().val()
        if all_products:
            total_products = sum(1 for product in all_products.values() 
                               if product.get('store_name') == store_name)
        
        # Calculate orders and revenue
        all_orders = db.child("orders").get().val()
        unique_customers = set()
        recent_orders = []
        
        if all_orders:
            for order_id, order in all_orders.items():
                order_items = order.get('items', [])
                for item in order_items:
                    if item.get('store_name') == store_name:
                        # Count unique customers
                        unique_customers.add(order.get('user_id'))
                        
                        # Add to total revenue
                        total_revenue += float(item.get('item_total', 0))
                        
                        # Count total orders
                        total_orders += 1
                        
                        # Add to recent orders list
                        if len(recent_orders) < 5:
                            product_id = item.get('product_id')
                            product_details = get_product_details(product_id)
                            recent_orders.append({
                                'order_id': order_id,
                                'product_image': product_details.get('product_image', ''),
                                'product_name': product_details.get('product_name', 'Unknown Product'),
                                'quantity': item.get('quantity', 0),
                                'order_date': order.get('created_at', 'N/A'),
                                'order_cost': f"₹{float(item.get('item_total', 0)):,.2f}",
                                'status': item.get('status', 'Unknown')
                            })
        
        # Set total customers from unique customers set
        total_customers = len(unique_customers)

        return render_template(
            'andshop/index.html',
            user_info=user_info,
            email=email,
            recent_orders=recent_orders,
            customer_count=total_customers,
            total_orders=total_orders,
            total_revenue=f"{total_revenue:,.2f}",
            product_count=total_products
        )
    except Exception as e:
        app.logger.error(f"Error in vendor_dashboard: {str(e)}")
        flash('An error occurred while loading the page. Please try again.', 'danger')
        return redirect(url_for('index'))

@app.route('/account')
def account():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_info = session.get('user_info')

    try:
        # Fetch orders for the current user
        orders_data = db.child("orders").order_by_child("user_id").equal_to(user_id).get()
        
        orders = []
        if orders_data.each():
            for order in orders_data.each():
                order_data = order.val()
                order_data['order_id'] = order.key()

                # Add payment ID and shipping address to order data
                order_data['payment_id'] = order_data.get('payment_intent_id', 'N/A')
                order_data['shipping_address'] = order_data.get('shipping_address', 'N/A')

                # Fetch product details for each item in the order
                items = order_data.get('items', [])
                for item in items:
                    product_id = item.get('product_id')
                    if product_id:
                        product_details = get_product_details(product_id)
                        item['product_name'] = product_details.get('product_name', 'Unknown Product')
                        item['image_url'] = product_details.get('product_image', '')
                    else:
                        item['product_name'] = 'Unknown Product'
                        item['image_url'] = ''

                orders.append(order_data)
        
        # Sort orders by date (assuming there's a 'created_at' field)
        orders.sort(key=lambda x: x.get('created_at', ''), reverse=True)

    except Exception as e:
        print(f"Error fetching orders: {str(e)}")
        flash('An error occurred while fetching your orders.', 'danger')
        orders = []

    return render_template('account.html', user_info=user_info, orders=orders)

def get_product_details(product_id):
    try:
        product = db.child("products").child(product_id).get().val()
        if product:
            return {
                'product_name': product.get('product_name', 'Unknown Product'),
                'product_image': product.get('product_image', '')
            }
        else:
            print(f"Product not found for ID: {product_id}")
            return {'product_name': 'Unknown Product', 'product_image': ''}
    except Exception as e:
        print(f"Error fetching product details for ID {product_id}: {str(e)}")
        return {'product_name': 'Unknown Product', 'product_image': ''}

@app.route('/get-order-details')
def get_order_details():
    order_id = request.args.get('order_id')
    user_id = session.get('user_id')
    
    try:
        order = db.child("orders").child(order_id).get().val()
        if order and order.get('user_id') == user_id:
            # Fetch product details for each item in the order
            for item in order.get('items', []):
                product_id = item.get('product_id')
                if product_id:
                    product = get_product_details(product_id)
                    item['product_name'] = product.get('product_name', 'Unknown Product')
                    item['image_url'] = product.get('product_image', '')
                    # The total_price and other details should already be in the item data
            
            return jsonify({
                'success': True,
                'order': order
                })
    except Exception as e:
        app.logger.error(f"Error fetching order details: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while fetching order details'}), 500

def get_product_details(product_id):
    try:
        product = db.child("products").child(product_id).get().val()
        if product:
            return {
                'product_name': product.get('product_name', 'Unknown Product'),
                'product_image': product.get('product_image', '')
            }
        else:
            return {'product_name': 'Unknown Product', 'product_image': ''}
    except Exception as e:
        print(f"Error fetching product details: {str(e)}")
        return {'product_name': 'Unknown Product', 'product_image': ''}

@app.route('/account-details')
def account_details():
    return render_template('account_details.html')

@app.route('/shop')
def shop():
    return render_template('shop.html')
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        try:
            auth.send_password_reset_email(email)
            flash('Password reset email sent. Please check your inbox.', 'success')
        except Exception as e:
            flash(f'Error sending password reset email: {str(e)}', 'danger')
    return render_template('reset_password.html')

@app.route('/logout')
def logout():
    # Clear the session
    session.pop('email', None)
    session.pop('user_info', None)
    session.pop('user_id', None)
    session.pop('google_token', None)
    session.clear()
    # Flash message
    flash('You have been logged out.', 'info')
    
    # Redirect to the index page
    response = redirect(url_for('login'))

    # Prevent caching to ensure the user can't go back to the previous page
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response


def save_profile_picture(profile_picture):
    # Generate a secure filename
    filename = secure_filename(profile_picture.filename)
    
    # Define the full path where the image will be saved
    UPLOAD_FOLDER = os.path.join('static', 'uploads', 'profile_pictures')
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    # Generate the full file path
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    
    # Save the file to the specified location
    profile_picture.save(file_path)
    
    # Return the relative file path to store in the database
    return os.path.join('uploads', 'profile_pictures', filename)

@app.route('/update-account', methods=['GET', 'POST'])
def update_account():
    if 'email' not in session or 'user_info' not in session:
        return redirect(url_for('login'))

    email = session['email']
    user_info = session['user_info']
    user_type = user_info.get('user_type')

    if request.method == 'POST':
        name = request.form.get('name')
        phone = request.form.get('phone')
        district = request.form.get('district')
        address = request.form.get('address')  # Get address from form

        if not is_valid_name(name):
            flash('Name cannot contain numbers or special characters.', 'danger')
            return render_template('account.html', email=email, user_info=user_info)

        if not is_valid_phone(phone):
            flash('Invalid phone number.', 'danger')
            return render_template('account.html', email=email, user_info=user_info)

        if not is_valid_district(district):
            flash('Please select a valid district.', 'danger')
            return render_template('account.html', email=email, user_info=user_info)

        if not is_valid_address(address):  # Add address validation
            flash('Address can only contain letters, numbers, spaces, commas, and periods.', 'danger')
            return render_template('account.html', email=email, user_info=user_info)

        update_data = {
            "name": name,
            "phone": phone,
            "district": district,
            "address": address  # Add address to update data
        }

        # Additional fields for vendors
        if user_type == 'vendor':
            store_name = request.form.get('store_name')
            profile_pic = request.files.get('profile_pic')

            if not store_name:
                flash('Store name is required for vendors.', 'danger')
                return render_template('account.html', email=email, user_info=user_info)

            # Save the profile picture if it exists
            if profile_pic:
                profile_pic_url = save_profile_picture(profile_pic)
                update_data['profile_pic'] = profile_pic_url

            update_data['store_name'] = store_name

        user_id = session['user_id']
        try:
            db.child("users").child(user_id).update(update_data)

            # Update session info
            session['user_info'].update(update_data)

            flash('Account updated successfully!', 'success')
            
            # Redirect based on user type
            if user_type == "vendor":
                return redirect(url_for('user_profile'))  # Redirect to the vendor profile route
            else:
                return redirect(url_for('account'))
        except Exception as e:
            flash(f"Failed to update account: {str(e)}", 'danger')
            return render_template('account.html', email=email, user_info=user_info)

    return render_template('account.html', email=email, user_info=user_info)

def is_valid_address(address):
    if not address or len(address.strip()) < 10:
        return False
    # Regular expression to allow only letters, numbers, spaces, commas, periods, and newlines
    regex = r'^[a-zA-Z0-9\s,.\n]+$'
    return bool(re.match(regex, address))

# Vendor-start
@app.route('/product-add')
def producadd():
    if 'user_id' not in session or 'email' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    email = session['email']

    try:
        # Fetch user info
        user_info = db.child("users").child(user_id).get().val()
        if not user_info:
            raise ValueError("User information not found")

        # Fetch categories
        categories = []
        categories_ref = db.child("categories").get()
        
        # Debug prints
        print("Fetching categories...")
        print("Categories reference:", categories_ref)
        
        if categories_ref:
            for category in categories_ref.each():
                category_data = category.val()
                if category_data and isinstance(category_data, dict):
                    print(f"Processing category: {category_data}")
                    categories.append(category_data)
        
        print(f"Total categories found: {len(categories)}")
        
        return render_template(
            '/andshop/product-add.html',
            user=user_info,
            email=email,
            categories=categories
        )
    except Exception as e:
        app.logger.error(f"Error in producadd: {str(e)}")
        print(f"Detailed error: {str(e)}")  # Additional debug print
        flash('An error occurred while loading the page. Please try again.', 'danger')
        return redirect(url_for('index'))
@app.route('/user-list')
def user_list():
    if 'user_info' not in session:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    user_info = session['user_info']
    try:
        # Fetch all users from the Firebase database
        users = db.child("users").get().val()
        
        # Filter users where user_type is 'customer'
        if users:
            customers = {user_id: user for user_id, user in users.items() if user.get('user_type') == 'customer'}
            
            if customers:
                return render_template('andshop/user-list.html', users=customers, user=user_info)
            else:
                flash('No customers found.', 'warning')
                return render_template('andshop/user-list.html', users={}, user=user_info)
        else:
            flash('No users found.', 'warning')
            return render_template('andshop/user-list.html', users={}, user=user_info)
    except Exception as e:
        flash(f"Error fetching user list: {str(e)}", 'danger')
        return redirect(url_for('vendor_dashboard'))


@app.route('/user-profile')
def user_profile():
    if 'email' not in session or 'user_info' not in session:
        flash('Please log in to view your profile.', 'warning')
        return redirect(url_for('login'))

    email = session['email']
    user_info = session['user_info']
    store_name = user_info.get('store_name', '')

    # Fetch all orders
    all_orders = db.child("orders").get().val()

    total_revenue = 0
    total_orders = 0
    if all_orders:
        for order in all_orders.values():
            order_items = order.get('order_items', [])
            store_order = False
            for item in order_items:
                if item.get('store_name', '').lower() == store_name.lower():
                    total_revenue += float(item.get('price', 0))
                    store_order = True
            if store_order:
                total_orders += 1

    # Format the total revenue to two decimal places
    formatted_revenue = "${:,.2f}".format(total_revenue)

    return render_template('andshop/user-profile.html', 
                           email=email, 
                           user=user_info, 
                           total_revenue=formatted_revenue,
                           total_orders=total_orders)
    

@app.route('/add-product', methods=['GET', 'POST'])
def add_product():
    if 'email' not in session or 'user_id' not in session:
        flash('Please log in to add a product.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    categories_list = []

    try:
        # Fetch categories from Firebase
        categories_data = db.child("categories").get().val()
        if categories_data:
            for key, value in categories_data.items():
                categories_list.append({
                    "id": key,
                    "category_name": value.get('category_name', 'N/A')
                })

        # Fetch user information to get the store name
        user_info = db.child("users").child(user_id).get().val()
        store_name = user_info.get('store_name', 'Default Store')  # Use a default if not found

    except Exception as e:
        flash(f"Failed to fetch data: {str(e)}", 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        product_name = request.form.get('product_name')
        product_type = request.form.get('product_type')
        main_category = request.form.get('main_category')
        product_quantity = request.form.get('product_quantity')
        product_price = request.form.get('product_price')
        product_image = request.files.get('product_image')

        # Validate inputs
        if not product_name or not product_price:
            flash('Product name and product price are required.', 'danger')
            return render_template('andshop/product-add.html', categories=categories_list)

        # Save the product image if it exists
        product_image_url = None
        if product_image and product_image.filename != '':
            product_image_url = save_product_image(product_image)

        try:
            # Insert product into the database with store name
            new_product = {
                "product_name": product_name,
                "product_type": product_type,
                "main_category": main_category,
                "product_quantity": product_quantity,
                "product_price": product_price,
                "product_image": product_image_url,
                "store_name": store_name,  # Add the store name here
                "vendor_id": user_id,  # Optionally add the vendor's user ID
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            product_ref = db.child("products").push(new_product)
            
            # After successfully adding to Firebase, register on blockchain
            try:
                authenticator = RentalAuthenticator()
                authenticator.register_product(
                    product_id=product_ref.key(),
                    name=product_name
                )
                print(f"Product registered on blockchain with ID: {product_ref.key()}")
            except Exception as e:
                print(f"Blockchain registration error: {str(e)}")
                # Continue even if blockchain registration fails
                pass

            flash('Product added successfully!', 'success')
            return redirect(url_for('product_list'))
        except Exception as e:
            flash(f"Failed to add product: {str(e)}", 'danger')

    # Render the product addition form with the categories data
    return render_template('andshop/product-add.html', categories=categories_list)

def save_product_image(product_image):
    filename = secure_filename(product_image.filename)
    products_folder = os.path.join('static/uploads', 'products')
    os.makedirs(products_folder, exist_ok=True)
    filepath = os.path.join(products_folder, filename)
    product_image.save(filepath)
    return url_for('static', filename=f'uploads/products/{filename}')

@app.route('/add-product-page')
def add_product_page():
    return render_template('/andshop/product-add.html')  # Replace with your template name

from flask import current_app, session
import logging

@app.route('/product/<product_id>')
def product_detail(product_id):
    try:
        # Get product data
        product = db.child("products").child(product_id).get().val()
        if not product:
            return render_template('error.html', message="Product not found"), 404
            
        # Add the ID to the product data
        product['id'] = product_id
        
        # Get product reviews
        reviews = db.child("product_reviews").child(product_id).get().val() or {}
        
        # Get user info from session
        user_info = None
        if 'user_id' in session:
            user_info = db.child("users").child(session['user_id']).get().val()
        
        # Get cart count
        cart_count = 0
        if 'user_id' in session:
            cart = db.child("carts").child(session['user_id']).get().val()
            if cart:
                cart_count = sum(item.get('quantity', 0) for item in cart.values())
        
        # Check if user has purchased this product
        user_purchased = False
        if 'user_id' in session:
            user_id = session['user_id']
            orders = db.child("orders").get().val() or {}
            for order_id, order in orders.items():
                if order.get('user_id') == user_id:
                    order_items = order.get('items', [])
                    for item in order_items:
                        if item.get('product_id') == product_id:
                            user_purchased = True
                            break
                    if user_purchased:
                        break
        
        # Get product reviews
        product_reviews = []
        reviews = db.child("product_reviews").child(product_id).get().val() or {}
        for review_id, review in reviews.items():
            # Get user name for review
            user = db.child("users").child(review['user_id']).get().val()
            review['user_name'] = user.get('name', 'Anonymous') if user else 'Anonymous'
            product_reviews.append(review)
        
        app.logger.info(f"Session data: {session}")
        app.logger.info(f"User info: {user_info}")
        app.logger.info(f"Cart count: {cart_count}")
        
        return render_template('product.html',
                             product=product,
                             user_info=user_info,
                             cart_count=cart_count,
                             user_purchased=user_purchased,
                             product_reviews=product_reviews,
                             session=session)
                             
    except Exception as e:
        app.logger.error(f"Error in product_detail: {str(e)}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return render_template('error.html', message=str(e)), 500

def get_upsell_products(limit=5, exclude_id=None):
    try:
        all_products = db.child("products").get().val()
        if all_products:
            # Convert to list and shuffle
            products_list = list(all_products.items())
            random.shuffle(products_list)
            
            # Filter out the current product and limit the number of products
            upsell_products = [
                {**product, 'id': key} 
                for key, product in products_list 
                if key != exclude_id
            ][:limit]
            
            return upsell_products
        return []
    except Exception as e:
        app.logger.error(f"Error fetching upsell products: {str(e)}")
        return []
@app.route('/products')
def product_list():
    if 'user_info' not in session:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    user_info = session['user_info']
    try:
        # Fetch all products from the Firebase database
        products = db.child("products").get()
        product_list = products.val() if products else {}

        if not product_list:
            flash('No products found.', 'warning')

    except Exception as e:
        flash(f"Failed to fetch product list: {str(e)}", 'danger')
        return redirect(url_for('index'))  # Redirect to home or an appropriate page

    # Render the product list template with the fetched product data and user info
    return render_template('/andshop/product-list.html', products=product_list, user=user_info)
            # edit product_page 
@app.route('/edit-product/<product_id>', methods=['GET', 'POST'])
def update_product(product_id):
    # Check if user is logged in
    if 'user_info' not in session:
        flash('Please log in to edit products.', 'warning')
        return redirect(url_for('login'))

    user_info = session['user_info']
    print(f"Accessing edit-product route for product_id: {product_id}")
    
    try:
        # Retrieve the existing product data
        product = db.child("products").child(product_id).get().val()
        print(f"Product retrieved: {product}")

        if not product:
            print(f"Product with ID {product_id} not found in the database.")
            flash('Product not found.', 'danger')
            return redirect(url_for('product_list'))

        # Fetch categories
        categories = []
        categories_ref = db.child("categories").get()
        print("Fetching categories...")
        
        if categories_ref:
            for category in categories_ref.each():
                category_data = category.val()
                if category_data and isinstance(category_data, dict):
                    print(f"Processing category: {category_data}")
                    categories.append(category_data)
        
        print(f"Total categories found: {len(categories)}")

        if request.method == 'POST':
            # Extract form data
            product_name = request.form.get('product_name', product['product_name'])
            product_quantity = request.form.get('product_quantity', product['product_quantity'])
            main_category = request.form.get('main_category', product['main_category'])
            product_price = request.form.get('product_price', product['product_price'])

            # Prepare data for update
            update_data = {
                "product_name": product_name,
                "product_quantity": product_quantity,
                "main_category": main_category,
                "product_price": product_price
            }

            # Handle product image
            product_image = request.files.get('product_image')
            if product_image:
                filename = secure_filename(product_image.filename)
                image_path = os.path.join('static/img/products', filename)
                print(f"Saving product image to {image_path}")
                product_image.save(image_path)
                update_data['product_image'] = image_path
            else:
                # Keep existing image if no new image is uploaded
                update_data['product_image'] = product.get('product_image')

            # Update the product in the database
            db.child("products").child(product_id).update(update_data)
            print("Product successfully updated.")
            flash('Product updated successfully!', 'success')
            return redirect(url_for('product_list'))

        # Render the edit product page if the request method is GET
        return render_template(
            'andshop/edit_product.html',
            product=product,
            product_id=product_id,
            user_info=user_info,
            categories=categories  # Pass categories to template
        )

    except Exception as e:
        print(f"Exception caught: {str(e)}")
        flash(f"Failed to update product: {str(e)}", 'danger')
        return redirect(url_for('product_list'))
# delete_product
@app.route('/delete-product/<product_id>', methods=['POST'])
def delete_product(product_id):
    try:
        # Delete the product from the Firebase database
        db.child("products").child(product_id).remove()
        flash('Product deleted successfully!', 'success')
    except Exception as e:
        flash(f"Failed to delete product: {str(e)}", 'danger')
    
    return redirect(url_for('product_list'))
 # Updated path
@app.route('/add-category', methods=['GET', 'POST'])
def add_category():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    try:
        user_id = session['user_id']
        user_info = db.child("users").child(user_id).get().val()
        
        if not user_info or user_info.get('user_type') != 'Admin':
            flash('Unauthorized access.', 'danger')
            return redirect(url_for('dashboard'))

        existing_categories = db.child("categories").get().val()
        error_message = ''
        success_message = ''

        if request.method == 'POST':
            category_name = request.form.get('category_name')
            
            if not category_name:
                error_message = 'Category name is required.'
            elif existing_categories:
                if any(cat['name'].lower() == category_name.lower() for cat in existing_categories.values()):
                    error_message = 'Category already exists.'
                else:
                    # Add new category
                    new_category = {
                        'name': category_name,
                        'status': 'active',
                        'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    db.child("categories").push(new_category)
                    success_message = 'Category added successfully.'
            else:
                # If no categories exist, add the first one
                new_category = {
                    'name': category_name,
                    'status': 'active',
                    'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                db.child("categories").push(new_category)
                success_message = 'Category added successfully.'

        return render_template('Admin/add-category.html', 
                               user_info=user_info, 
                               error_message=error_message,
                               success_message=success_message)

    except Exception as e:
        app.logger.error(f"Error in add_category: {str(e)}")
        flash('An error occurred while processing your request. Please try again.', 'danger')
        return redirect(url_for('admin_dashboard'))
@app.route('/categories', methods=['GET'])
def categories():
    try:
        # Check if user is logged in
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))

        # Fetch categories from Firebase
        categories_data = db.child("categories").get().val()
        print("Raw categories data:", categories_data)  # Debug print
        
        # Convert data into a list of dictionaries for easier processing
        categories_list = []
        if categories_data:
            for key, value in categories_data.items():
                categories_list.append({
                    "id": key,
                    "name": value.get('name', 'N/A'),
                    "status": value.get('status', 'inactive'),
                    "created_at": value.get('created_at', 'N/A')
                })
        
        print("Processed categories list:", categories_list)  # Debug print

        # Fetch user info
        user_info = db.child("users").child(session['user_id']).get().val()
        if not user_info or user_info.get('user_type') != 'Admin':
            flash('Unauthorized access.', 'danger')
            return redirect(url_for('dashboard'))

        # Pass the categories list and user info to the template
        return render_template('Admin/main-category.html', categories=categories_list, user_info=user_info)
        
    except Exception as e:
        error_message = f"Error fetching categories: {str(e)}"
        print(error_message)  # Print to console for debugging
        flash(error_message, 'danger')
        return redirect(url_for('login'))

@app.route('/main-category')
def main_category():
    return categories()

import logging
from flask import abort, render_template
import requests
def get_user_id_by_email(email):
    try:
        users = db.child("users").order_by_child("email").equal_to(email).get().val()
        print(f"Users data for email {email}: {users}")  # Debug print
        if users:
            user_id = list(users.keys())[0]
            print(f"Found user ID: {user_id}")  # Debug print
            return user_id
        else:
            print(f"No user found for email: {email}")  # Debug print
    except Exception as e:
        print(f"Error in get_user_id_by_email: {str(e)}")
        traceback.print_exc()
    return None

def get_cart_count(user_id):
    try:
        cart_items = db.child("cart").order_by_child("user_id").equal_to(user_id).get().val()
        return len(cart_items) if cart_items else 0
    except Exception as e:
        print(f"Error getting cart count: {str(e)}")
        return 0
from decimal import Decimal

import logging
from decimal import Decimal, InvalidOperation

from flask import url_for

@app.route('/new-order')
def new_order():
    try:
        # Check if user is logged in
        if 'user_info' not in session:
            return redirect('/login')

        user_info = session['user_info']

        # Get all products
        products = db.child("products").get().val() or {}

        # Get all orders
        orders = db.child("orders").get().val() or {}
        
        processed_orders = []
        if orders:
            for order_id, order_data in orders.items():
                # Get items from the order
                items = order_data.get('items', [])
                created_at = order_data.get('created_at', '')  # Get the order creation date
                
                # Process each item as a separate order row
                for item in items:
                    if item.get('store_name') == user_info.get('store_name'):
                        order_row = {
                            'order_id': order_id,
                            'product_id': item.get('product_id'),
                            'quantity': item.get('quantity', 1),
                            'total_price': item.get('total_price', 0),
                            'rent_from': item.get('rent_from', ''),
                            'rent_to': item.get('rent_to', ''),
                            'status': item.get('status', 'Unknown'),
                            'store_name': item.get('store_name'),
                            'shipping_address': order_data.get('shipping_address', ''),
                            'shipping_district': order_data.get('shipping_district', ''),
                            'created_at': created_at  # Add creation date to order row
                        }
                        processed_orders.append(order_row)

        # Sort processed orders by created_at in descending order (latest first)
        processed_orders.sort(key=lambda x: x.get('created_at', ''), reverse=True)

        return render_template('andshop/new-order.html', 
                            user_info=user_info, 
                            orders=processed_orders,
                            products=products)
    except Exception as e:
        app.logger.error(f"Error in new_order: {str(e)}")
        app.logger.error(traceback.format_exc())
        return redirect('/index')

@app.route('/add-to-cart', methods=['POST'])
def add_to_cart():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 403
    
    try:
        data = request.get_json()
        if not data or 'product_id' not in data:
            return jsonify({'success': False, 'message': 'Invalid request data'}), 400

        user_id = session['user_id']
        product_id = data['product_id']
        quantity = data.get('quantity', 1)

        # Fetch the product from the database
        product = db.child("products").child(product_id).get().val()
        if not product:
            return jsonify({'success': False, 'message': 'Product not found'}), 404

        current_stock = int(product.get('product_quantity', 0))
        if current_stock <= 0:
            return jsonify({'success': False, 'message': 'This product is out of stock'}), 200

        # Check if the product already exists in the cart
        existing_item = db.child("cart").order_by_child("user_id").equal_to(user_id).get().val()
        if existing_item:
            for item_key, item in existing_item.items():
                if item.get('product_id') == product_id:
                    # Update quantity if the product is already in the cart
                    new_quantity = item['quantity'] + quantity
                    db.child("cart").child(item_key).update({"quantity": new_quantity})
                    cart_count = get_cart_count(user_id)
                    return jsonify({'success': True, 'message': f'Cart updated. New quantity: {new_quantity}', 'cart_count': cart_count}), 200
            
        # If the product is not in the cart, add it
        cart_item = {
            "product_id": product_id,
            "quantity": quantity,
            "user_id": user_id,
        }
        db.child("cart").push(cart_item)

        cart_count = get_cart_count(user_id)
        return jsonify({'success': True, 'message': 'Product added to cart!', 'cart_count': cart_count}), 200

    except Exception as e:
        app.logger.error(f"Error adding to cart: {str(e)}")
        return jsonify({'success': False, 'message': f"An error occurred: {str(e)}"}), 500

@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', error=str(e.description)), 400
@app.route('/cart')
@app.route('/cart/')
def cart():
    if 'user_id' not in session:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    print(f"User ID: {user_id}")  # Debug print

    try:
        # Fetch cart items for the logged-in user from Firebase
        cart_data = db.child("cart").order_by_child("user_id").equal_to(user_id).get().val()
        
        print("Fetched cart data:", cart_data)  # Debug print to check fetched data
        
        cart_items = []
        if cart_data:
            for cart_item_id, cart_item in cart_data.items():
                print(f"Processing cart item: {cart_item_id}, {cart_item}")  # Debug print
                product_id = cart_item.get('product_id')
                if not product_id:
                    print(f"No product_id found for cart item: {cart_item_id}")
                    continue

                # Fetch product details from the products table
                product_details = db.child("products").child(product_id).get().val()
                print(f"Product details for {product_id}: {product_details}")  # Debug print
                
                if product_details:
                    cart_items.append({
                        "cart_item_id": cart_item_id,
                        "product_id": product_id,
                        "product_image": product_details.get('product_image', ''),
                        "product_name": product_details.get('product_name', ''),
                        "product_price": float(product_details.get('product_price', 0)),
                        "product_quantity": int(cart_item.get('quantity', 1)),
                        "total_price": float(product_details.get('product_price', 0)) * int(cart_item.get('quantity', 1))
                    })
                else:
                    print(f"No product details found for product_id: {product_id}")
            print(f"Processed cart items: {cart_items}")  # Debug print
        else:
            print("No cart data found for the user.")  # Debug print if no data is found

        for item in cart_items:
            item['product_price'] = f"₹{item['product_price']:.2f}"
            item['total_price'] = f"₹{item['total_price']:.2f}"

    except Exception as e:
        print(f"Error fetching cart items: {str(e)}")  # Print the error message
        traceback.print_exc()  # Print the full traceback
        flash(f"Failed to fetch cart items: {str(e)}", 'danger')
        cart_items = []

    return render_template('cart.html', cart_items=cart_items, user_id=user_id)

@app.route('/update-cart', methods=['POST'])
def update_cart():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 403

    user_id = session['user_id']
    
    try:
        cart_data = request.json
        logging.debug(f'Received cart data: {cart_data}')

        if not isinstance(cart_data, dict) or 'cart' not in cart_data:
            return jsonify({'success': False, 'message': 'Invalid data format'}), 400

        cart_items = cart_data['cart']
        total_amount = 0
        updated_items = []

        # Fetch all cart items for the user
        user_cart = db.child("cart").order_by_child("user_id").equal_to(user_id).get().val()

        for item in cart_items:
            product_id = item.get('product_id')
            requested_quantity = int(item.get('quantity', 1))
            
            # Fetch the current product data from the products table
            product = db.child("products").child(product_id).get().val()
            logging.debug(f'Product data for {product_id}: {product}')
            
            if product:
                product_name = product.get('product_name', 'Unknown Product')
                product_price = float(product.get('product_price', 0))
                product_quantity = int(product.get('product_quantity', 0))
                
                # Limit the quantity to the available quantity
                quantity = min(requested_quantity, product_quantity)
                
                # Find the existing cart item for this product
                existing_cart_item_key = None
                existing_cart_item = None
                for key, cart_item in user_cart.items():
                    if cart_item.get('product_id') == product_id:
                        existing_cart_item_key = key
                        existing_cart_item = cart_item
                        break

                # Calculate rental days and total price
                rent_from = existing_cart_item.get('rent_from') if existing_cart_item else None
                rent_to = existing_cart_item.get('rent_to') if existing_cart_item else None
                
                if rent_from and rent_to:
                    rent_from_date = datetime.strptime(rent_from, '%Y-%m-%d')
                    rent_to_date = datetime.strptime(rent_to, '%Y-%m-%d')
                    rental_days = (rent_to_date - rent_from_date).days + 1
                    total_price = product_price * quantity * rental_days
                else:
                    rental_days = 0
                    total_price = 0

                # Update the existing cart item or create a new one
                if existing_cart_item_key:
                    db.child("cart").child(existing_cart_item_key).update({
                        "quantity": quantity,
                        "total_price": total_price,
                        "max_quantity": product_quantity,
                        "rental_days": rental_days
                    })
                else:
                    db.child("cart").push({
                        "product_id": product_id,
                        "quantity": quantity,
                        "total_price": total_price,
                        "user_id": user_id,
                        "max_quantity": product_quantity,
                        "rental_days": rental_days
                    })
                
                total_amount += total_price
                updated_items.append({
                    "product_id": product_id,
                    "product_name": product_name,
                    "quantity": quantity,
                    "max_quantity": product_quantity,
                    "total_price": total_price,
                    "rental_days": rental_days
                })
            else:
                logging.warning(f"Product {product_id} not found in the database.")

        return jsonify({
            'success': True, 
            'total': total_amount,
            'updated_items': updated_items
        }), 200

    except Exception as e:
        logging.error(f"Error updating cart: {str(e)}")
        logging.error(traceback.format_exc())
        return jsonify({'success': False, 'message': str(e)}), 500

from flask import jsonify, request
import logging

@app.route('/update-rent-dates', methods=['POST'])
def update_rent_dates():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in to update rent dates.'}), 401

    user_id = session['user_id']

    try:
        data = request.get_json()
        logging.info(f"Received data: {data}")  # Debug log

        cart_item_id = data.get('cart_item_id')
        rent_from = data.get('rent_from')
        rent_to = data.get('rent_to')

        if not cart_item_id or not rent_from or not rent_to:
            logging.error(f"Missing required data: cart_item_id={cart_item_id}, rent_from={rent_from}, rent_to={rent_to}")
            return jsonify({'success': False, 'message': 'Missing required data.'}), 400

        # Update the cart item in the database
        cart_item = db.child("cart").child(cart_item_id).get().val()
        logging.info(f"Cart item: {cart_item}")  # Debug log

        if cart_item and str(cart_item.get('user_id')) == str(user_id):
            # Calculate rental days and total price
            rent_from_date = datetime.strptime(rent_from, '%Y-%m-%d')
            rent_to_date = datetime.strptime(rent_to, '%Y-%m-%d')
            rental_days = (rent_to_date - rent_from_date).days + 1

            product_id = cart_item.get('product_id')
            product_details = db.child("products").child(product_id).get().val()
            if product_details:
                price_per_unit = float(product_details.get('product_price', 0))
                quantity = int(cart_item.get('quantity', 1))
                total_price = price_per_unit * quantity * rental_days

                db.child("cart").child(cart_item_id).update({
                    "rent_from": rent_from,
                    "rent_to": rent_to,
                    "rental_days": rental_days,
                    "total_price": total_price
                })
                logging.info("Rent dates, rental days, and total price updated successfully")
                return jsonify({'success': True, 'message': 'Rent dates updated successfully', 'rental_days': rental_days, 'total_price': total_price}), 200
            else:
                logging.error(f"Product details not found for product_id: {product_id}")
                return jsonify({'success': False, 'message': 'Product details not found.'}), 404
        else:
            logging.error(f"Cart item not found or unauthorized. cart_item={cart_item}, user_id={user_id}")
            return jsonify({'success': False, 'message': 'Cart item not found or unauthorized.'}), 404

    except Exception as e:
        logging.error(f"Error updating rent dates: {str(e)}")
        return jsonify({'success': False, 'message': f"An error occurred: {str(e)}"}), 500

# Make sure to configure logging at the top of your app.py file
logging.basicConfig(level=logging.DEBUG)

@app.route('/remove-from-cart/<item_key>', methods=['POST'])
def remove_from_cart(item_key):
    if 'user_id' not in session:
        logging.error("User not logged in")
        return jsonify({'success': False, 'message': 'User not logged in'}), 403

    user_id = session['user_id']
    logging.info(f"Attempting to remove item {item_key} for user {user_id}")

    try:
        # Fetch the cart item
        cart_item = db.child("cart").child(item_key).get().val()
        logging.info(f"Cart item data: {cart_item}")

        if cart_item and cart_item.get('user_id') == user_id:
            # Attempt to remove the item
            db.child("cart").child(item_key).remove()
            
            # Verify if the item was removed
            removed_item = db.child("cart").child(item_key).get().val()
            if removed_item is None:
                logging.info(f"Item {item_key} successfully removed from database")
            else:
                logging.error(f"Failed to remove item {item_key} from database")

            product_id = cart_item.get('product_id')
            product = db.child("products").child(product_id).get().val()
            product_name = product.get('product_name', 'Unknown Product') if product else 'Unknown Product'
            
            return jsonify({
                'success': True, 
                'message': f'{product_name} removed from cart successfully',
                'removed_item_key': item_key
            }), 200
        else:
            logging.warning(f"Cart item {item_key} not found or doesn't belong to user {user_id}")
            return jsonify({'success': False, 'message': 'Cart item not found or unauthorized'}), 404
    except Exception as e:
        logging.error(f"Error removing item from cart: {str(e)}")
        logging.error(traceback.format_exc())
        return jsonify({'success': False, 'message': str(e)}), 500
stripe.api_key = 'sk_test_51Pqv8iRsdj1Rwn4ZPqX8neIYjhGs1FPpWoTC7zuT1O1i9qQ1G8BivIbcx9Clzf1kE0AKiVcyOn0a8CpIz1oF75Y500FziKufLt'

@app.route('/checkout', methods=['GET'])
def checkout():
    if 'user_id' not in session:
        flash('Please log in to proceed with checkout', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    cart_items = get_cart_items()
    
    # Calculate total price considering rental days
    total_price = sum(
        item['product_price'] * item['quantity'] * item.get('rental_days', 1)
        for item in cart_items
    )

    # Fetch user details from the database
    user_details = db.child("users").child(user_id).get().val()

    return render_template('checkout.html', 
                           cart_items=cart_items, 
                           total_price=total_price,
                           user_details=user_details,
                           stripe_public_key='pk_test_51Pqv8iRsdj1Rwn4Zx6ePlGYpqKw0BC4wWhgxlyxYaqo9hQwJh8pMgWRVKgaFv2DP5IcAF9kuMdZN1DmrkaUVAsQQ008yNC3FFG')

from flask import jsonify, request, session, url_for
from decimal import Decimal

from flask import jsonify, request, session, url_for
from werkzeug.exceptions import HTTPException
import traceback
from decimal import Decimal, InvalidOperation

@app.route('/create-payment', methods=['POST'])
def create_payment():
    if 'user_id' not in session:
        return jsonify({'error': 'User not logged in'}), 403

    try:
        user_id = session['user_id']
        
        # Get shipping information
        use_different_shipping = request.form.get('use_different_shipping') == 'true'
        shipping_address = request.form.get('shipping_address')
        shipping_district = request.form.get('shipping_district')
        
        # Get wallet deposit amount from form
        wallet_deposit = float(request.form.get('wallet_deposit', 1000))
        
        # Get cart items and create order items list
        order_items = []
        product_ids = request.form.getlist('product_ids[]')
        quantities = request.form.getlist('quantities[]')
        rent_from_dates = request.form.getlist('rent_from[]')
        rent_to_dates = request.form.getlist('rent_to[]')
        rental_days = request.form.getlist('rental_days[]')
        item_totals = request.form.getlist('item_totals[]')
        
        for i in range(len(product_ids)):
            order_items.append({
                'product_id': product_ids[i],
                'quantity': int(quantities[i]),
                'rent_from': rent_from_dates[i],
                'rent_to': rent_to_dates[i],
                'rental_days': int(rental_days[i]),
                'total_price': float(item_totals[i])
            })
        
        order_total = float(request.form.get('order_total', 0))
        subtotal = order_total - wallet_deposit  # Calculate subtotal
        
        # Create order in database with wallet deposit
        order_id = create_order_in_database(
            user_id=user_id,
            order_items=order_items,
            order_total=order_total,
            use_different_shipping=use_different_shipping,
            shipping_address=shipping_address,
            shipping_district=shipping_district,
            wallet_deposit=wallet_deposit
        )
        
        # Process payment
        payment_success, payment_intent_id = process_payment(order_total)
        
        if payment_success:
            # Clear cart after successful payment
            clear_cart(user_id)
            
            return jsonify({
                'success': True,
                'redirect_url': url_for('payment_success', order_id=order_id)
            })
        else:
            return jsonify({'error': 'Payment failed'}), 400
            
    except Exception as e:
        app.logger.error(f"Error in create_payment: {str(e)}")
        return jsonify({'error': str(e)}), 500

def create_order_in_database(user_id, order_items, order_total, use_different_shipping, 
                           shipping_address, shipping_district, wallet_deposit):
    try:
        order_id = str(uuid.uuid4())
        current_time = datetime.now().isoformat()
        
        # Set initial status for each item
        for item in order_items:
            product_id = item.get('product_id')
            product_details = get_product_details(product_id)
            item['store_name'] = product_details.get('store_name', 'Unknown Store')
            if 'status' not in item:
                item['status'] = 'ordered'
                item['ordered_at'] = current_time

        # Create order data structure with wallet deposit
        order_data = {
            'order_id': order_id,
            'user_id': user_id,
            'items': order_items,
            'order_total': order_total,
            'wallet_deposit': float(wallet_deposit),  # Ensure it's stored as float
            'subtotal': float(order_total - wallet_deposit),  # Calculate and store subtotal
            'use_different_shipping': use_different_shipping,
            'shipping_address': shipping_address,
            'shipping_district': shipping_district,
            'status': 'pending',
            'created_at': current_time
        }
        
        # Push to Firebase
        new_order = db.child("orders").push(order_data)
        
        # Create wallet transaction record
        wallet_transaction = {
            'user_id': user_id,
            'amount': float(wallet_deposit),
            'type': 'deposit',
            'order_id': order_id,
            'status': 'active',
            'created_at': current_time
        }
        db.child("wallet_transactions").push(wallet_transaction)
        
        return order_id
        
    except Exception as e:
        app.logger.error(f"Error creating order in database: {str(e)}")
        raise

@app.errorhandler(Exception)
def handle_exception(e):
    # Pass through HTTP errors
    if isinstance(e, HTTPException):
        return jsonify({'success': False, 'error': str(e)}), e.code
    
    # Now you're handling non-HTTP exceptions only
    app.logger.error(f"Unhandled Exception: {str(e)}")
    app.logger.error(traceback.format_exc())
    return jsonify({'success': False, 'error': 'An unexpected error occurred'}), 500

# Make sure to implement these functions according to your needs:
# create_order_in_database, process_payment, update_order_status, clear_cart
@app.errorhandler(Exception)
def handle_exception(e):
    # Pass through HTTP errors
    if isinstance(e, HTTPException):
        return jsonify({'success': False, 'error': str(e)}), e.code
    
    # Now you're handling non-HTTP exceptions only
    app.logger.error(f"Unhandled Exception: {str(e)}")
    app.logger.error(traceback.format_exc())
    return jsonify({'success': False, 'error': 'An unexpected error occurred'}), 500

def process_payment(amount):
    try:
        # Implement your payment processing logic here
        # This is just a placeholder
        payment_success = True
        payment_intent_id = 'pi_' + ''.join(random.choices(string.ascii_letters + string.digits, k=24))
        return payment_success, payment_intent_id
    except Exception as e:
        app.logger.error(f"Error processing payment: {str(e)}")
        raise

def clear_cart(user_id):
    try:
        db.reference(f'carts/{user_id}').delete()
    except Exception as e:
        app.logger.error(f"Error clearing cart: {str(e)}")
        raise

def process_payment(amount):
    # Implement your payment processing logic here
    # This is just a placeholder
    payment_success = True
    payment_intent_id = 'pi_' + ''.join(random.choices(string.ascii_letters + string.digits, k=24))
    return payment_success, payment_intent_id

def process_payment(amount):
    # Implement your payment processing logic here
    # This is just a placeholder
    payment_success = True
    payment_intent_id = 'pi_' + ''.join(random.choices(string.ascii_letters + string.digits, k=24))
    return payment_success, payment_intent_id

def create_order_in_database(user_id, order_items, order_total, use_different_shipping, shipping_address, shipping_address2):
    # Implement your order creation logic here
    # This is just a placeholder
    order_data = {
        'user_id': user_id,
        'items': order_items,
        'order_total': order_total,
        'use_different_shipping': use_different_shipping,
        'shipping_address': shipping_address,
        'shipping_address2': shipping_address2,
        'status': 'pending',
        'created_at': datetime.now().isoformat()
    }
    new_order = db.reference('orders').push(order_data)
    return new_order.key

def clear_cart(user_id):
    try:
        db.reference(f'carts/{user_id}').delete()
    except Exception as e:
        app.logger.error(f"Error clearing cart: {str(e)}")
        raise

def process_payment(amount):
    try:
        # Implement your payment processing logic here
        # This is just a placeholder
        payment_success = True
        payment_intent_id = 'pi_' + ''.join(random.choices(string.ascii_letters + string.digits, k=24))
        return payment_success, payment_intent_id
    except Exception as e:
        app.logger.error(f"Error processing payment: {str(e)}")
        raise

@app.route('/save-order', methods=['POST'])
def save_order():
    if 'user_id' not in session:
        return jsonify({'error': 'User not logged in'}), 403

    user_id = session['user_id']
    data = request.json
    order_id = data.get('order_id')
    payment_intent_id = data.get('payment_intent_id')

    try:
        # Get cart items
        cart_items = get_cart_items()
        
        # Save order to the database
        order_data = {
            'order_id': order_id,
            'user_id': user_id,
            'payment_intent_id': payment_intent_id,
            'items': cart_items,
            'total_amount': sum(item['total_price'] for item in cart_items),
            'status': 'paid',
            'created_at': datetime.now().isoformat()
        }
        db.child("orders").push(order_data)

        # Clear the user's cart
        cart_ref = db.child("cart").order_by_child("user_id").equal_to(user_id)
        cart_items = cart_ref.get().val()
        if cart_items:
            for item_key in cart_items.keys():
                db.child("cart").child(item_key).remove()

        return jsonify({'success': True, 'order_id': order_id})
    except Exception as e:
        print(f"Error saving order: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/payment-success/<order_id>')
def payment_success(order_id):
    try:
        # Fetch all orders
        all_orders = db.child("orders").get().val()
        app.logger.info(f"All orders: {all_orders}")  # Debug log
        
        order_data = None
        if all_orders:
            for key, order in all_orders.items():
                if order.get('order_id') == order_id:
                    order_data = order
                    break
        
        if order_data:
            app.logger.info(f"Order found: {order_data}")
            
            # Fetch product details for each item in the order
            for item in order_data.get('items', []):
                product_id = item.get('product_id')
                if product_id:
                    product = db.child("products").child(product_id).get().val()
                    if product:
                        item['product_name'] = product.get('product_name', 'Unknown Product')
                    else:
                        item['product_name'] = 'Product Not Found'
                else:
                    item['product_name'] = 'Unknown Product'
            
            return render_template('payment_success.html', order=order_data)
        else:
            app.logger.warning(f"Order not found for ID: {order_id}")
            return render_template('payment_success.html', order=None, error=f"Order not found for ID: {order_id}")
    except Exception as e:
        app.logger.error(f"Error in payment_success route: {str(e)}")
        return render_template('payment_success.html', order=None, error=f"An error occurred: {str(e)}")

def process_payment(amount):
    # Implement your payment processing logic here
    # This is just a placeholder
    payment_success = True
    payment_intent_id = 'pi_' + ''.join(random.choices(string.ascii_letters + string.digits, k=24))
    return payment_success, payment_intent_id

def create_order_in_database(user_id, order_items, order_total, use_different_shipping, shipping_address, shipping_district, wallet_deposit=1000):
    try:
        order_id = str(uuid.uuid4())  # Generate a unique order ID
        
        # Set initial status for each item
        for item in order_items:
            product_id = item.get('product_id')
            product_details = get_product_details(product_id)
            item['store_name'] = product_details.get('store_name', 'Unknown Store')
            if 'status' not in item:
                item['status'] = 'ordered'
                item['ordered_at'] = datetime.now().isoformat()

        order_data = {
            'order_id': order_id,
            'user_id': user_id,
            'items': order_items,
            'order_total': order_total,
            'wallet_deposit': wallet_deposit,  # Add this line
            'subtotal': order_total - wallet_deposit,  # Add this line
            'use_different_shipping': use_different_shipping,
            'shipping_address': shipping_address,
            'shipping_district': shipping_district,
            'status': 'pending',
            'created_at': datetime.now().isoformat()
        }
        
        # Push to Firebase
        new_order = db.child("orders").push(order_data)
        
        # Create wallet transaction record
        wallet_transaction = {
            'user_id': user_id,
            'amount': wallet_deposit,
            'type': 'deposit',
            'order_id': order_id,
            'status': 'active',
            'created_at': datetime.now().isoformat()
        }
        db.child("wallet_transactions").push(wallet_transaction)
        
        return order_id
        
    except Exception as e:
        app.logger.error(f"Error creating order in database: {str(e)}")
        raise

def get_product_details(product_id):
    try:
        product = db.child("products").child(product_id).get().val()
        if product:
            return {
                'product_name': product.get('product_name', 'Unknown Product'),
                'product_image': product.get('product_image', ''),
                'store_name': product.get('store_name', 'Unknown Store')
            }
        else:
            return {'product_name': 'Unknown Product', 'product_image': '', 'store_name': 'Unknown Store'}
    except Exception as e:
        app.logger.error(f"Error fetching product details for ID {product_id}: {str(e)}")
        return {'product_name': 'Unknown Product', 'product_image': '', 'store_name': 'Unknown Store'}

def clear_cart(user_id):
    try:
        db.child("cart").order_by_child("user_id").equal_to(user_id).remove()
    except Exception as e:
        app.logger.error(f"Error clearing cart: {str(e)}")
        raise

def get_cart_items():
    if 'user_id' not in session:
        return []

    user_id = session['user_id']
    try:
        # Fetch cart items for the logged-in user from Firebase
        cart_data = db.child("cart").order_by_child("user_id").equal_to(user_id).get().val()
        
        cart_items = []
        if cart_data:
            for cart_item_id, cart_item in cart_data.items():
                product_id = cart_item.get('product_id')
                if not product_id:
                    continue

                # Fetch product details from the products table
                product_details = db.child("products").child(product_id).get().val()
                
                if product_details:
                    quantity = int(cart_item.get('quantity', 1))
                    price = float(product_details.get('product_price', 0))
                    rent_from = cart_item.get('rent_from', '')
                    rent_to = cart_item.get('rent_to', '')
                    
                    # Calculate rental days
                    rental_days = 1
                    if rent_from and rent_to:
                        rent_from_date = datetime.strptime(rent_from, '%Y-%m-%d')
                        rent_to_date = datetime.strptime(rent_to, '%Y-%m-%d')
                        rental_days = (rent_to_date - rent_from_date).days + 1

                    cart_items.append({
                        "cart_item_id": cart_item_id,
                        "product_id": product_id,
                        "product_image": product_details.get('product_image', ''),
                        "product_name": product_details.get('product_name', ''),
                        "product_price": price,
                        "quantity": quantity,
                        "rent_from": rent_from,
                        "rent_to": rent_to,
                        "rental_days": rental_days
                    })

        return cart_items
    except Exception as e:
        print(f"Error fetching cart items: {str(e)}")
        return []
@app.route('/wishlist')
def wishlist():
    app.logger.info("Accessing wishlist route")
    app.logger.info(f"Session contents: {session}")

    if 'user_id' not in session or 'user_info' not in session:
        app.logger.warning("User not logged in, redirecting to login page")
        flash('Please log in to view your wishlist.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_info = session['user_info']
    user_name = user_info.get('name', 'User')
    email = user_info.get('email', '')

    app.logger.info(f"User ID: {user_id}")
    app.logger.info(f"User name: {user_name}")
    app.logger.info(f"User email: {email}")

    # Fetch wishlist items (you'll need to implement this function)
    wishlist_items = get_wishlist_items_from_database(user_id)

    return render_template('wishlist.html', 
                           user_name=user_name,
                           email=email,
                           user_info=user_info,  # Pass the entire user_info dictionary
                           wishlist_items=wishlist_items)

@app.route('/get-wishlist-items')
def get_wishlist_items():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 403

    user_id = session['user_id']
    try:
        wishlist_items = get_wishlist_items_from_database(user_id)
        return jsonify({'success': True, 'wishlist_items': wishlist_items})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/add-to-wishlist', methods=['POST'])
def add_to_wishlist():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 403
    
    try:
        data = request.get_json()
        if not data or 'product_id' not in data:
            return jsonify({'success': False, 'message': 'Invalid request data'}), 400

        user_id = session['user_id']
        product_id = data['product_id']

        # Check if the product already exists in the wishlist
        existing_item = db.child("wishlist").order_by_child("user_id").equal_to(user_id).get().val()
        if existing_item:
            for item in existing_item.values():
                if item.get('product_id') == product_id:
                    return jsonify({'success': False, 'message': 'Product already in wishlist'}), 200
        
        # Add to wishlist
        wishlist_item = {
            "product_id": product_id,
            "user_id": user_id,
        }
        db.child("wishlist").push(wishlist_item)

        return jsonify({'success': True, 'message': 'Product added to wishlist!'}), 200

    except Exception as e:
        app.logger.error(f"Error adding to wishlist: {str(e)}")
        return jsonify({'success': False, 'message': f"An error occurred: {str(e)}"}), 500

@app.route('/remove-from-wishlist', methods=['POST'])
def remove_from_wishlist():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 403

    user_id = session['user_id']
    data = request.get_json()
    product_id = data.get('product_id')

    try:
        # Find and remove the wishlist item
        wishlist_items = db.child("wishlist").order_by_child("user_id").equal_to(user_id).get().val()
        if wishlist_items:
            for item_key, item_data in wishlist_items.items():
                if item_data.get('product_id') == product_id:
                    db.child("wishlist").child(item_key).remove()
                    return jsonify({'success': True, 'message': 'Product removed from wishlist'})

        return jsonify({'success': False, 'message': 'Product not found in wishlist'}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

def get_wishlist_items_from_database(user_id):
    try:
        wishlist_data = db.child("wishlist").order_by_child("user_id").equal_to(user_id).get().val()
        wishlist_items = []

        if wishlist_data:
            for item_key, item_data in wishlist_data.items():
                product_id = item_data.get('product_id')
                product_details = db.child("products").child(product_id).get().val()

                if product_details:
                    wishlist_items.append({
                        'product_id': product_id,
                        'product_name': product_details.get('product_name', ''),
                        'product_image': product_details.get('product_image', ''),
                        'product_price': float(product_details.get('product_price', 0)),
                        'stock_status': 'In Stock' if int(product_details.get('product_quantity', 0)) > 0 else 'Out of Stock'
                    })

        return wishlist_items
    except Exception as e:
        print(f"Error fetching wishlist items: {str(e)}")
        return []

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from io import BytesIO
from reportlab.lib.enums import TA_CENTER
from datetime import datetime

@app.route('/download_order_pdf/<order_id>')
def download_order_pdf(order_id):
    order = db.child("orders").child(order_id).get().val()
    
    if not order:
        return "Order not found", 404

    # Fetch user details
    user_id = order.get('user_id')
    user_data = db.child("users").child(user_id).get().val()
    user_name = user_data.get('name', 'N/A') if user_data else 'N/A'
    user_email = user_data.get('email', 'N/A') if user_data else 'N/A'

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    
    elements = []
    styles = getSampleStyleSheet()

    # Header
    elements.append(Paragraph("INVOICE", styles['Title']))
    elements.append(Spacer(1, 0.25*inch))

    # Company Info
    elements.append(Paragraph("ToolHive", styles['Heading2']))
    elements.append(Paragraph("123 Business Street, Xyz, India", styles['Normal']))
    elements.append(Paragraph("Phone: +91 1800 567 890", styles['Normal']))
    elements.append(Paragraph("Email: toolhive@gmail.com", styles['Normal']))
    elements.append(Paragraph("GSTIN: 29AAAAA0000A1Z5", styles['Normal']))
    elements.append(Spacer(1, 0.25*inch))

    # Customer and Order Info
    data = [
        ["Order ID:", order_id],
        ["Date:", order.get('created_at', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))],
        ["Customer:", user_name],
        ["Email:", user_email]
    ]
    table = Table(data, colWidths=[2*inch, 4*inch])
    table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTNAME', (1,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 0.25*inch))

    # Order Items
    data = [["Item", "Store Name", "Quantity", "Price/Day", "Rent From", "Rent To", "Days", "Total"]]
    
    for item in order.get('items', []):
        product_id = item.get('product_id')
        product_data = db.child("products").child(product_id).get().val()
        
        # Get store name directly from the item
        store_name = item.get('store_name', 'Store Not Found')
        
        data.append([
            product_data.get('product_name', 'Product Not Found') if product_data else 'Product Not Found',
            store_name,
            str(item.get('quantity', 0)),
            f"₹{float(product_data.get('product_price', 0)):.2f}" if product_data else '₹0.00',
            item.get('rent_from', 'N/A'),
            item.get('rent_to', 'N/A'),
            str(item.get('rental_days', 0)),
            f"₹{float(item.get('item_total', 0)):.2f}"
        ])

    # Add total row
    total_price = float(order.get('order_total', 0))
    data.append(["Total", "", "", "", "", "", "", f"₹{total_price:.2f}"])

    table = Table(data, colWidths=[1.2*inch, 1.2*inch, 0.5*inch, 0.7*inch, 0.7*inch, 0.7*inch, 0.5*inch, 0.8*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 10),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,-1), (-1,-1), colors.grey),
        ('TEXTCOLOR', (0,-1), (-1,-1), colors.whitesmoke),
        ('FONTNAME', (0,-1), (-1,-1), 'Helvetica-Bold'),
        ('ALIGN', (0,1), (1,-1), 'LEFT'),
        ('ALIGN', (2,1), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 1, colors.black)
    ]))
    elements.append(table)

    # Footer
    elements.append(Spacer(1, 0.5*inch))
    elements.append(Paragraph("Thank you for your business!", styles['Normal']))

    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f'invoice_{order_id}.pdf', mimetype='application/pdf')
from flask import request, render_template, abort, session, redirect, url_for

from flask import render_template, abort, jsonify, session, redirect, url_for, flash
import traceback

@app.route('/order/<order_id>')
def order_details(order_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 403

    user_id = session['user_id']

    try:
        order = db.child("orders").child(order_id).get().val()

        if not order:
            return jsonify({'success': False, 'message': 'Order not found'}), 404

        if str(order.get('user_id')) != str(user_id):
            return jsonify({'success': False, 'message': 'You do not have permission to view this order'}), 403

        order_data = {
            'order_id': order_id,
            'created_at': order.get('created_at', 'N/A'),
            'status': order.get('status', 'N/A'),
            'order_total': float(order.get('order_total', 0)),
            'payment_id': order.get('payment_intent_id', 'N/A'),
            'shipping_address': order.get('shipping_address', 'N/A'),
            'items': []
        }

        items = order.get('items', [])
        for item in items:
            product_id = item.get('product_id')
            product_details = get_product_details(product_id) if product_id else {}
            order_data['items'].append({
                'product_name': product_details.get('product_name', 'Unknown Product'),
                'quantity': item.get('quantity', 'N/A'),
                'rent_from': item.get('rent_from', 'N/A'),
                'rent_to': item.get('rent_to', 'N/A'),
                'rental_days': item.get('rental_days', 'N/A'),
                'item_total': float(item.get('item_total', 0))
            })

        return jsonify({'success': True, 'order': order_data})

    except Exception as e:
        app.logger.error(f"Error in order_details: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

def get_product_details(product_id):
    try:
        product = db.child("products").child(product_id).get().val()
        logging.info(f"Raw product data for ID {product_id}: {product}")
        if product:
            return {
                'product_name': product.get('product_name', 'Unknown Product'),
                'product_image': product.get('product_image', ''),
                'store_name': product.get('store_name', 'Unknown Store'),
                'main_category': product.get('main_category', 'Unknown Category'),
                'item_total': product.get('item_total', 0)  # Changed from 'product_price' to 'item_total'
            }
        else:
            logging.warning(f"Product not found for ID: {product_id}")
            return {'product_name': 'Unknown Product', 'product_image': '', 'store_name': 'Unknown Store', 'main_category': 'Unknown Category', 'item_total': 0}
    except Exception as e:
        logging.error(f"Error fetching product details for ID {product_id}: {str(e)}")
        logging.error(traceback.format_exc())
        return {'product_name': 'Unknown Product', 'product_image': '', 'store_name': 'Unknown Store', 'main_category': 'Unknown Category', 'item_total': 0}

@app.route('/vendor-list')
def vendor_list():
    if 'user_id' not in session or 'email' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    email = session['email']

    try:
        user_info = db.child("users").child(user_id).get().val()
        if not user_info or user_info.get('user_type') != 'Admin':
            flash('Unauthorized access.', 'danger')
            return redirect(url_for('dashboard'))

        # Fetch all users from the database
        all_users = db.child("users").get().val()

        # Filter vendors
        vendors = {uid: user for uid, user in all_users.items() if user.get('user_type') == 'vendor'}

        return render_template('Admin/vendor-list.html', 
                               user_info=user_info, 
                               email=email,  # Pass email to the template
                               vendors=vendors)
    except Exception as e:
        app.logger.error(f"Error in vendor_list: {str(e)}")
        flash('An error occurred while loading the page. Please try again.', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/vendor-accept')
def vendor_accept():
    if 'user_id' not in session or 'email' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    try:
        user_info = db.child("users").child(session['user_id']).get().val()
        if not user_info or user_info.get('user_type') != 'Admin':
            raise ValueError("Unauthorized access")

        all_users = db.child("users").get().val()

        # Filter pending vendors
        pending_vendors = {uid: user for uid, user in all_users.items() if user.get('vendor_status') == 'pending'}

        return render_template('Admin/vendor-accept.html', 
                               user_info=user_info, 
                               email=session['email'], 
                               pending_vendors=pending_vendors)
    except Exception as e:
        app.logger.error(f"Error in vendor_accept: {str(e)}")
        flash('An error occurred while loading the page. Please try again.', 'danger')
        return redirect(url_for('admin_dashboard'))
@app.route('/approve-vendor/<vendor_id>')
def approve_vendor(vendor_id):
    if 'user_id' not in session or 'email' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    try:
        user_info = db.child("users").child(session['user_id']).get().val()
        if not user_info or user_info.get('user_type') != 'Admin':
            raise ValueError("Unauthorized access")

        # Update vendor status to approved and change user_type to vendor
        db.child("users").child(vendor_id).update({
            "vendor_status": "approved",
            "user_type": "vendor"
        })
        flash('Vendor has been approved successfully.', 'success')
    except Exception as e:
        app.logger.error(f"Error in approve_vendor: {str(e)}")
        flash('An error occurred while approving the vendor. Please try again.', 'danger')

    return redirect(url_for('vendor_accept'))

@app.route('/reject-vendor/<vendor_id>')
def reject_vendor(vendor_id):
    if 'user_id' not in session or 'email' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    try:
        user_info = db.child("users").child(session['user_id']).get().val()
        if not user_info or user_info.get('user_type') != 'Admin':
            raise ValueError("Unauthorized access")

        # Update vendor status to rejected and change user_type to customer
        db.child("users").child(vendor_id).update({
            "vendor_status": "rejected",
            "user_type": "customer"
        })
        flash('Vendor has been rejected.', 'success')
    except Exception as e:
        app.logger.error(f"Error in reject_vendor: {str(e)}")
        flash('An error occurred while rejecting the vendor. Please try again.', 'danger')

    return redirect(url_for('vendor_accept'))
def update_product_quantities(order_items):
    try:
        app.logger.info(f"Updating quantities for order items: {order_items}")
        for item in order_items:
            product_id = item.get('product_id')
            ordered_quantity = int(item.get('quantity', 0))  # Ensure this is an integer
            
            app.logger.info(f"Processing product ID: {product_id}, Ordered quantity: {ordered_quantity}")
            
            # Fetch current product data
            product = db.child("products").child(product_id).get().val()
            if product:
                current_quantity = int(product.get('product_quantity', 0))  # Convert to integer
                new_quantity = max(0, current_quantity - ordered_quantity)  # Ensure quantity doesn't go below 0
                
                app.logger.info(f"Product {product_id}: Current quantity: {current_quantity}, New quantity: {new_quantity}")
                
                # Update the product quantity
                db.child("products").child(product_id).update({'product_quantity': str(new_quantity)})  # Store as string
                
                app.logger.info(f"Updated quantity for product {product_id}. New quantity: {new_quantity}")
            else:
                app.logger.warning(f"Product not found for ID: {product_id}")
    except Exception as e:
        app.logger.error(f"Error updating product quantities: {str(e)}")
        app.logger.error(traceback.format_exc())
        raise
@app.route('/toggle-category-status/<id>', methods=['POST'])
def toggle_category_status(id):
    try:
        # Fetch the category
        category = db.child("categories").child(id).get().val()
        if not category:
            return jsonify({'success': False, 'message': 'Category not found'}), 404

        # Toggle the status
        new_status = 'inactive' if category.get('status') == 'active' else 'active'
        db.child("categories").child(id).update({'status': new_status})

        return jsonify({'success': True, 'message': f'Category status updated to {new_status}'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

import firebase_admin
from firebase_admin import credentials, auth as admin_auth

# Initialize Firebase Admin SDK (if not already done)
if not firebase_admin._apps:
    cred = credentials.Certificate('serviceAccountKey.json')
    firebase_admin.initialize_app(cred)

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_deactivation_email(user_id, reason):
    try:
        # Get the user's email from Firebase Authentication
        user = admin_auth.get_user(user_id)
        to_email = user.email

        # Email configuration
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        sender_email = "mail.rentaltools@gmail.com"
        sender_password = "ffnr ygih qpec mvsm"  # Your App Password

        # Create the email message
        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = to_email
        message['Subject'] = "Your account has been deactivated"

        link = url_for('login', _external=True)
        body = f"Your account has been deactivated. Reason: {reason}. For more information or to appeal this decision, please visit: {link}"
        message.attach(MIMEText(body, 'plain'))

        # Connect to the SMTP server and send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(message)
           

        return True

    except smtplib.SMTPAuthenticationError as e:
        app.logger.error(f"SMTP Authentication Error: {str(e)}")
        return False
    except Exception as e:
        app.logger.error(f"Error in send_deactivation_email: {str(e)}")
        return False

# The rest of your code remains the same

@app.route('/toggle-user-status/<user_id>', methods=['POST'])
def toggle_user_status(user_id):
    try:
        data = request.json
        new_status = data.get('status')
        reason = data.get('reason', '')
        # Get current user data from Realtime Database
        user_data = db.child("users").child(user_id).get().val()

        if not user_data:
            app.logger.warning(f"User {user_id} not found")
            return jsonify({'success': False, 'message': 'User not found'}), 404

        # Prepare update data for Realtime Database
        update_data = {"status": new_status}
        
        if new_status == 'inactive':
            update_data["deactivation_reason"] = reason
            update_data["deactivation_date"] = datetime.now().isoformat()
        else:
            # Remove deactivation reason and date when reactivating
            update_data["deactivation_reason"] = None
            update_data["deactivation_date"] = None

        # Update user data in the Realtime Database
        db.child("users").child(user_id).update(update_data)
        # Update user status in Firebase Authentication
        try:
            admin_auth.update_user(user_id, disabled=(new_status == 'inactive'))
            # Send deactivation email if the status is changed to inactive
            if new_status == 'inactive':
                if send_deactivation_email(user_id, reason):
                    app.logger.info(f"Deactivation email sent to user {user_id}")
                else:
                    app.logger.warning(f"Failed to send deactivation email to user {user_id}")

        except Exception as auth_e:
            app.logger.error(f"Failed to update user in Firebase Authentication: {str(auth_e)}")
            return jsonify({'success': False, 'message': f'Failed to update user status: {str(auth_e)}'}), 500

        return jsonify({
            'success': True,
            'message': f'User status updated to {new_status}',
            'current_status': new_status
        })

    except Exception as e:
        app.logger.error(f"Error in toggle_user_status for user {user_id}: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({'success': False, 'message': f'An error occurred while updating the user status: {str(e)}'}), 500



from flask import jsonify
@app.route('/get-user-status/<user_id>', methods=['GET'])
def get_user_status(user_id):
    try:
        user_ref = db.child("users").child(user_id)
        user_data = user_ref.get().val()
        if user_data:
            status = user_data.get('status', 'unknown')
            app.logger.info(f"User {user_id} status: {status}")
            return jsonify({
                'success': True,
                'status': status,
                'is_active': status == 'active'
            })
        else:
            app.logger.warning(f"User {user_id} not found")
            return jsonify({
                'success': False,
                'message': 'User not found'
            }), 404
    except Exception as e:
        app.logger.error(f"Error fetching user status for {user_id}: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while fetching the user status'
        }), 500
@app.route('/submit-review', methods=['POST'])
def submit_review():
    print("Received review submission request")
    if 'user_id' not in session:
        print("User not logged in")
        return jsonify({'success': False, 'message': 'Please log in to submit a review.'}), 401

    data = request.json
    print(f"Received data: {data}")
    user_id = session['user_id']
    product_id = data.get('product_id')
    rating = data.get('rating')
    review = data.get('review', '').strip()
    
    # Fetch user name from the session or database
    user_name = session.get('name', '')
    if not user_name:
        user_info = db.child("users").child(user_id).get().val()
        user_name = user_info.get('name', 'Anonymous') if user_info else 'Anonymous'

    print(f"User ID: {user_id}, User Name: {user_name}")

    if not product_id:
        return jsonify({'success': False, 'message': 'Product ID is missing.'}), 400
    if not rating:
        return jsonify({'success': False, 'message': 'Rating is required.'}), 400
    if not review:
        return jsonify({'success': False, 'message': 'Review text is required.'}), 400

    try:
        rating = int(rating)
        if not (1 <= rating <= 5):
            raise ValueError("Rating must be between 1 and 5")

        new_review = {
            'user_id': user_id,
            'user_name': user_name,
            'rating': rating,
            'review': review,
            'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        # Add the review to the database
        db.child("product_reviews").child(product_id).push(new_review)

        print(f"Review submitted successfully: {new_review}")
        return jsonify({'success': True, 'message': 'Review submitted successfully.'}), 200
    except ValueError as ve:
        print(f"ValueError: {str(ve)}")
        return jsonify({'success': False, 'message': str(ve)}), 400
    except Exception as e:
        print(f"Error submitting review: {str(e)}")
        return jsonify({'success': False, 'message': f'An error occurred while submitting the review: {str(e)}'}), 500
from flask import render_template_string

@app.route('/get-reviews/<product_id>')
def get_reviews(product_id):
    reviews = db.child("product_reviews").child(product_id).get().val()
    product_reviews = []
    if reviews:
        for review_id, review_data in reviews.items():
            product_reviews.append(review_data)
    
    # Sort reviews by date (newest first)
    product_reviews.sort(key=lambda x: x['date'], reverse=True)
    
    html = render_template_string("""
        {% if product_reviews %}
            {% for review in product_reviews %}
                <div class="single-review mb-30">
                    <div class="review-header">
                        <div class="review-author">
                            <strong>{{ review.user_name }}</strong>
                        </div>
                        <div class="review-rating">
                            {% for _ in range(review.rating|int) %}
                                <i class="fa fa-star"></i>
                            {% endfor %}
                            {% for _ in range(5 - review.rating|int) %}
                                <i class="fa fa-star-o"></i>
                            {% endfor %}
                        </div>
                        <div class="review-date">
                            {{ review.date }}
                        </div>
                    </div>
                    <div class="review-content">
                        <p>{{ review.review }}</p>
                    </div>
                </div>
            {% endfor %}
        {% else %}
            <p>No reviews yet. Be the first to review this product!</p>
        {% endif %}
    """, product_reviews=product_reviews)
@app.route('/check_auth')
def check_auth():
    if 'user_id' in session:
        return jsonify({"authenticated": True}), 200
    else:
        return jsonify({"authenticated": False}), 401
    return jsonify({'success': True, 'html': html})
from flask import Flask, jsonify, request, session
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
import pyrebase
import logging

# ... (your existing imports and configurations)


scheduler = BackgroundScheduler()
scheduler.start()

# ... (your existing Firebase configuration)

def complete_return(order_id, product_id):
    try:
        # Get the current return information
        return_info = db.child("orders").child(order_id).child('returns').get().val()

        if return_info and return_info['status'] == 'return_initiated':
            # Update the return status to 'returned' and add completed_at timestamp
            return_info['status'] = 'returned'
            return_info['completed_at'] = datetime.now().isoformat()

            # Update the database
            db.child("orders").child(order_id).child('returns').set(return_info)

            app.logger.info(f"Return completed automatically for order {order_id}, product {product_id}")
        else:
            app.logger.warning(f"Return not completed for order {order_id}, product {product_id}. Current status: {return_info.get('status') if return_info else 'No return info'}")

    except Exception as e:
        app.logger.error(f"Error completing return automatically: {str(e)}")

from firebase_admin import db as admin_db

from flask import jsonify, request
from datetime import datetime, timedelta


from apscheduler.schedulers.background import BackgroundScheduler
import logging

scheduler = BackgroundScheduler()
scheduler.start()

@app.route('/initiate-return', methods=['POST'])
def initiate_return():
    app.logger.info("=== Starting initiate_return ===")
    
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Please login to continue'})

    try:
        data = request.get_json()
        order_id = data.get('order_id')
        product_id = data.get('product_id')
        
        app.logger.info(f"Processing return for order ID: {order_id}, product ID: {product_id}")

        if not order_id or not product_id:
            app.logger.error(f"Missing required fields. order_id: {order_id}, product_id: {product_id}")
            return jsonify({'success': False, 'error': 'Order ID and Product ID are required'})

        # Get order data
        order_ref = db.child("orders").child(order_id)
        order_data = order_ref.get().val()
        
        if not order_data:
            app.logger.error(f"Order not found: {order_id}")
            return jsonify({'success': False, 'error': 'Order not found'})

        # Find the specific item in items array
        items = order_data.get('items', [])
        target_item_index = None
        
        for index, item in enumerate(items):
            if item.get('product_id') == product_id:
                target_item_index = index
                break

        if target_item_index is None:
            app.logger.error(f"Product {product_id} not found in order {order_id}")
            return jsonify({'success': False, 'error': 'Product not found in order'})

        current_time = datetime.now().isoformat()

        try:
            # Update specific item status
            db.child("orders").child(order_id).child("items").child(str(target_item_index)).update({
                "status": "return_initiated",
                "return_initiated_at": current_time
            })
            
            app.logger.info(f"Successfully initiated return for order {order_id}, product {product_id}")
            return jsonify({
                'success': True,
                'message': 'Return initiated successfully'
            })

        except Exception as e:
            app.logger.error(f"Error updating Firebase: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'Failed to update status: {str(e)}'
            })

    except Exception as e:
        app.logger.error(f"Error in initiate_return: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}'
        })

@app.route('/get-return-status/<order_id>')
def get_return_status(order_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 403

    try:
        order = db.child("orders").child(order_id).get().val()
        if order and 'returns' in order:
            return jsonify({'success': True, 'status': order['returns'].get('status', 'not_initiated')})
        else:
            return jsonify({'success': True, 'status': 'not_initiated'})
    except Exception as e:
        app.logger.error(f"Error getting return status: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

def complete_return(order_id, product_id):
    try:
        # Get the order details
        order = db.child("orders").child(order_id).get().val()
        if not order:
            app.logger.error(f"Order not found: {order_id}")
            return False

        # Find the specific item in the order
        item_to_return = next((item for item in order.get('items', []) 
                             if item.get('product_id') == product_id), None)
        if not item_to_return:
            app.logger.error(f"Product not found in order: {product_id}")
            return False

        current_time = datetime.now().isoformat()

        # Record return on blockchain
        try:
            authenticator = RentalAuthenticator()
            shipping_address = order.get('shipping_address', '')
            condition = item_to_return.get('return_condition', 'Good')
            notes = item_to_return.get('return_notes', '')
            
            # Record return with proper parameters
            blockchain_success = authenticator.record_return(
                product_id,
                shipping_address,
                condition,
                notes
            )

            if blockchain_success:
                # Update verification status in Firebase
                db.child("products").child(product_id).update({
                    'blockchain_verified': True,
                    'last_verification': current_time,
                    'last_condition': condition,
                    'last_return': {
                        'order_id': order_id,
                        'returned_at': current_time,
                        'condition': condition,
                        'notes': notes
                    }
                })

        except Exception as e:
            app.logger.error(f"Error recording return on blockchain: {str(e)}")
            blockchain_success = False

        # Update the order status
        try:
            db.child("orders").child(order_id).child("items").update({
                'status': 'returned',
                'return_completed_at': current_time,
                'blockchain_verified': blockchain_success
            })
            
            return True

        except Exception as e:
            app.logger.error(f"Error updating order status: {str(e)}")
            return False

    except Exception as e:
        app.logger.error(f"Error in complete_return: {str(e)}")
        return False


from flask import jsonify, request

@app.route('/cancel-order', methods=['POST'])
def cancel_order():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 403

    data = request.json
    order_id = data.get('order_id')

    try:
        order = db.child("orders").child(order_id).get().val()
        if not order:
            return jsonify({'success': False, 'message': 'Order not found'}), 404

        # Check if the order belongs to the logged-in user
        if order.get('user_id') != session['user_id']:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403

        # Check if the order is already cancelled or returned
        if order.get('status') == 'cancelled' or order.get('returns', {}).get('status') in ['return_initiated', 'returned']:
            return jsonify({'success': False, 'message': 'Cannot cancel this order'}), 400

        # Update order status to cancelled
        db.child("orders").child(order_id).update({
            'status': 'cancelled',
            'cancelled_at': datetime.now().isoformat()
        })

        # Return the quantity to product stock
        for item in order.get('items', []):
            product_id = item.get('product_id')
            quantity = item.get('quantity', 0)
            
            product = db.child("products").child(product_id).get().val()
            if product:
                current_quantity = int(product.get('product_quantity', '0'))
                new_quantity = current_quantity + quantity
                db.child("products").child(product_id).update({'product_quantity': str(new_quantity)})

        return jsonify({'success': True, 'message': 'Order cancelled successfully'})
    except Exception as e:
        app.logger.error(f"Error cancelling order: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while cancelling the order'}), 500
@app.route('/become-seller', methods=['GET', 'POST'])
def become_seller():
    app.logger.info(f"Entering become_seller route. Method: {request.method}")
    if 'user_id' not in session:
        app.logger.warning("User not logged in, redirecting to login")
        return redirect(url_for('login'))

    user_id = session['user_id']
    app.logger.info(f"User ID from session: {user_id}")
    
    # Fetch user data from the database
    user_data = db.child("users").child(user_id).get().val()
    app.logger.info(f"Fetched user data: {user_data}")
    
    if user_data:
        name = user_data.get('name', 'Unknown')
        email = user_data.get('email', 'Unknown')
        phone = user_data.get('phone', 'Unknown')
        district = user_data.get('district', 'Unknown')
        vendor_status = user_data.get('vendor_status', None)
    else:
        name = email = phone = district = 'Unknown'
        vendor_status = None
        app.logger.warning(f"No user data found for user_id: {user_id}")

    if vendor_status == 'pending':
        app.logger.info("Vendor application is pending")
        return render_template('become_seller.html', 
                               application_pending=True,
                               name=name, 
                               email=email, 
                               phone=phone,
                               district=district)
    elif vendor_status == 'approved':
        flash('You are already a registered vendor.', 'info')
        return redirect(url_for('vendor_dashboard'))

    if request.method == 'POST':
        app.logger.info("Processing POST request")
        current_step = int(request.form.get('current_step', 0))
        app.logger.info(f"Current step: {current_step}")

        update_data = {}
        if current_step == 0:
            update_data['store_name'] = request.form.get('store_name')
            update_data['name'] = request.form.get('name')
        elif current_step == 1:
            update_data['phone'] = request.form.get('phone')
            update_data['district'] = request.form.get('address')
        elif current_step == 2:
            update_data['gst_number'] = request.form.get('gst_number')
            if request.form.get('final_submit') == 'true':
                update_data['vendor_status'] = 'pending'

        app.logger.info(f"Update data prepared: {update_data}")

        try:
            # Update user data in the Realtime Database
            app.logger.info(f"Attempting to update user data for user_id: {user_id}")
            result = db.child("users").child(user_id).update(update_data)
            app.logger.info(f"Update result: {result}")
            
            # Verify the update
            updated_user_data = db.child("users").child(user_id).get().val()
            app.logger.info(f"Updated user data: {updated_user_data}")

            if all(updated_user_data.get(key) == value for key, value in update_data.items()):
                app.logger.info("Update successful")
                # Update session info
                if 'user_info' in session:
                    session['user_info'].update(update_data)
                return jsonify({'success': True, 'message': 'Vendor registration successful!'})
            else:
                app.logger.error("Data update verification failed")
                raise Exception("Data update verification failed")

        except Exception as e:
            app.logger.error(f"Error in become_seller for user {user_id}: {str(e)}")
            app.logger.error(traceback.format_exc())
            return jsonify({'success': False, 'error': str(e)})

    app.logger.info("Rendering become_seller template with form")
    return render_template('become_seller.html', 
                           application_pending=False,
                           name=name, 
                           email=email, 
                           phone=phone,
                           district=district)
@app.route('/get-low-stock-notifications', methods=['GET'])
def get_low_stock_notifications():
    try:
        # Fetch all products
        products = db.child("products").get().val()
        
        low_stock_notifications = []
        
        for product_id, product in products.items():
            if int(product.get('product_quantity', 0)) == 0:
                low_stock_notifications.append({
                    'product_id': product_id,
                    'product_name': product.get('product_name', 'Unknown Product'),
                    'store_name': product.get('store_name', 'Unknown Store'),
                    'message': f"{product.get('product_name', 'A product')} is out of stock!"
                })
        
        return jsonify(low_stock_notifications)
    except Exception as e:
        app.logger.error(f"Error fetching low stock notifications: {str(e)}")
        return jsonify([]), 500
from flask import request, jsonify

@app.route('/update-order', methods=['POST'])
def update_order():
    data = request.json
    order_id = data['order_id']
    updated_items = data['items']
    new_order_total = data['order_total']

    try:
        # Update the order in your database
        # This is a placeholder - replace with your actual database update logic
        update_order_in_database(order_id, updated_items, new_order_total)

        return jsonify({'success': True, 'message': 'Order updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

def update_order_in_database(order_id, updated_items, new_order_total):
    # Implement your database update logic here
    # This might involve updating a SQL database, a NoSQL database, or whatever storage system you're using
    pass
# Add this new route after your existing routes
@app.route('/cancel-order-item', methods=['POST'])
def cancel_order_item():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 401

    data = request.json
    order_id = data.get('order_id')
    product_id = data.get('product_id')
    cancel_quantity = int(data.get('quantity', 1))

    try:
        # Fetch the order from the database
        order = db.child("orders").child(order_id).get().val()
        if not order:
            return jsonify({'success': False, 'message': 'Order not found'}), 404

        # Ensure the order belongs to the logged-in user
        if order['user_id'] != session['user_id']:
            return jsonify({'success': False, 'message': 'Unauthorized access'}), 403

        # Find the item in the order
        items = order.get('items', [])
        item = next((item for item in items if item['product_id'] == product_id), None)
        if not item:
            return jsonify({'success': False, 'message': 'Item not found in order'}), 404

        # Update the item status
        if item['quantity'] == 1 or cancel_quantity >= item['quantity']:
            item['status'] = 'cancelled'
            new_status = 'cancelled'
            remaining_quantity = 0
        else:
            item['quantity'] -= cancel_quantity
            item['status'] = 'partially_cancelled'
            remaining_quantity = item['quantity']
            new_status = 'partially_cancelled'

        # Update the order in the database
        db.child("orders").child(order_id).update({
            'items': items,
            'updated_at': datetime.now().isoformat()
        })

        # Recalculate the order total
        new_order_total = sum(item.get('item_total', 0) for item in items if item.get('status') != 'cancelled')
        
        # Update the order total in the database
        db.child("orders").child(order_id).update({
            'order_total': new_order_total
        })
        
        # Remove wallet deposit if all items are cancelled
        all_cancelled = all(item.get('status') == 'cancelled' for item in items)
        if all_cancelled:
            # Update order to remove wallet deposit
            db.child("orders").child(order_id).update({
                'wallet_deposit': 0
            })
            
            # Update wallet transaction status to cancelled
            transactions = db.child("wallet_transactions").order_by_child("order_id").equal_to(order_id).get()
            if transactions.each():
                for transaction in transactions.each():
                    transaction_data = transaction.val()
                    if transaction_data.get('type') == 'deposit':
                        db.child("wallet_transactions").child(transaction.key()).update({
                            'status': 'cancelled',
                            'updated_at': datetime.now().isoformat()
                        })

        # Update product quantity in stock
        product = db.child("products").child(product_id).get().val()
        if product:
            current_quantity = int(product.get('product_quantity', '0'))
            new_quantity = current_quantity + cancel_quantity
            db.child("products").child(product_id).update({'product_quantity': str(new_quantity)})

        return jsonify({
            'success': True,
            'status': new_status,
            'quantity': remaining_quantity,
            'rent_from': item.get('rent_from', 'N/A'),
            'rent_to': item.get('rent_to', 'N/A'),
            'rental_days': item.get('rental_days', 'N/A'),
            'order_total': new_order_total
        })

    except Exception as e:
        app.logger.error(f"Error in cancel_order_item: {str(e)}")
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 500
@app.route('/update-item-status', methods=['POST'])
def update_item_status():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 401

    data = request.json
    order_id = data.get('order_id')
    product_id = data.get('product_id')
    returns_data = data.get('returns', {})

    try:
        # Fetch the order
        order = db.child("orders").child(order_id).get().val()
        if not order:
            return jsonify({'success': False, 'message': 'Order not found'}), 404

        # Ensure the order belongs to the logged-in user
        if order['user_id'] != session['user_id']:
            return jsonify({'success': False, 'message': 'Unauthorized access'}), 403

        # Find and update the specific item
        items = order.get('items', [])
        item_updated = False
        
        for item in items:
            if item['product_id'] == product_id:
                # Update item status and dates based on returns status
                item['status'] = returns_data.get('status')
                if returns_data.get('status') == 'return_initiated':
                    item['return_initiated_at'] = returns_data.get('initiated_at')
                elif returns_data.get('status') == 'returned':
                    item['return_completed_at'] = returns_data.get('completed_at')
                item_updated = True
                break

        if not item_updated:
            return jsonify({'success': False, 'message': 'Item not found in order'}), 404

        # Update items in the order
        update_data = {
            'items': items,
            'updated_at': datetime.now().isoformat()
        }

        # Update the order in the database
        db.child("orders").child(order_id).update(update_data)

        # Handle product quantity update for returned items
        if returns_data.get('status') == 'returned':
            try:
                product = db.child("products").child(product_id).get().val()
                if product:
                    current_quantity = int(product.get('product_quantity', '0'))
                    returned_quantity = 1  # or get from item['quantity'] if needed
                    new_quantity = current_quantity + returned_quantity
                    db.child("products").child(product_id).update({
                        'product_quantity': str(new_quantity)
                    })
            except Exception as e:
                app.logger.error(f"Error updating product quantity: {str(e)}")

        response_data = {
            'success': True,
            'message': f'Return {returns_data.get("status")} successfully'
        }

        # Include invoice URL for completed returns
        if returns_data.get('status') == 'returned':
            invoice_url = url_for('download_order_pdf', order_id=order_id)
            response_data['invoice_url'] = invoice_url

        return jsonify(response_data)

    except Exception as e:
        app.logger.error(f"Error in update_item_status: {str(e)}")
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 500
from collections import defaultdict
from datetime import datetime, timedelta

@app.route('/get-sales-data')
def get_sales_data():
    try:
        period = request.args.get('period', 'monthly')
        orders = db.child("orders").get().val()
        
        # Initialize data structures
        monthly_data = defaultdict(float)
        
        if orders:
            for order_id, order in orders.items():
                try:
                    # Get order date from created_at field
                    created_at = datetime.strptime(order.get('created_at', ''), '%Y-%m-%dT%H:%M:%S.%f')
                    order_total = float(order.get('order_total', 0))
                    
                    # Create month key in format "MMM YYYY"
                    month_key = created_at.strftime('%b %Y')
                    monthly_data[month_key] += order_total
                    
                except (ValueError, TypeError) as e:
                    app.logger.warning(f"Error processing order {order_id}: {str(e)}")
                    continue
        
        # Sort the data by date
        sorted_months = sorted(monthly_data.keys(), 
                             key=lambda x: datetime.strptime(x, '%b %Y'))
        
        # Get last 12 months if monthly view
        if period == 'monthly':
            sorted_months = sorted_months[-12:] if len(sorted_months) > 12 else sorted_months
        
        response_data = {
            'labels': sorted_months,
            'values': [monthly_data[month] for month in sorted_months]
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        app.logger.error(f"Error in get_sales_data: {str(e)}")
        return jsonify({'labels': [], 'values': []})
@app.route('/get-monthly-sales')
def get_monthly_sales():
    try:
        month = request.args.get('month', 'all')
        year = request.args.get('year', datetime.now().year)
        
        orders = db.child("orders").get().val()
        monthly_sales = defaultdict(float)
        
        if orders:
            for order in orders.values():
                try:
                    # Parse the created_at timestamp
                    created_at = datetime.strptime(order.get('created_at', ''), '%Y-%m-%dT%H:%M:%S.%f')
                    
                    # Apply year filter
                    if str(created_at.year) != str(year):
                        continue
                        
                    # Apply month filter if not "all"
                    if month != 'all' and created_at.month != int(month):
                        continue
                        
                    order_total = float(order.get('order_total', 0))
                    
                    # Format month as "MMM YYYY" or just "MMM" if year is selected
                    month_key = created_at.strftime('%b %Y' if month == 'all' else '%b')
                    monthly_sales[month_key] += order_total
                    
                except (ValueError, TypeError) as e:
                    continue
        
        # Sort months chronologically
        if month == 'all':
            sorted_months = sorted(monthly_sales.keys(), 
                                 key=lambda x: datetime.strptime(x, '%b %Y'))
        else:
            # Use month number for sorting when showing single year
            month_order = {
                'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
            }
            sorted_months = sorted(monthly_sales.keys(), 
                                 key=lambda x: month_order[x])
        
        return jsonify({
            'labels': sorted_months,
            'values': [monthly_sales[month] for month in sorted_months]
        })
        
    except Exception as e:
        app.logger.error(f"Error getting monthly sales: {str(e)}")
        return jsonify({'labels': [], 'values': []})
@app.route('/get-order-status-counts')
def get_order_status_counts():
    try:
        orders = db.child("orders").get().val()
        status_counts = {
            'ordered': 0,
            'delivered': 0,
            'returned': 0,
            'cancelled': 0
        }
        
        if orders:
            for order in orders.values():
                try:
                    # Get status from items array
                    items = order.get('items', [])
                    if items:
                        for item in items:
                            status = item.get('status', '').lower()
                            if status == 'ordered':
                                status_counts['ordered'] += 1
                            elif status == 'delivered':
                                status_counts['delivered'] += 1
                            elif status == 'returned':
                                status_counts['returned'] += 1
                            elif status == 'cancelled':
                                status_counts['cancelled'] += 1
                    
                except Exception as e:
                    continue
        
        return jsonify(status_counts)
        
    except Exception as e:
        app.logger.error(f"Error getting order status counts: {str(e)}")
        return jsonify({
            'ordered': 0,
            'delivered': 0,
            'returned': 0,
            'cancelled': 0
        })
from fpdf import FPDF
from datetime import datetime
import io

from fpdf import FPDF
from datetime import datetime
from flask import send_file
import tempfile
import os

@app.route('/download-report')
def download_report():
    try:
        # Create PDF object
        pdf = FPDF()
        pdf.add_page()
        
        # Set font
        pdf.set_font('Arial', 'B', 16)
        
        # Title
        pdf.cell(190, 10, 'Sales and Orders Report', 0, 1, 'C')
        pdf.ln(10)
        
        # Get orders data
        orders = db.child("orders").get().val()
        
        # Initialize counters
        status_counts = {
            'ordered': 0,
            'delivered': 0,
            'returned': 0,
            'cancelled': 0
        }
        total_revenue = 0
        
        # Process orders
        order_details = []
        if orders:
            for order_id, order in orders.items():
                items = order.get('items', [])
                for item in items:
                    status = item.get('status', '').lower()
                    if status in status_counts:
                        status_counts[status] += 1
                    
                    # Calculate revenue for delivered orders
                    if status == 'delivered':
                        total_revenue += float(item.get('item_total', 0))
                    
                    # Store order details for the report
                    order_details.append({
                        'order_id': order_id,
                        'status': status,
                        'amount': item.get('item_total', 0),
                        'date': order.get('created_at', ''),
                        'store': item.get('store_name', '')
                    })
        
        # Add Order Status Summary
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(190, 10, 'Order Status Summary', 0, 1, 'L')
        pdf.set_font('Arial', '', 12)
        for status, count in status_counts.items():
            pdf.cell(190, 10, f'{status.capitalize()}: {count}', 0, 1, 'L')
        
        # Add Total Revenue
        pdf.ln(5)
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(190, 10, 'Revenue Summary', 0, 1, 'L')
        pdf.set_font('Arial', '', 12)
        pdf.cell(190, 10, f'Total Revenue: ₹{total_revenue:,.2f}', 0, 1, 'L')
        
        # Add Recent Orders
        pdf.ln(5)
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(190, 10, 'Recent Orders', 0, 1, 'L')
        pdf.set_font('Arial', '', 12)
        
        # Table header
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(40, 10, 'Order ID', 1)
        pdf.cell(30, 10, 'Status', 1)
        pdf.cell(30, 10, 'Amount', 1)
        pdf.cell(50, 10, 'Date', 1)
        pdf.cell(40, 10, 'Store', 1)
        pdf.ln()
        
        # Table content
        pdf.set_font('Arial', '', 10)
        for order in order_details[-10:]:  # Show last 10 orders
            # Truncate order ID to fit
            order_id_short = order['order_id'][:10] + '...'
            
            pdf.cell(40, 10, order_id_short, 1)
            pdf.cell(30, 10, order['status'].capitalize(), 1)
            pdf.cell(30, 10, f"₹{float(order['amount']):,.2f}", 1)
            
            # Format date
            try:
                date_obj = datetime.strptime(order['date'], '%Y-%m-%dT%H:%M:%S.%f')
                formatted_date = date_obj.strftime('%Y-%m-%d')
            except:
                formatted_date = order['date']
                
            pdf.cell(50, 10, formatted_date, 1)
            pdf.cell(40, 10, order['store'], 1)
            pdf.ln()

        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
            pdf.output(tmp.name)
            
            # Generate timestamp for filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            # Send the temporary file
            return send_file(
                tmp.name,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=f'sales_report_{timestamp}.pdf'
            )
        
    except Exception as e:
        app.logger.error(f"Error generating report: {str(e)}")
        return "Error generating report", 500
    
    finally:
        # Clean up the temporary file
        if 'tmp' in locals():
            try:
                os.unlink(tmp.name)
            except:
                pass
from datetime import datetime, timedelta

@app.route('/get-daily-user-stats')
def get_daily_user_stats():
    try:
        users = db.child("users").get().val()
        
        # Get last 7 days
        dates = [(datetime.now() - timedelta(days=x)).strftime('%Y-%m-%d') for x in range(6, -1, -1)]
        
        stats = {
            'active': [0] * 7,
            'inactive': [0] * 7,
            'dates': dates
        }
        
        if users:
            for user_id, user_data in users.items():
                if user_data.get('user_type') != 'vendor':  # Exclude vendors
                    reg_date = user_data.get('registration_date')
                    status = user_data.get('status', 'inactive')
                    
                    # Find which day index this user belongs to
                    if reg_date in dates:
                        day_index = dates.index(reg_date)
                        if status == 'active':
                            stats['active'][day_index] += 1
                        else:
                            stats['inactive'][day_index] += 1
        
        return jsonify(stats)
    except Exception as e:
        app.logger.error(f"Error getting daily user stats: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/agent-add', methods=['GET', 'POST'])
def agent_add():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    try:
        user_id = session['user_id']
        user_info = db.child("users").child(user_id).get().val()
        
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            phone = request.form.get('phone')
            district = request.form.get('district')
            profile_photo = request.files.get('profile_photo')

            try:
                # Generate a random password for initial account creation
                temp_password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))

                # Create user in Firebase Authentication
                auth = firebase.auth()
                user = auth.create_user_with_email_and_password(email, temp_password)
                
                # Send password reset email
                auth.send_password_reset_email(email)

                # Handle profile photo upload
                profile_pic_url = ""
                if profile_photo and profile_photo.filename:
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"{timestamp}_{secure_filename(profile_photo.filename)}"
                    profile_folder = os.path.join('static/uploads', 'profiles')
                    os.makedirs(profile_folder, exist_ok=True)
                    filepath = os.path.join(profile_folder, filename)
                    profile_photo.save(filepath)
                    profile_pic_url = f'uploads/profiles/{filename}'

                # Create new agent data
                new_agent = {
                    "name": name,
                    "email": email,
                    "phone": phone,
                    "district": district,
                    "registration_date": datetime.now().strftime('%Y-%m-%d'),
                    "status": "active",
                    "user_type": "delivery_agent",
                    "profile_pic": profile_pic_url,
                    "firebase_uid": user['localId']  # Store Firebase UID
                }

                # Add to Firebase database
                db.child("users").push(new_agent)
                
                return jsonify({
                    'success': True, 
                    'message': 'Delivery Agent registered successfully! A password reset email has been sent.'
                })

            except Exception as e:
                app.logger.error(f"Error in agent_add: {str(e)}")
                # If user was created but other steps failed, try to delete the user
                if 'user' in locals():
                    try:
                        auth.delete_user_account(user['idToken'])
                    except:
                        pass
                return jsonify({
                    'success': False, 
                    'message': f'Error: {str(e)}'
                })

        return render_template('Admin/agent-add.html', user=user_info)

    except Exception as e:
        app.logger.error(f"Error in agent_add: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

def save_profile_image(profile_photo):
    filename = secure_filename(profile_photo.filename)
    profile_folder = os.path.join('static/uploads', 'profiles')
    os.makedirs(profile_folder, exist_ok=True)
    filepath = os.path.join(profile_folder, filename)
    profile_photo.save(filepath)
    return url_for('static', filename=f'uploads/profiles/{filename}')

@app.route('/agent-list')
def agent_list():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    try:
        user_id = session['user_id']
        user_info = db.child("users").child(user_id).get().val()

        # Get all users
        users = db.child("users").get()
        
        # Filter for delivery agents
        agents = {}
        if users.each():
            for user in users.each():
                user_data = user.val()
                if user_data.get('user_type') == 'delivery_agent':
                    agents[user.key()] = user_data

        return render_template('Admin/agent-list.html', 
                            user_info=user_info,
                            agents=agents)

    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))
@app.route('/delivery/dashboard')
def delivery_dashboard():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    try:
        user_id = session['user_id']
        user_info = db.child("users").child(user_id).get().val()

        # Verify user is a delivery agent
        if user_info.get('user_type') != 'delivery_agent':
            flash('Unauthorized access.', 'danger')
            return redirect(url_for('home'))

        # Get delivery statistics
        orders = db.child("orders").get().val() or {}
        
        pending_count = 0
        active_count = 0 
        completed_count = 0

        for order in orders.values():
            items = order.get('items', [])
            if any(item.get('status', '').lower() == 'ordered' for item in items):
                pending_count += 1
            if any(item.get('status', '').lower() == 'in_transit' for item in items):
                active_count += 1
            if any(item.get('status', '').lower() == 'delivered' for item in items):
                completed_count += 1

        return render_template('delivery/dashboard.html',
                             user_info=user_info,
                             pending_count=pending_count,
                             active_count=active_count,
                             completed_count=completed_count)

    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('home'))
@app.route('/delivery/profile', methods=['GET', 'POST'])
def delivery_profile():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    try:
        user_id = session['user_id']
        user_info = session.get('user_info', {})

        # Verify user is a delivery agent
        if user_info.get('user_type') != 'delivery_agent':
            flash('Unauthorized access.', 'error')
            return redirect(url_for('login'))

        if request.method == 'POST':
            # Handle profile updates
            name = request.form.get('name')
            phone = request.form.get('phone')
            district = request.form.get('district')
            profile_photo = request.files.get('profile_photo')

            # Update user data
            updates = {
                'name': name,
                'phone': phone,
                'district': district
            }

            # Handle profile photo upload if provided
            if profile_photo and profile_photo.filename:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{timestamp}_{secure_filename(profile_photo.filename)}"
                profile_folder = os.path.join('static/uploads', 'profiles')
                os.makedirs(profile_folder, exist_ok=True)
                filepath = os.path.join(profile_folder, filename)
                profile_photo.save(filepath)
                updates['profile_pic'] = f'uploads/profiles/{filename}'

            # Update in database
            db.child("users").child(user_id).update(updates)
            
            # Update session info
            user_info.update(updates)
            session['user_info'] = user_info

            flash('Profile updated successfully!', 'success')
            return redirect(url_for('delivery_profile'))

        return render_template('delivery/profile.html', user=user_info)

    except Exception as e:
        app.logger.error(f"Error in delivery profile: {str(e)}")
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('delivery_dashboard'))

@app.route('/delivery/pending-orders')
def delivery_pending_orders():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    try:
        user_id = session['user_id']
        user_info = session.get('user_info', {})

        # Verify user is a delivery agent
        if user_info.get('user_type') != 'delivery_agent':
            flash('Unauthorized access.', 'error')
            return redirect(url_for('login'))

        # Fetch all orders
        orders = db.child("orders").get().val()
        pending_orders = {}
        
        if orders:
            for order_id, order in orders.items():
                # Get items from the order
                items = order.get('items', [])
                
                # Check if any item has status 'ordered'
                has_pending_items = any(
                    item.get('status', '').lower() == 'ordered' 
                    for item in items
                )
                
                if has_pending_items:
                    # Get the first pending item
                    pending_item = next(
                        item for item in items 
                        if item.get('status', '').lower() == 'ordered'
                    )
                    
                    # Create order data with item details
                    order_data = {
                        'id': order_id,
                        'order_id': order.get('order_id', order_id),
                        'store_name': pending_item.get('store_name', 'N/A'),
                        'product_id': pending_item.get('product_id', 'N/A'),
                        'rent_from': pending_item.get('rent_from', order.get('rent_from', 'N/A')),
                        'rent_to': pending_item.get('rent_to', order.get('rent_to', 'N/A')),
                        'shipping_address': order.get('shipping_address', 'N/A'),
                        'shipping_address2': order.get('shipping_address2', ''),
                        'order_total': order.get('order_total', 0),
                        'status': pending_item.get('status', 'ordered'),
                        'updated_at': pending_item.get('ordered_at', order.get('updated_at', '')),
                        'payment_intent_id': order.get('payment_intent_id', 'N/A'),
                        'quantity': pending_item.get('quantity', 1)
                    }
                    
                    pending_orders[order_id] = order_data
        
        app.logger.debug(f"Fetched pending orders: {pending_orders}")

        return render_template('delivery/pending_orders.html', 
                             user=user_info,
                             pending_orders=pending_orders)

    except Exception as e:
        app.logger.error(f"Error in pending orders: {str(e)}")
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('delivery_dashboard'))
# Add this import at the top with other imports
from flask_mail import Mail, Message

# Add these configurations right after your existing app configurations
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='mail.rentaltools@gmail.com',
    MAIL_PASSWORD='cqsu jjxz voza prli',
    MAIL_DEFAULT_SENDER='mail.rentaltools@gmail.com'
)

# Initialize Mail
mail = Mail(app)

# ... rest of your existing code ...
@app.route('/delivery/active-orders')
def delivery_active_orders():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    try:
        user_id = session['user_id']
        user_info = session.get('user_info', {})

        # Verify user is a delivery agent
        if user_info.get('user_type') != 'delivery_agent':
            flash('Unauthorized access.', 'error')
            return redirect(url_for('login'))

        # Fetch all orders
        orders = db.child("orders").get().val()
        active_orders = {}
        
        if orders:
            for order_id, order in orders.items():
                # Get items from the order
                items = order.get('items', [])
                
                # Check if any item has status 'in_transit'
                has_active_items = any(
                    item.get('status', '').lower() == 'in_transit' 
                    for item in items
                )
                
                if has_active_items:
                    # Get the first active item
                    active_item = next(
                        item for item in items 
                        if item.get('status', '').lower() == 'in_transit'
                    )
                    
                    # Create order data with item details
                    order_data = {
                        'id': order_id,
                        'order_id': order.get('order_id', order_id),
                        'store_name': active_item.get('store_name', 'N/A'),
                        'product_id': active_item.get('product_id', 'N/A'),
                        'rent_from': active_item.get('rent_from', order.get('rent_from', 'N/A')),
                        'rent_to': active_item.get('rent_to', order.get('rent_to', 'N/A')),
                        'shipping_address': order.get('shipping_address', 'N/A'),
                        'shipping_address2': order.get('shipping_address2', ''),
                        'order_total': order.get('order_total', 0),
                        'status': active_item.get('status', 'in_transit'),
                        'updated_at': active_item.get('ordered_at', order.get('updated_at', '')),
                        'payment_intent_id': order.get('payment_intent_id', 'N/A'),
                        'quantity': active_item.get('quantity', 1),
                        'delivery_started_at': order.get('delivery_started_at', '')
                    }
                    
                    active_orders[order_id] = order_data
        
        app.logger.debug(f"Fetched active orders: {active_orders}")

        return render_template('delivery/active_orders.html', 
                             user=user_info,
                             active_orders=active_orders)

    except Exception as e:
        app.logger.error(f"Error in active orders: {str(e)}")
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('delivery_dashboard'))

# Add this route with your other delivery routes
@app.route('/delivery/send-delivery-otp', methods=['POST'])
def send_delivery_otp():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data received'}), 400
            
        email = data.get('email')
        delivery_details = data.get('delivery_details')
        
        if not email or not delivery_details:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400

        items_list = "\n".join([
            f"- Quantity: {item.get('quantity', 'N/A')}\n"
            f"  Rental Period: {item.get('rent_from', 'N/A')} to {item.get('rent_to', 'N/A')}\n"
            f"  Store: {item.get('store_name', 'N/A')}"
            for item in delivery_details.get('items', [])
        ])

        email_content = f"""Dear Customer,

Your delivery is ready to be completed.

Order Details:
Order ID: {delivery_details.get('order_id', 'N/A')}
Store: {delivery_details.get('store_name', 'N/A')}
Shipping Address: {delivery_details.get('shipping_address', 'N/A')}
{delivery_details.get('shipping_address2', '')}

Items:
{items_list}

Your OTP for delivery confirmation: {delivery_details.get('otp', 'N/A')}

Please provide this OTP to the delivery agent to complete the delivery.

Thank you for using our service!"""

        msg = Message(
            'Delivery OTP Confirmation',
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[email]
        )
        msg.body = email_content
        mail.send(msg)
        
        return jsonify({
            'success': True, 
            'message': 'OTP sent successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False, 
            'message': str(e)
        }), 500

@app.route('/delivery/complete-delivery', methods=['POST'])
def complete_delivery():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data received'}), 400
            
        order_id = data.get('order_id')
        otp = data.get('otp')
        
        if not order_id or not otp:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400

        # Get delivery agent info from session
        delivery_agent_id = session.get('user_id')
        user_info = session.get('user_info', {})
        
        if not delivery_agent_id:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 401

        # Get the order
        order_ref = db.child("orders").child(order_id)
        order = order_ref.get().val()
        
        if not order:
            return jsonify({'success': False, 'message': 'Order not found'}), 404

        # Verify OTP
        if str(order.get('delivery_otp')) != str(otp):
            return jsonify({'success': False, 'message': 'Invalid OTP'}), 400

        current_time = datetime.now().isoformat()
        
        # Update order with delivery agent info
        updates = {
            'delivery_completed_at': current_time,
            'updated_at': current_time,
            'delivery_agent_id': delivery_agent_id,
            'items': {
                'status': 'delivered'
            }
        }

        # Update the order
        order_ref.update(updates)

        return jsonify({
            'success': True,
            'message': 'Delivery completed successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/delivery/completed-orders')
def delivery_completed_orders():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    try:
        user_id = session['user_id']
        user_info = session.get('user_info', {})

        # Verify user is a delivery agent
        if user_info.get('user_type') != 'delivery_agent':
            flash('Unauthorized access.', 'error')
            return redirect(url_for('login'))

        # Fetch all orders
        orders = db.child("orders").get().val()
        completed_orders = {}
        
        if orders:
            for order_id, order in orders.items():
                # Get items array
                items = order.get('items', [])
                
                # Check if items is a list and has elements
                if isinstance(items, list) and len(items) > 0:
                    # Check for items with status 'delivered' or 'returned'
                    for item in items:
                        if item.get('status') in ['delivered', 'returned']:
                            # Create order data
                            order_data = {
                                'order_id': order.get('order_id'),
                                'store_name': item.get('store_name'),
                                'quantity': item.get('quantity'),
                                'rent_from': item.get('rent_from'),
                                'rent_to': item.get('rent_to'),
                                'shipping_address': order.get('shipping_address'),
                                'shipping_address2': order.get('shipping_address2', ''),
                                'order_total': order.get('order_total', 0),
                                'status': item.get('status'),
                                'delivery_completed_at': order.get('delivery_completed_at', 'N/A'),
                                'return_completed_at': item.get('return_completed_at', 'N/A')
                            }
                            completed_orders[order_id] = order_data

        app.logger.debug(f"Fetched completed orders: {completed_orders}")
        return render_template('delivery/completed_orders.html', 
                          user=user_info,
                          completed_orders=completed_orders)

    except Exception as e:
        print(f"Error in completed_orders: {str(e)}")
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('delivery_dashboard'))

@app.route('/delivery/pending-returns')
def delivery_pending_returns():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    user_info = session.get('user_info', {})
    if user_info.get('user_type') != 'delivery_agent':
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))
        
    return render_template('delivery/pending_returns.html', user=user_info)

@app.route('/delivery/active-returns')
def delivery_active_returns():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    try:
        user_info = session.get('user_info', {})
        if user_info.get('user_type') != 'delivery_agent':
            flash('Unauthorized access.', 'error')
            return redirect(url_for('login'))

        # Fetch all orders
        orders = db.child("orders").get().val()
        active_returns = {}
        
        if orders:
            for order_id, order in orders.items():
                # Get items from the order
                items = order.get('items', [])
                
                # Check if any item has status 'Pickup is on the way'
                has_active_returns = any(
                    item.get('status', '') == 'Pickup is on the way'
                    for item in items
                )
                
                if has_active_returns:
                    # Get the first active return item
                    active_item = next(
                        item for item in items 
                        if item.get('status', '') == 'Pickup is on the way'
                    )
                    
                    # Create order data with item details
                    order_data = {
                        'id': order_id,
                        'order_id': order.get('order_id', order_id),
                        'store_name': active_item.get('store_name', 'N/A'),
                        'product_id': active_item.get('product_id', 'N/A'),
                        'rent_from': active_item.get('rent_from', order.get('rent_from', 'N/A')),
                        'rent_to': active_item.get('rent_to', order.get('rent_to', 'N/A')),
                        'shipping_address': order.get('shipping_address', 'N/A'),
                        'shipping_address2': order.get('shipping_address2', ''),
                        'order_total': active_item.get('item_total', 0),
                        'status': active_item.get('status', 'Pickup is on the way'),
                        'return_pickup_started_at': order.get('return_pickup_started_at', ''),
                        'quantity': active_item.get('quantity', 1)
                    }
                    
                    active_returns[order_id] = order_data
        
        app.logger.debug(f"Fetched active returns: {active_returns}")
        
        return render_template('delivery/active_returns.html', 
                            user=user_info,
                            active_returns=active_returns)
                            
    except Exception as e:
        app.logger.error(f"Error in active returns: {str(e)}")
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('delivery_dashboard'))

@app.route('/delivery/complete-return', methods=['POST'])
def complete_return_delivery():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in'}), 401
        
    try:
        data = request.get_json()
        order_id = data.get('orderId')
        product_id = data.get('productId')
        store_name = data.get('storeName')
        condition = data.get('condition')
        notes = data.get('notes')
        current_time = datetime.now().isoformat()
        
        if not all([order_id, product_id, condition]):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
            
        # Get the order and product
        order = db.child("orders").child(order_id).get().val()
        product = db.child("products").child(product_id).get().val()
        
        if not order or not product:
            return jsonify({'success': False, 'message': 'Order or product not found'}), 404

        # Get items array
        items = order.get('items', [])
        if isinstance(items, dict):
            items = [items]

        # Find the item being returned and update product quantity
        for i, item in enumerate(items):
            if (item.get('product_id') == product_id and 
                item.get('store_name') == store_name):
                # Get the quantity being returned
                returned_quantity = int(item.get('quantity', 1))
                current_product_quantity = int(product.get('product_quantity', 0))
                
                # Update product quantity
                new_quantity = current_product_quantity + returned_quantity
                db.child("products").child(product_id).update({
                    'product_quantity': str(new_quantity)
                })
                
                # Update item status
                item_path = f"orders/{order_id}/items/{i}"
                db.update({
                    f"{item_path}/status": "returned",
                    f"{item_path}/return_completed_at": current_time
                })
                break

        # Create product condition entry
        condition_data = {
            'product_id': product_id,
            'store_name': store_name,
            'condition': condition,
            'notes': notes,
            'recorded_at': current_time,
            'order_id': order_id,
            'recorded_by': session.get('user_id')
        }
        
        # Add to product_conditions table
        db.child("product_conditions").push(condition_data)

        return jsonify({
            'success': True,
            'message': 'Return completed and product quantity updated successfully'
        })
        
    except Exception as e:
        app.logger.error(f"Error completing return: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/get_ai_response', methods=['POST'])
def get_ai_response():
    try:
        data = request.get_json()
        user_message = data.get('message', '').lower()

        # Get products from Firebase
        products = db.child("products").get().val()
        
        # Create product info string
        product_info = "Here are our available products:\n"
        if products:
            for product_id, product in products.items():
                product_info += f"- {product.get('product_name', 'N/A')}: ₹{product.get('product_price', 'N/A')}/day (Quantity: {product.get('product_quantity', '0')})\n"

        # Create context with real product data and 30-day limit
        context = f"""You are a helpful customer service agent for ToolHive, a tool rental website.
        Be concise and friendly in your responses. 
        
        Current product information:
        {product_info}
        
        Rental policies:
        - Minimum rental period: 1 day
        - Maximum rental period: 30 days from today
        - Delivery available within city limits
        
        Payment options:
        - Online payment
        
        Important rental rules:
        - Tools can only be rented for up to 30 days from the current date
        - Rentals cannot be extended beyond the 30-day limit
        - Early returns are allowed
        
        If asked about a specific product, check the product list above and provide accurate information.
        If the product is not in our list, inform that it's not available.
        If asked about rental duration, emphasize the 30-day maximum limit.
        Keep responses under 100 words."""

        # Combine context and user message
        prompt = f"{context}\n\nUser: {user_message}\nAssistant:"

        # Get response from Gemini
        response = model.generate_content(prompt)
        ai_response = response.text

        return jsonify({
            'success': True,
            'response': ai_response
        })

    except Exception as e:
        app.logger.error(f"Error getting AI response: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
from blockchain.rental_authenticator import RentalAuthenticator

authenticator = RentalAuthenticator()

@app.route('/verify-rental-history/<product_id>')
def verify_rental_history(product_id):
    try:
        app.logger.debug(f"Verifying rental history for product: {product_id}")
        authenticator = RentalAuthenticator()
        
        # Get product from Firebase
        product = db.child("products").child(product_id).get().val()
        if not product:
            return jsonify({
                'verified': False,
                'message': 'Product not found'
            })

        # Get blockchain verification status and history
        blockchain_data = authenticator.get_product_history(product_id)
        is_verified = blockchain_data[0] if blockchain_data else False

        # Get all orders for this product from Firebase
        orders_ref = db.child("orders").get()
        rental_history = []
        
        # Create a reverse lookup map for order IDs
        order_id_map = {}
        orders_data = orders_ref.val() if orders_ref.val() else {}
        for firebase_key, order in orders_data.items():
            if 'order_id' in order:
                order_id_map[order['order_id']] = firebase_key

        # Get all conditions for this product
        conditions_ref = db.child("product_conditions").get()
        conditions_map = {}
        if conditions_ref.each():
            for condition_record in conditions_ref.each():
                record = condition_record.val()
                if record.get('product_id') == product_id:
                    # Get the original order ID from Firebase key
                    firebase_order_key = record.get('order_id')
                    if firebase_order_key:
                        conditions_map[firebase_order_key] = {
                            'condition': record.get('condition'),
                            'notes': record.get('notes', ''),
                            'recorded_at': record.get('recorded_at')
                        }
        
        app.logger.debug(f"Conditions map: {conditions_map}")
        app.logger.debug(f"Order ID map: {order_id_map}")

        if orders_ref.each():
            for order in orders_ref.each():
                order_data = order.val()
                items = order_data.get('items', [])
                
                if isinstance(items, dict):
                    items = [items]
                
                for item in items:
                    if (isinstance(item, dict) and 
                        item.get('product_id') == product_id and 
                        item.get('status') == 'returned'):
                        
                        firebase_key = order.key()
                        app.logger.debug(f"Processing Firebase key: {firebase_key}")
                        
                        condition_info = conditions_map.get(firebase_key, {})
                        app.logger.debug(f"Found condition info: {condition_info}")

                        user_id = order_data.get('user_id')
                        user_info = db.child("users").child(user_id).get().val() if user_id else None
                        
                        history_entry = {
                            'order_id': order_data.get('order_id'),
                            'user_name': user_info.get('name', 'Unknown User') if user_info else 'Unknown User',
                            'rent_from': item.get('rent_from'),
                            'rent_to': item.get('rent_to'),
                            'status': 'returned',
                            'store_name': item.get('store_name'),
                            'quantity': item.get('quantity', 1),
                            'condition': condition_info.get('condition', 'Not specified'),
                            'notes': condition_info.get('notes', ''),
                            'returned_at': item.get('return_completed_at')
                        }
                        rental_history.append(history_entry)
                        app.logger.debug(f"Added history entry with condition: {condition_info.get('condition')}")

        return jsonify({
            'verified': is_verified,
            'product': {
                **product,
                'blockchain_verified': is_verified
            },
            'rental_history': rental_history,
            'blockchain_data': blockchain_data
        })
        
    except Exception as e:
        app.logger.error(f"Error in verify_rental_history: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/record-rental', methods=['POST'])
def record_rental():
    try:
        order_data = request.json
        
        # Initialize rental authenticator
        authenticator = RentalAuthenticator()
        
        # Record rental with full order data
        success = authenticator.record_rental(order_data)
        
        if success:
            return jsonify({'success': True, 'message': 'Rental recorded successfully'})
        else:
            return jsonify({'success': False, 'message': 'Failed to record rental'}), 400
            
    except Exception as e:
        app.logger.error(f"Error recording rental: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

def get_user_wallet_balance(user_id):
    try:
        # Get all orders for the user
        orders = db.child("orders").order_by_child("user_id").equal_to(user_id).get()
        
        total_balance = 0
        if orders.each():
            for order in orders.each():
                order_data = order.val()
                # Add wallet deposit if order status is not 'cancelled' or 'refunded'
                if order_data.get('status') not in ['cancelled', 'refunded']:
                    total_balance += float(order_data.get('wallet_deposit', 0))
        
        return total_balance
    except Exception as e:
        print(f"Error fetching wallet balance: {str(e)}")
        return 0

@app.route('/store-revenue')
def store_revenue():
    if 'email' not in session or 'user_info' not in session:
        flash('Please log in to view revenue details.', 'warning')
        return redirect(url_for('login'))

    user_info = session['user_info']
    store_name = user_info.get('store_name', '')

    # Fetch all orders
    all_orders = db.child("orders").get().val()

    # Initialize revenue data
    revenue_data = {
        'total_orders': 0,
        'total_sales': 0,
        'total_revenue': 0,  # 5% of total sales
        'monthly_data': defaultdict(lambda: {'sales': 0, 'revenue': 0, 'orders': 0}),
        'orders': []
    }

    if all_orders:
        for order_id, order in all_orders.items():
            # Get order items, handle both list and dict formats
            order_items = order.get('items', [])
            if isinstance(order_items, dict):
                order_items = list(order_items.values())
            elif not isinstance(order_items, list):
                order_items = []
            
            # Filter items for this store
            store_items = []
            for item in order_items:
                if isinstance(item, dict) and item.get('store_name', '').lower() == store_name.lower():
                    store_items.append(item)
            
            if store_items:
                # Calculate store's total for this order and revenue (5%)
                store_total = 0
                store_revenue = 0
                for item in store_items:
                    item_total = float(item.get('total_price', 0))
                    store_total += item_total
                    # Calculate 5% revenue for each item
                    store_revenue += (item_total * 0.05)
                
                try:
                    # Get order date - try different formats
                    created_at_str = order.get('created_at', '')
                    try:
                        created_at = datetime.strptime(created_at_str, '%Y-%m-%dT%H:%M:%S.%f')
                    except ValueError:
                        try:
                            created_at = datetime.strptime(created_at_str, '%Y-%m-%d %H:%M')
                        except ValueError:
                            app.logger.error(f"Could not parse date: {created_at_str}")
                            continue
                    
                    month_key = created_at.strftime('%B %Y')
                    
                    # Update monthly data
                    revenue_data['monthly_data'][month_key]['sales'] += store_total
                    revenue_data['monthly_data'][month_key]['revenue'] += store_revenue
                    revenue_data['monthly_data'][month_key]['orders'] += 1
                    
                    # Update totals
                    revenue_data['total_orders'] += 1
                    revenue_data['total_sales'] += store_total
                    revenue_data['total_revenue'] += store_revenue
                    
                    # Get customer name
                    user_id = order.get('user_id')
                    customer_name = 'Unknown Customer'
                    if user_id:
                        user_data = db.child("users").child(user_id).get().val()
                        if user_data:
                            customer_name = user_data.get('name', 'Unknown Customer')
                    
                    # Process items with product details
                    processed_items = []
                    for item in store_items:
                        product_id = item.get('product_id')
                        if product_id:
                            product_details = get_product_details(product_id)
                            if product_details:
                                product_name = product_details.get('product_name', 'Unknown Product')
                            else:
                                product_name = 'Unknown Product'
                        else:
                            product_name = 'Unknown Product'
                            
                        processed_items.append({
                            'product_name': product_name,
                            'quantity': int(item.get('quantity', 1))
                        })
                    
                    # Create order data structure matching template expectations
                    order_data = {
                        'order_id': str(order.get('order_id', order_id)),
                        'customer_name': customer_name,
                        'order_items': processed_items,
                        'total': float(store_total),
                        'revenue': float(store_revenue),
                        'created_at': created_at.strftime('%Y-%m-%d %H:%M')
                    }
                    
                    revenue_data['orders'].append(order_data)
                except Exception as e:
                    app.logger.error(f"Error processing order {order_id}: {str(e)}")
                    continue

    # Sort orders by date (newest first)
    revenue_data['orders'].sort(key=lambda x: x['created_at'], reverse=True)
    
    # Convert monthly data to sorted list
    monthly_data = [
        {
            'month': month,
            'sales': data['sales'],
            'revenue': data['revenue'],
            'orders': data['orders']
        }
        for month, data in revenue_data['monthly_data'].items()
    ]
    monthly_data.sort(key=lambda x: datetime.strptime(x['month'], '%B %Y'), reverse=True)
    revenue_data['monthly_data'] = monthly_data

    app.logger.debug(f"Revenue data structure: {revenue_data}")

    return render_template('andshop/store-revenue.html', 
                         revenue_data=revenue_data,
                         store_name=store_name,
                         user_info=user_info)

if __name__ == '__main__':
    app.run(debug=True)
