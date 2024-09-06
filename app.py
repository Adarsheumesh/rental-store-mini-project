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

logging.basicConfig(level=logging.DEBUG)

load_dotenv()

# Allow insecure transport for development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Initialize Flask application
app = Flask(__name__)
app.secret_key = 'turbolegion6282'

# Firebase configuration
config = {
    "apiKey": "AIzaSyB42nHmPcpj7BmOPPdO93lXqzA3PjjXZOc",
    "authDomain": "project-dbebd.firebaseapp.com",
    "projectId": "project-dbebd",
    "storageBucket": "project-dbebd.appspot.com",
    "messagingSenderId": "374516311348",
    "appId": "1:374516311348:web:d916facf6720a4e275f161",
    "databaseURL": "https://project-dbebd-default-rtdb.asia-southeast1.firebasedatabase.app/"
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
    if 'email' in session and 'user_info' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email').lower()
        password = request.form.get('password')

        if not is_valid_email(email):
            flash('Invalid email address.', 'danger')
            return render_template('login.html')

        if not is_valid_password(password):
            flash('Invalid password.', 'danger')
            return render_template('login.html')

        try:
            user = auth.sign_in_with_email_and_password(email, password)
            user_id = user['localId']

            if not auth.get_account_info(user['idToken'])['users'][0]['emailVerified']:
                flash('Email not verified. Please check your email for the verification link.', 'danger')
                return render_template('login.html')

            session['user_id'] = user_id  # Store user_id in session
            user_data = db.child("users").child(user_id).get().val()

            if user_data:
                session['email'] = email
                session['user_info'] = user_data

                # Redirect based on user type
                if user_data.get('user_type') == 'vendor':
                    return redirect(url_for('vendor_dashboard'))
                else:
                    return redirect(url_for('index'))
            else:
                flash('User data not found.', 'danger')

        except Exception as e:
            error = f"Unsuccessful login: {str(e)}"
            flash(error, 'danger')

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
        flash(f"Failed to retrieve best seller products: {str(e)}", 'danger')

    return render_template('index.html', 
                           email=email, 
                           user_info=user_info, 
                           products=products, 
                           best_seller_products=best_seller_products)


@app.route('/vendor_dashboard')
def vendor_dashboard():
    if 'email' in session and 'user_info' in session:
        email = session['email']
        user_info = session['user_info']
        return render_template('andshop/index.html', email=email, user_info=user_info)
    else:
        return redirect(url_for('login'))

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
        
        # Sort orders by date (assuming there's a 'date' field)
        orders.sort(key=lambda x: x.get('date', ''), reverse=True)

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
        else:
            return jsonify({
                'success': False,
                'message': 'Order not found or unauthorized'
            }), 404
    except Exception as e:
        print(f"Error fetching order details: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error fetching order details'
        }), 500

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
        email = request.form['email']
        try:
            auth.send_password_reset_email(email)
            flash('Password reset email sent successfully. Please check your inbox.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Failed to send password reset email: {str(e)}', 'danger')
            return render_template('reset_password.html')
    
    # If it's a GET request, render the reset password form
    return render_template('reset_password.html')

@app.route('/logout')
def logout():
    # Clear the session
    session.pop('email', None)
    session.pop('user_info', None)
    session.pop('user_id', None)
    session.pop('google_token', None)

    # Flash message
    flash('You have been logged out.', 'info')
    
    # Redirect to the index page
    response = redirect(url_for('index'))

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

        if not is_valid_name(name):
            flash('Name cannot contain numbers or special characters.', 'danger')
            return render_template('account.html', email=email, user_info=user_info)

        if not is_valid_phone(phone):
            flash('Invalid phone number.', 'danger')
            return render_template('account.html', email=email, user_info=user_info)

        if not is_valid_district(district):
            flash('District cannot contain numbers or special characters.', 'danger')
            return render_template('account.html', email=email, user_info=user_info)

        update_data = {
            "name": name,
            "phone": phone,
            "district": district
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

# Vendor-start
@app.route('/product-add')
def producadd():
    return render_template('/andshop/product-add.html')
@app.route('/user-list')
def user_list():
    # Check if the user is logged in
    if 'user_info' in session:
        try:
            # Fetch all users from the Firebase database
            users = db.child("users").get().val()
            
            # Filter users where user_type is 'customer'
            if users:
                customers = {user_id: user for user_id, user in users.items() if user.get('user_type') == 'customer'}
                
                if customers:
                    return render_template('/andshop/user-list.html', users=customers)
                else:
                    flash('No customers found.', 'warning')
                    return render_template('/andshop/user-list.html', users={})
            else:
                flash('No users found.', 'warning')
                return render_template('/andshop/user-list.html', users={})
        except Exception as e:
            flash(f"Error fetching user list: {str(e)}", 'danger')
            return redirect(url_for('vendor_dashboard'))
    else:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))


@app.route('/user-profile')
def user_profile():
    if 'user_info' in session:
        user_info = session['user_info']
        return render_template('/andshop/user-profile.html', user=user_info)
    else:
        flash('You need to log in to view your profile.', 'warning')
        return redirect(url_for('login'))
    

@app.route('/add-product', methods=['GET', 'POST'])
def add_product():
    if 'email' not in session or 'user_info' not in session:
        return redirect(url_for('login'))

    categories_list = []
    try:
        # Fetch categories from Firebase
        categories_data = db.child("categories").get().val()
        print("Raw categories data:", categories_data)  # Debug print
        if categories_data:
            for key, value in categories_data.items():
                categories_list.append({
                    "id": key,
                    "category_name": value.get('category_name', 'N/A')
                })
        print("Categories fetched:", categories_list)  # Debug print
    except Exception as e:
        flash(f"Failed to fetch categories: {str(e)}", 'danger')
        return redirect(url_for('index'))  # Redirect to a safe page

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
            # Insert product into the database
            db.child("products").push({
                "product_name": product_name,
                "product_type": product_type,
                "main_category": main_category,
                "product_quantity": product_quantity,
                "product_price": product_price,
                "product_image": product_image_url
            })

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

@app.route('/product/<product_id>')
def product_detail(product_id):
    try:
        # Fetch product details from Firebase using the provided product_id
        product = db.child("products").child(product_id).get()
        product_details = product.val() if product else None

        if product_details:
            # Add the id to the product_details dictionary
            product_details['id'] = product_id
            print(f"Product Details: {product_details}")  # Debug print
        else:
            print("No product details found.")

        # If no product details are found, flash a warning and redirect to the product list
        if product_details is None:
            flash('Product not found.', 'warning')
            return redirect(url_for('product_list'))

    except Exception as e:
        # If there's an error fetching product details, flash an error message
        flash(f"Failed to fetch product details: {str(e)}", 'danger')
        return redirect(url_for('product_list'))

    # Render the product detail template with the fetched product details
    return render_template('product.html', product_details=product_details)
@app.route('/products')
def product_list():
    try:
        # Fetch all products from the Firebase database
        products = db.child("products").get()
        product_list = products.val() if products else {}

        if not product_list:
            flash('No products found.', 'warning')

    except Exception as e:
        flash(f"Failed to fetch product list: {str(e)}", 'danger')
        return redirect(url_for('index'))  # Redirect to home or an appropriate page

    # Render the product list template with the fetched product data
    return render_template('/andshop/product-list.html', products=product_list)
            # edit product_page 
@app.route('/edit-product/<product_id>', methods=['GET', 'POST'])
def update_product(product_id):
    print(f"Accessing edit-product route for product_id: {product_id}")
    try:
        # Retrieve the existing product data
        product = db.child("products").child(product_id).get().val()
        print(f"Product retrieved: {product}")

        if not product:
            print(f"Product with ID {product_id} not found in the database.")
            flash('Product not found.', 'danger')
            return redirect(url_for('product_list'))

        if request.method == 'POST':
            # Extract form data
            product_name = request.form.get('product_name', product['product_name'])
            product_quantity = request.form.get('product_quantity', product['product_quantity'])
            main_category = request.form.get('main_category', product['main_category'])
            product_type = request.form.get('product_type', product['product_type'])
            product_price = request.form.get('product_price', product['product_price'])

            # Prepare data for update
            update_data = {
                "product_name": product_name,
                "product_quantity": product_quantity,
                "main_category": main_category,
                "product_type": product_type,
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
        return render_template('andshop/edit_product.html', product=product, product_id=product_id)

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

@app.route('/add-category')
def add_category_page():
    return render_template('/andshop/add-category.html')  
@app.route('/add-category', methods=['POST'])
def add_category():
    if request.method == 'POST':
        # Retrieve category name from form
        category_name = request.form.get('category-name')

        # Validate category name
        if not category_name:
            flash('Category name is required.', 'danger')
            return redirect(url_for('add_category_page'))

        try:
            # Insert category into Firebase Realtime Database
            db.child("categories").push({
                "category_name": category_name,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Optional: add a timestamp
            })

            flash('Category added successfully!', 'success')
            return redirect(url_for('main_category'))  # Redirect to the category list page
        except Exception as e:
            flash(f"Failed to add category: {str(e)}", 'danger')

    return redirect(url_for('add_category_page'))  # Redirect if method is not POST
@app.route('/categories', methods=['GET'])
def categories():
    try:
        # Fetch categories from Firebase
        categories_data = db.child("categories").get().val()
        print("Raw categories data:", categories_data)  # Debug print
        # Convert data into a list of dictionaries for easier processing
        categories_list = []
        if categories_data:
            for key, value in categories_data.items():
                categories_list.append({
                    "id": key,
                    "category_name": value.get('category_name', 'N/A'),
                    "created_at": value.get('created_at', 'N/A')
                })
        
        print("Processed categories list:", categories_list)  # Debug print

        # Pass the categories list to the template
        return render_template('/andshop/main-category.html', categories=categories_list)
        
    except Exception as e:
        error_message = f"Error fetching categories: {str(e)}"
        print(error_message)  # Print to console for debugging
        flash(error_message, 'danger')
        return render_template('/andshop/main-category.html', categories=[])

@app.route('/main-category')
def main_category():
    return categories()
@app.route('/delete-category/<id>', methods=['POST'])
def delete_category(id):
    try:
        # Delete the category from the database using the provided ID
        db.child("categories").child(id).remove()
        flash('Category deleted successfully!', 'success')
    except Exception as e:
        flash(f"Failed to delete category: {str(e)}", 'danger')

    return redirect(url_for('main_category'))  # Redirect back to the main category page
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
        quantity = data.get('quantity', 1)  # Default to 1 if quantity is not provided

        # Check if the product already exists in the cart
        existing_item = db.child("cart").order_by_child("user_id").equal_to(user_id).get().val()
        if existing_item:
            for item_key, item in existing_item.items():
                if item.get('product_id') == product_id:
                    # Update quantity if the product is already in the cart
                    new_quantity = item['quantity'] + quantity
                    db.child("cart").child(item_key).update({"quantity": new_quantity})
                    cart_count = get_cart_count(user_id)
                    return jsonify({'success': True, 'message': 'Product quantity updated in cart!', 'cart_count': cart_count}), 200

        # If the product is not in the cart, add it
        cart_item = {
            "product_id": product_id,
            "quantity": quantity,
            "user_id": user_id,
        }
        
        result = db.child("cart").push(cart_item)
        
        if result:
            cart_count = get_cart_count(user_id)
            return jsonify({'success': True, 'message': 'Product added to cart!', 'cart_count': cart_count}), 200
        else:
            return jsonify({'success': False, 'message': 'Failed to add product to cart. Please try again.'}), 400

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
        # Fetch all cart items for the user
        cart_ref = db.child("cart").order_by_child("user_id").equal_to(user_id)
        cart_items = cart_ref.get().val()
        
        logging.debug(f"Cart items for user {user_id}: {cart_items}")
        
        if cart_items:
            for cart_item_key, cart_item in cart_items.items():
                logging.debug(f"Checking cart item: {cart_item_key} - {cart_item}")
                if cart_item_key == item_key:
                    logging.info(f"Found item to remove: {cart_item_key}")
                    product_id = cart_item.get('product_id')
                    product = db.child("products").child(product_id).get().val()
                    product_name = product.get('product_name', 'Unknown Product') if product else 'Unknown Product'
                    db.child("cart").child(cart_item_key).remove()
                    logging.info("Item removed successfully")
                    return jsonify({
                        'success': True, 
                        'message': f'{product_name} removed from cart successfully',
                        'removed_item_key': cart_item_key
                    }), 200
        
        logging.warning(f"Cart item {item_key} not found for user {user_id}")
        return jsonify({'success': False, 'message': 'Cart item not found'}), 404
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
    try:
        # Extract form data
        product_ids = request.form.getlist('product_ids[]')
        quantities = request.form.getlist('quantities[]')
        rent_from = request.form.getlist('rent_from[]')
        rent_to = request.form.getlist('rent_to[]')
        rental_days = request.form.getlist('rental_days[]')
        item_totals = request.form.getlist('item_totals[]')
        order_total = float(request.form.get('order_total', 0))
        use_different_shipping = request.form.get('use_different_shipping') == 'on'
        shipping_address = request.form.get('shipping_address')
        shipping_address2 = request.form.get('shipping_address2')

        # Prepare order items
        order_items = [
            {
                'product_id': pid,
                'quantity': int(qty),
                'rent_from': rf,
                'rent_to': rt,
                'rental_days': int(rd),
                'item_total': float(it)
            }
            for pid, qty, rf, rt, rd, it in zip(product_ids, quantities, rent_from, rent_to, rental_days, item_totals)
        ]

        # Create order in database
        user_id = session.get('user_id')
        order_id = create_order_in_database(user_id, order_items, order_total, use_different_shipping, shipping_address, shipping_address2)

        # Process payment (implement your payment logic here)
        payment_success, payment_intent_id = process_payment(order_total)

        if payment_success:
            # Update order status
            update_order_status(order_id, 'paid', payment_intent_id)
            
            # Clear the cart
            clear_cart(user_id)

            return jsonify({'success': True, 'redirect_url': url_for('payment_success', order_id=order_id)})
        else:
            return jsonify({'success': False, 'error': 'Payment processing failed'})

    except Exception as e:
        app.logger.error(f"Error in create_payment: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

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



def create_order_in_database(user_id, order_items, order_total, use_different_shipping, shipping_address, shipping_address2):
    # Implement your logic to create an order in the database
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
    
    # Add the order to your database (e.g., using Firebase)
    new_order = db.child("orders").push(order_data)
    return new_order['name']  # Return the new order ID

def create_order_in_database(user_id, order_items, order_total, use_different_shipping, shipping_address, shipping_address2):
    try:
        order_data = {
            'user_id': user_id,
            'items': order_items,
            'order_total': order_total,
            'use_different_shipping': use_different_shipping,
            'shipping_address': shipping_address or '',
            'shipping_address2': shipping_address2 or '',
            'status': 'pending',
            'created_at': datetime.now().isoformat()
        }
        
        new_order = db.child("orders").push(order_data)
        return new_order['name']
    except Exception as e:
        app.logger.error(f"Error creating order in database: {str(e)}")
        raise

def create_order_in_database(user_id, order_items, order_total, use_different_shipping, shipping_address, shipping_address2):
    try:
        order_data = {
            'user_id': user_id,
            'items': order_items,
            'order_total': order_total,
            'use_different_shipping': use_different_shipping,
            'shipping_address': shipping_address or '',
            'shipping_address2': shipping_address2 or '',
            'status': 'pending',
            'created_at': datetime.now().isoformat()
        }
        
        new_order = db.child("orders").push(order_data)
        return new_order['name']
    except Exception as e:
        app.logger.error(f"Error creating order in database: {str(e)}")
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

def create_order_in_database(user_id, order_items, order_total, use_different_shipping, shipping_address, shipping_address2):
    try:
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
        new_order = db.child("orders").push(order_data)
        return new_order['name']  # Return the new order ID
    except Exception as e:
        app.logger.error(f"Error creating order in database: {str(e)}")
        raise

def update_order_status(order_id, status, payment_intent_id=None):
    try:
        # Fetch all orders
        all_orders = db.child("orders").get().val()
        
        if all_orders:
            for key, order in all_orders.items():
                if order.get('order_id') == order_id:
                    update_data = {
                        'status': status,
                        'updated_at': datetime.now().isoformat()
                    }
                    if payment_intent_id:
                        update_data['payment_intent_id'] = payment_intent_id
                    
                    db.child("orders").child(key).update(update_data)
                    app.logger.info(f"Order status updated for order ID: {order_id}")
                    return
        
        app.logger.warning(f"Order not found for updating status: {order_id}")
    except Exception as e:
        app.logger.error(f"Error updating order status: {str(e)}")
        raise

def create_order_in_database(user_id, order_items, order_total, use_different_shipping, shipping_address, shipping_address2):
    try:
        order_id = str(uuid.uuid4())  # Generate a unique order ID
        order_data = {
            'order_id': order_id,
            'user_id': user_id,
            'items': order_items,
            'order_total': order_total,
            'use_different_shipping': use_different_shipping,
            'shipping_address': shipping_address,
            'shipping_address2': shipping_address2,
            'status': 'pending',
            'created_at': datetime.now().isoformat()
        }
        new_order = db.child("orders").push(order_data)
        app.logger.info(f"New order created with ID: {order_id}")
        return order_id
    except Exception as e:
        app.logger.error(f"Error creating order in database: {str(e)}")
        raise

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
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('wishlist.html')

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

    user_id = session['user_id']
    data = request.get_json()
    product_id = data.get('product_id')

    try:
        # Check if the product is already in the wishlist
        existing_item = db.child("wishlist").order_by_child("user_id").equal_to(user_id).get().val()
        if existing_item:
            for item_key, item_data in existing_item.items():
                if item_data.get('product_id') == product_id:
                    return jsonify({'success': False, 'message': 'Product already in wishlist'}), 400

        # Add the product to the wishlist
        wishlist_item = {
            'user_id': user_id,
            'product_id': product_id,
            'added_at': datetime.now().isoformat()
        }
        db.child("wishlist").push(wishlist_item)

        return jsonify({'success': True, 'message': 'Product added to wishlist'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

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

    # Styles
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Center', alignment=1))
    styles.add(ParagraphStyle(name='Right', alignment=2))

    # Header
    elements.append(Paragraph("INVOICE", styles['Title']))
    elements.append(Spacer(1, 0.25*inch))

    # Company Info
    elements.append(Paragraph("Your Company Name", styles['Heading2']))
    elements.append(Paragraph("123 Business Street, City, Country", styles['Normal']))
    elements.append(Paragraph("Phone: +1 234 567 890", styles['Normal']))
    elements.append(Paragraph("Email: info@yourcompany.com", styles['Normal']))
    elements.append(Spacer(1, 0.25*inch))

    # Customer and Order Info
    data = [
        ["Order ID:", order_id],
        ["Date:", order.get('created_at', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))],
        ["Customer:", user_name],
        ["Email:", user_email],
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
    data = [["Item", "Quantity", "Rent From", "Rent To", "Days", "Price"]]
    for item in order.get('items', []):
        product_id = item.get('product_id')
        product_data = db.child("products").child(product_id).get().val()
        product_name = product_data.get('product_name', 'Unknown Product') if product_data else 'Unknown Product'
        
        data.append([
            product_name,
            str(item.get('quantity', 0)),
            item.get('rent_from', 'N/A'),
            item.get('rent_to', 'N/A'),
            str(item.get('rental_days', 0)),
            f"₹{item.get('total_price', 0):.2f}"
        ])
    
    # Add total row
    total_price = order.get('order_total', 0)
    data.append(["Total", "", "", "", "", f"₹{total_price:.2f}"])

    table = Table(data, colWidths=[2.5*inch, 0.75*inch, 1*inch, 1*inch, 0.75*inch, 1*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 12),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-2), colors.beige),
        ('TEXTCOLOR', (0,1), (-1,-1), colors.black),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,1), (-1,-1), 10),
        ('TOPPADDING', (0,1), (-1,-1), 6),
        ('BOTTOMPADDING', (0,1), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
        ('BACKGROUND', (0,-1), (-1,-1), colors.grey),
        ('TEXTCOLOR', (0,-1), (-1,-1), colors.whitesmoke),
        ('FONTNAME', (0,-1), (-1,-1), 'Helvetica-Bold'),
    ]))
    elements.append(table)

    # Footer
    elements.append(Spacer(1, 0.5*inch))
    elements.append(Paragraph("Thank you for your business!", styles['Center']))

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
        # Fetch the specific order
        order = db.child("orders").child(order_id).get().val()

        if not order:
            return jsonify({'success': False, 'message': 'Order not found'}), 404

        if str(order.get('user_id')) != str(user_id):
            return jsonify({'success': False, 'message': 'You do not have permission to view this order'}), 403

        # Ensure all necessary fields are present
        order_data = {
            'order_id': order_id,
            'created_at': order.get('created_at', 'N/A'),
            'status': order.get('status', 'N/A'),
            'order_total': float(order.get('order_total', 0)),
            'items': []
        }

        # Fetch product details for each item in the order
        items = order.get('items', [])
        for item in items:
            product_id = item.get('product_id')
            product_details = get_product_details(product_id) if product_id else {}
            order_data['items'].append({
                'product_name': product_details.get('product_name', 'Unknown Product'),
                'image_url': product_details.get('product_image', ''),
                'quantity': item.get('quantity', 'N/A'),
                'rent_from': item.get('rent_from', 'N/A'),
                'rent_to': item.get('rent_to', 'N/A'),
                'rental_days': item.get('rental_days', 'N/A'),
                'total_price': float(item.get('total_price', 0))
            })

        return jsonify({'success': True, 'order': order_data})

    except Exception as e:
        print(f"Error in order_details: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

def get_product_details(product_id):
    try:
        product = db.child("products").child(product_id).get().val()
        print(f"Fetched product details for ID {product_id}: {product}")
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

if __name__ == '__main__':
    app.run(debug=True)
