from sqlite3 import Date
from weakref import ref
from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash, logging
from networkx import is_path
import pyrebase
import re
import json
from oauthlib.oauth2 import WebApplicationClient
import requests
import os
import firebase_admin
from firebase_admin import db
from firebase_admin import credentials
from dotenv import load_dotenv  # type: ignore
from datetime import datetime  # Import datetime
from werkzeug.utils import secure_filename
import traceback
import logging

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

            session['user_id'] = user_id
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

    return render_template('index.html', email=email, user_info=user_info, products=products)


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
    if 'email' in session and 'user_info' in session:
        email = session['email']
        user_info = session['user_info']
        return render_template('account.html', email=email, user_info=user_info)
    else:
        return redirect(url_for('login'))

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
            print(f"Product Details: {product_details}")
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
from flask import render_template, request, redirect, url_for, flash, session

from flask import render_template, request, redirect, url_for, flash
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

@app.route('/add-to-cart/', methods=['GET', 'POST'])
@app.route('/add-to-cart/<product_id>', methods=['POST'])
def add_to_cart(product_id=None):
    if 'email' not in session or 'user_info' not in session:
        flash('Please log in to add items to your cart.', 'warning')
        return redirect(url_for('login'))

    try:
        product_name = request.form.get('product_name')
        product_image = request.form.get('product_image')
        product_price = request.form.get('product_price')
        quantity = request.form.get('quantity')

        if not all([product_name, product_image, product_price, quantity]):
            missing_fields = [field for field in ['product_name', 'product_image', 'product_price', 'quantity'] if not request.form.get(field)]
            flash(f"Missing required product information: {', '.join(missing_fields)}", 'danger')
            return redirect(url_for('index'))

        try:
            product_price = float(product_price)
            quantity = int(quantity)
        except ValueError:
            flash('Invalid price or quantity.', 'danger')
            return redirect(url_for('index'))

        cart_item = {
            "product_id": product_id,
            "product_name": product_name,
            "product_image": product_image,
            "product_price": product_price,
            "quantity": quantity,
            "total_price": product_price * quantity,
            "user_email": session['email']
        }
        
        result = db.child("cart").push(cart_item)
        
        if result:
            flash('Product added to cart!', 'success')
            return redirect(url_for('view_cart'))
        else:
            flash('Failed to add product to cart. Please try again.', 'danger')
            return redirect(url_for('index'))

    except Exception as e:
        flash(f"An error occurred: {str(e)}", 'danger')
        return redirect(url_for('index'))

@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', error=str(e.description)), 400

@app.route('/cart')
def cart():
    user_id = session.get('user_id')
    if not user_id:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    try:
        # Fetch cart items for the logged-in user from Firebase
        cart_data = db.child("cart").order_by_child("user_email").equal_to(session['email']).get().val()
        
        print("Fetched cart data:", cart_data)  # Debug print to check fetched data
        
        cart_items = []
        if cart_data:
            for key, value in cart_data.items():
                cart_items.append({
                    "product_image": value.get('product_image', ''),
                    "product_name": value.get('product_name', ''),
                    "product_price": float(value.get('product_price', 0)),
                    "product_quantity": int(value.get('quantity', 1)),
                    "total_price": float(value.get('product_price', 0)) * int(value.get('quantity', 1))
                })
        else:
            print("No cart data found for the user.")  # Debug print if no data is found

    except Exception as e:
        print(f"Error fetching cart items: {str(e)}")  # Print the error message
        flash(f"Failed to fetch cart items: {str(e)}", 'danger')
        cart_items = []

    print("Cart items to display:", cart_items)  # Debug print to check processed cart items

    return render_template('cart.html', cart_items=cart_items)

@app.route('/update-cart', methods=['POST'])
def update_cart():
    if 'email' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 403

    try:
        cart_data = request.json
        print('Received cart data:', cart_data)  # Debug log

        if not isinstance(cart_data, list):
            return jsonify({'success': False, 'message': 'Invalid data format'}), 400

        user_email = session['email']
        total_amount = 0

        for item in cart_data:
            product_id = item.get('product_id')
            quantity = int(item.get('quantity', 1))
            
            # Fetch the current product data
            product = db.child("cart").child(user_email).child(product_id).get().val()
            print(f'Product data for {product_id}:', product)  # Debug log
            
            if product:
                product_price = float(product.get('product_price', 0))
                total_price = product_price * quantity
                
                # Update the cart item
                db.child("cart").child(user_email).child(product_id).update({
                    "quantity": quantity,
                    "total_price": total_price
                })
                
                total_amount += total_price

        return jsonify({'success': True, 'total': total_amount}), 200

    except Exception as e:
        print(f"Error updating cart: {str(e)}")
        traceback.print_exc()  # Print full traceback
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/remove-from-cart/<product_id>', methods=['POST'])
def remove_from_cart(product_id):
    if 'email' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 403

    try:
        user_email = session['email']
        print(f'Removing product {product_id} for user {user_email}')  # Debug log

        db.child("cart").child(user_email).child(product_id).remove()
        
        # Recalculate total price
        cart_items = db.child("cart").child(user_email).get().val()
        print('Updated cart items:', cart_items)  # Debug log

        total_amount = sum(float(item.get('total_price', 0)) for item in cart_items.values() if item)

        return jsonify({'success': True, 'total': total_amount}), 200

    except Exception as e:
        print(f"Error removing item from cart: {str(e)}")
        traceback.print_exc()  # Print full traceback
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
