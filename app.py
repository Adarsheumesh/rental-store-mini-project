from flask import Flask, render_template, request, redirect, url_for, session, flash
import pyrebase
import re
import json
from oauthlib.oauth2 import WebApplicationClient
import requests
import os
from dotenv import load_dotenv # type: ignore

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
        status = 0  # Default status

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
            user = auth.create_user_with_email_and_password(email, password)
            user_id = user['localId']
            auth.send_email_verification(user['idToken'])

            db.child("users").child(user_id).set({
                "name": name,
                "phone": phone,
                "district": district,
                "email": email,
                "user_type": user_type,  # Save user type
                "status": status  # Default status
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
                    return render_template('admin/index.html', email=email, user_info=user_data)
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
        return render_template('index.html', email=email, user_info=user_info)
    return render_template('index.html')

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

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        try:
            auth.send_password_reset_email(email)
            flash('Password reset email sent.', 'success')
        except Exception as e:
            flash(f'Failed to send password reset email: {str(e)}', 'danger')

    return render_template('forgot_password.html')

@app.route('/logout')
def logout():
    session.pop('email', None)
    session.pop('user_info', None)
    session.pop('user_id', None)
    session.pop('google_token', None, None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/update-account', methods=['GET', 'POST'])
def update_account():
    if 'email' not in session or 'user_info' not in session:
        return redirect(url_for('login'))

    email = session['email']
    user_info = session['user_info']

    if request.method == 'POST':
        name = request.form.get('name')
        phone = request.form.get('phone')
        district = request.form.get('district')

        if not is_valid_name(name):
            flash('Name cannot contain numbers or special characters.', 'danger')
            return render_template('update_account.html', email=email, user_info=user_info)

        if not is_valid_phone(phone):
            flash('Invalid phone number.', 'danger')
            return render_template('update_account.html', email=email, user_info=user_info)

        if not is_valid_district(district):
            flash('District cannot contain numbers or special characters.', 'danger')
            return render_template('update_account.html', email=email, user_info=user_info)

        user_id = session['user_id']
        try:
            db.child("users").child(user_id).update({
                "name": name,
                "phone": phone,
                "district": district
            })

            # Update session info
            session['user_info'] = {
                "name": name,
                "phone": phone,
                "district": district,
                "email": email
            }

            flash('Account updated successfully!', 'success')
            return redirect(url_for('account'))
        except Exception as e:
            flash(f"Failed to update account: {str(e)}", 'danger')

    return render_template('update_account.html', email=email, user_info=user_info)

if __name__ == '__main__':
    app.run(debug=True)
