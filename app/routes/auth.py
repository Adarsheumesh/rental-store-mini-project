from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app import auth, db
from app.utils import is_valid_email, is_valid_password, is_valid_phone, is_valid_name, is_valid_district

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email').lower()
        password = request.form.get('password')
        name = request.form.get('name')
        phone = request.form.get('phone')
        district = request.form.get('district')

        if not is_valid_email(email):
            flash('Invalid email address.', 'danger')
            return render_template('register.html')

        if not is_valid_password(password):
            flash('Password must be at least 8 characters long and include one uppercase letter, one lowercase letter, and one number.', 'danger')
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
                "email": email
            })

            flash('Registration successful! Please verify your email before logging in.', 'success')
            return redirect(url_for('auth.login'))

        except Exception as e:
            error = f"Unsuccessful registration: {str(e)}"
            flash(error, 'danger')
            return render_template('register.html')

    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
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
                return redirect(url_for('main.index'))
            else:
                flash('User data not found.', 'danger')

        except Exception as e:
            error = f"Unsuccessful login: {str(e)}"
            flash(error, 'danger')

    return render_template('login.html')

@auth_bp.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form.get('email')
        try:
            user = auth.sign_in_with_email_and_password(email, request.form.get('password'))
            auth.send_email_verification(user['idToken'])
            flash('Verification email sent.', 'success')
        except:
            flash('Failed to send verification email.', 'danger')

    return render_template('resend_verification.html')

@auth_bp.route('/logout')
def logout():
    session.pop('email', None)
    session.pop('user_info', None)
    return redirect(url_for('auth.login'))
