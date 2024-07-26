from flask import Blueprint, render_template, session, redirect, url_for, flash, request
from app import auth, db
from app.utils import is_valid_name, is_valid_phone, is_valid_district

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def home():
    return redirect(url_for('auth.login'))

@main_bp.route('/index')
def index():
    if 'email' in session and 'user_info' in session:
        email = session['email']
        user_info = session['user_info']
        return render_template('index.html', email=email, user_info=user_info)
    else:
        return redirect(url_for('auth.login'))

@main_bp.route('/account')
def account():
    if 'email' in session and 'user_info' in session:
        email = session['email']
        user_info = session['user_info']
        return render_template('account.html', email=email, user_info=user_info)
    else:
        return redirect(url_for('auth.login'))

@main_bp.route('/account-details')
def account_details():
    return render_template('account_details.html')

@main_bp.route('/shop')
def shop():
    return render_template('shop.html')

@main_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        try:
            auth.send_password_reset_email(email)
            flash('Password reset email sent.', 'success')
        except:
            flash('Failed to send password reset email.', 'danger')
    return render_template('forgot_password.html')

@main_bp.route('/update-account', methods=['GET', 'POST'], endpoint='update_account')
def update_account():
    if 'email' not in session or 'user_info' not in session:
        return redirect(url_for('auth.login'))

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
