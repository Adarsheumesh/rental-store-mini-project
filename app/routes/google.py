from flask import Blueprint, redirect, url_for, request, session, flash, json, render_template
from oauthlib.oauth2 import WebApplicationClient
import requests
from app.utils import get_google_provider_cfg
from app import auth, db

google_bp = Blueprint('google', __name__)

@google_bp.route('/login/google')
def google_login():
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    client = WebApplicationClient(app.config['GOOGLE_CLIENT_ID'])

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@google_bp.route('/login/google/callback')
def google_callback():
    code = request.args.get("code")
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    client = WebApplicationClient(app.config['GOOGLE_CLIENT_ID'])
    
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
        auth=(app.config['GOOGLE_CLIENT_ID'], app.config['GOOGLE_CLIENT_SECRET']),
    )

    token_json = token_response.json()
    session['google_token'] = token_json['access_token']

    client.parse_request_body_response(json.dumps(token_json))
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    userinfo = userinfo_response.json()

    if userinfo.get("email_verified"):
        unique_id = userinfo["sub"]
        users_name = userinfo["name"]
        users_email = userinfo["email"]
        picture = userinfo["picture"]

        session['email'] = users_email
        session['name'] = users_name
        session['picture'] = picture

        try:
            user = auth.create_user_with_email_and_password(users_email, unique_id)
            user_id = user['localId']
        except:
            user = auth.sign_in_with_email_and_password(users_email, unique_id)
            user_id = user['localId']

        # Fetch user data from the database and update the session
        user_data = db.child("users").child(user_id).get().val()

        if user_data:
            session['user_id'] = user_id
            session['user_info'] = user_data

        flash('Logged in successfully with Google.', 'success')
        return redirect(url_for('main.index'))
    else:
        flash('User email not available or not verified by Google.', 'danger')
        return redirect(url_for('auth.login'))
