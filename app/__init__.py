from flask import Flask
from app.config import Config
import pyrebase

firebase = None
auth = None
db = None

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    global firebase, auth, db
    # Initialize Firebase
    firebase = pyrebase.initialize_app(app.config['FIREBASE_CONFIG'])
    auth = firebase.auth()
    db = firebase.database()

    # Register Blueprints
    from app.routes.auth import auth_bp
    from app.routes.main import main_bp
    from app.routes.google import google_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(google_bp)

    return app
