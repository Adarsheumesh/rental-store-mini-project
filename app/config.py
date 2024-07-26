import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'turbolegion6282')
    FIREBASE_CONFIG = {
        "apiKey": os.getenv('FIREBASE_API_KEY', "AIzaSyB42nHmPcpj7BmOPPdO93lXqzA3PjjXZOc"),
        "authDomain": "project-dbebd.firebaseapp.com",
        "projectId": "project-dbebd",
        "storageBucket": "project-dbebd.appspot.com",
        "messagingSenderId": "374516311348",
        "appId": "1:374516311348:web:d916facf6720a4e275f161",
        "databaseURL": "https://project-dbebd-default-rtdb.asia-southeast1.firebasedatabase.app/"
    }
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', "374516311348-552mjim983t2bctndppsjper37rmkboc.apps.googleusercontent.com")
    GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET', "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")
    GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
    OAUTHLIB_INSECURE_TRANSPORT = '1'
