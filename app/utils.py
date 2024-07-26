import re
import requests
from flask import current_app as app

def get_google_provider_cfg():
    return requests.get(app.config['GOOGLE_DISCOVERY_URL']).json()

def is_valid_email(email):
    regex = r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$'
    return re.match(regex, email)

def is_valid_password(password):
    regex = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{8,}$'
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
