import sqlite3
import os
from datetime import datetime, timedelta, timezone
import time
from functools import wraps
from dotenv import load_dotenv
from passlib.hash import pbkdf2_sha256
from flask import request, g, render_template
import jwt


load_dotenv()
SECRET = os.getenv('SECRET')

_login_attempt_timestamps = {}

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not logged_in():
            return render_template("login.html")
        return func(*args, **kwargs)
    return wrapper

def get_user_with_credentials(email, password):
    try:
        con = sqlite3.connect('bank.db')
        cur = con.cursor()
        cur.execute('''
            SELECT email, name, password FROM users where email=?''',
            (email,))
        row = cur.fetchone()
        if row is None:
            return None
        email, name, hash = row
        if not pbkdf2_sha256.verify(password, hash):
            return None
        return {"email": email, "name": name, "token": create_token(email)}
    finally:
        con.close()

def logged_in():
    token = request.cookies.get('auth_token')
    try:
        data = jwt.decode(token, SECRET, algorithms=['HS256'])
        g.user = data['sub']
        return True
    except jwt.InvalidTokenError:
        return False

def create_token(email):
    now = datetime.now(timezone.utc)  # Make datetime timezone-aware
    payload = {
        'sub': email,
        'iat': int(now.timestamp()),
        'exp': int((now + timedelta(minutes=60)).timestamp())
    }
    token = jwt.encode(payload, SECRET, algorithm='HS256')
    return token

def too_soon_since_last_login():
    client_ip = request.remote_addr
    now = time.time()
    last_attempt = _login_attempt_timestamps.get(client_ip, 0)
    if now - last_attempt < 2:
        return True
    _login_attempt_timestamps[client_ip] = now
    return False


def wait_to_avoid_timing_attacks(start_time, duration=2):
    elapsed = time.time() - start_time
    if elapsed < duration:
        time.sleep(duration - elapsed)
