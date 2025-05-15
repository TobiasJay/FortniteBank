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

# for future use it would be better to use a database or a cache like Redis
_login_attempt_timestamps = {} 

def login_required(func):
    """
    Decorator that ensures a user is logged in before allowing access to the decorated route.
    If the user is not authenticated, renders the login page instead of executing the route handler.

    Args:
        func (function): The route handler function to wrap.

    Returns:
        function: The wrapped function that checks authentication before execution.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not logged_in():
            return render_template("login.html")
        return func(*args, **kwargs)
    return wrapper

def get_user_with_credentials(email, password):
    """
    Authenticate a user by email and password.

    Connects to the 'bank.db' SQLite database, retrieves the user record with the given email,
    and verifies the provided password against the stored password hash using PBKDF2-SHA256.
    If authentication is successful, returns a dictionary containing the user's email, name,
    and a generated authentication token. Returns None if authentication fails.

    Args:
        email (str): The user's email address.
        password (str): The user's plaintext password.

    Returns:
        dict or None: A dictionary with keys 'email', 'name', and 'token'
                      if authentication succeeds and None otherwise.
    """
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
    """
    Checks if the user is logged in by verifying the JWT token from cookies.

    Retrieves the 'auth_token' from the request cookies and attempts to decode it using the provided 
    secret and HS256 algorithm.
    If the token is valid, sets the user information in the Flask global `g` object and returns True
    If the token is invalid or missing, returns False.

    Returns:
        bool: True if the user is authenticated, False otherwise.
    """
    token = request.cookies.get('auth_token')
    try:
        data = jwt.decode(token, SECRET, algorithms=['HS256'])
        g.user = data['sub']
        return True
    except jwt.InvalidTokenError:
        return False

def create_token(email):
    """
    Generates a JSON Web Token (JWT) for the given email address.

    Args:
        email (str): The email address to include as the subject ('sub') in the token payload.

    Returns:
        str: The encoded JWT as a string.

    The token includes the following claims:
        - 'sub': The provided email address.
        - 'iat': Issued at time (current UTC timestamp).
        - 'exp': Expiration time (60 minutes from issuance).

    The token is signed using the HS256 algorithm and a secret key.
    """
    now = datetime.now(timezone.utc)  # Make datetime timezone-aware
    payload = {
        'sub': email,
        'iat': int(now.timestamp()),
        'exp': int((now + timedelta(minutes=60)).timestamp())
    }
    token = jwt.encode(payload, SECRET, algorithm='HS256')
    return token

def too_soon_since_last_login():
    """
    Checks if the current login attempt from a client IP address is occurring too 
    soon after the previous attempt.

    Returns:
        bool: True if the time since the last login attempt from the same client IP 
              is less than 2 seconds, False otherwise.

    Notes:
        - Uses the client's IP address to track login attempt timestamps.
        - Updates the timestamp for the client IP if the attempt is not too soon.
        - Assumes the existence of a global dictionary `_login_attempt_timestamps`
          and access to `request.remote_addr`.
    """
    client_ip = request.remote_addr
    now = time.time()
    last_attempt = _login_attempt_timestamps.get(client_ip, 0)
    if now - last_attempt < 2:
        return True
    _login_attempt_timestamps[client_ip] = now
    return False


def wait_to_avoid_timing_attacks(start_time, duration=2):
    """
    Ensures a minimum execution time to help mitigate timing attacks.

    Args:
        start_time (float): The timestamp (in seconds) when the sensitive operation started.
        duration (float, optional): The minimum total time (in seconds) the operation should take.
        Defaults to 2.

    This function calculates the elapsed time since `start_time` and, if it is less than `duration`,
    sleeps for the remaining time to ensure the total duration is at least `duration` seconds.
    """
    elapsed = time.time() - start_time
    if elapsed < duration:
        time.sleep(duration - elapsed)
