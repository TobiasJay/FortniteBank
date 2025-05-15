import time
import os

from dotenv import load_dotenv
from flask import (
    Flask, request, make_response, redirect,
    render_template, g, abort, flash)
from flask_wtf.csrf import CSRFProtect
from user_service import (
    get_user_with_credentials, login_required,
    too_soon_since_last_login, wait_to_avoid_timing_attacks)
from account_service import get_balance, do_transfer



app = Flask(__name__)

load_dotenv()
app.config['SECRET_KEY'] = os.getenv('CSRF_SECRET_KEY')
csrf = CSRFProtect(app)


@app.route("/", methods=['GET'])
@login_required
def home():
    """
    @login_required decorator checks if the user is logged in. and redirects to the
    login page if not.
    
    Returns a redirect to the dashboard.
    """
    return redirect('/dashboard')

@app.route("/login", methods=["POST"])
def login():
    """
    Handles user login requests.
    This route processes login form submissions by validating user credentials,
    enforcing rate limiting to prevent brute-force attacks, and mitigating timing
    attacks by normalizing response times. If authentication is successful, the
    user is redirected to the dashboard with an authentication token set in a
    cookie. Otherwise, appropriate error messages are rendered on the login page.
    Returns:
        Response: A redirect to the dashboard with an auth token on success,
        or the login page with an error message on failure.

    """
    if too_soon_since_last_login(): # validates that the login
        return render_template("login.html", error="Too many login attempts, please wait a moment.")
    start_time = time.time()

    email = request.form.get("email")
    password = request.form.get("password")
    user = get_user_with_credentials(email, password)

    wait_to_avoid_timing_attacks(start_time)

    if not user:
        return render_template("login.html", error="Invalid credentials")
    response = make_response(redirect("/dashboard"))
    response.set_cookie("auth_token", user["token"])
    return response, 303

@app.route("/dashboard", methods=['GET'])
@login_required
def dashboard():
    """
    Renders the dashboard page for the logged-in user.
    Returns:
        Response: The rendered 'dashboard.html' template with the user's email passed as context.
    """
    return render_template("dashboard.html", email=g.user)

@app.route("/details", methods=['GET'])
@login_required
def details():
    """
    Renders the details page for a specific user account.

    Retrieves the account number from the request arguments, fetches the account balance for the 
    current user, and renders the 'details.html' template with the user information, account number
    and balance.

    Returns:
        A rendered HTML page displaying the account details.

    Raises:
        KeyError: If the 'account' parameter is missing from the request arguments.
    """
    account_number = request.args['account']
    return render_template(
        "details.html", 
        user=g.user,
        account_number=account_number,
        balance = get_balance(account_number, g.user))

@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    """
    Handle money transfer requests between accounts for the logged-in user.
    GET: Render the transfer form.
    POST: Process a transfer request by validating input, checking balances,
    and performing the transfer.
    Returns:
        - On GET: Rendered transfer form template.
        - On successful POST: Redirect to dashboard with a success message.
        - On error: Aborts with appropriate HTTP status and message.
    Raises:
        - 400 Bad Request: If the amount is invalid, negative, exceeds limit, or insufficient funds.
        - 404 Not Found: If the source account does not exist.
    """
    if request.method == "GET":
        return render_template("transfer.html", user=g.user)

    source = request.form.get("from")
    target = request.form.get("to")
    try:
        amount = int(request.form.get("amount"))
    except ValueError:
        abort(400, "Invalid amount, must be an integer")

    if amount < 0:
        abort(400, "NO STEALING")
    if amount > 1000:
        abort(400, "WOAH THERE TAKE IT EASY")

    available_balance = get_balance(source, g.user)
    if available_balance is None:
        abort(404, "Account not found")
    if amount > available_balance:
        abort(400, "You don't have that much")

    if do_transfer(source, target, amount):
        flash(message="Transfer successful.")
    else:
        abort(400, "Something bad happened")

    response = make_response(redirect("/dashboard"))
    return response, 303

@app.route("/logout", methods=["GET"])
def logout():
    """'''
    Logs out the current user by deleting the 'auth_token' cookie and redirecting to the dashboard.
    Returns:
        tuple: A tuple containing the response object (with the cookie deleted and redirect set)
               and the HTTP status code 303 (See Other).
    """
    response = make_response(redirect("/dashboard"))
    response.delete_cookie("auth_token")
    return response, 303
