from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
import random, logging, qrcode, io, os, json, hashlib, re
from datetime import datetime, date, timedelta
from functools import wraps
from dotenv import load_dotenv # Ensure this is at the very top

# Load environment variables from .env file (for local development)
load_dotenv()

# For TOTP (Time-based One-Time Password)
import pyotp
import base64 # Used for encoding/decoding TOTP secrets

# Import the REAL BlockchainClient and production config
# These should be in separate files: blockchain_client.py and production_config.py
from blockchain_client import BlockchainClient
from production_config import get_production_config, validate_production_config, get_wallet_config

app = Flask(__name__)
# IMPORTANT: In a real production environment, app.secret_key MUST be a long,
# randomly generated string stored securely (e.g., in an environment variable).
app.secret_key = os.environ.get("SESSION_SECRET", "blackrock_terminal_secret_2025_DEFAULT_DO_NOT_USE_IN_PROD")
app.permanent_session_lifetime = timedelta(hours=8) # Sessions last for 8 hours

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Configuration ---
USERNAME = "ADMIN" # As specified by user
PASSWORD_FILE = "password.json" # Stores hashed password and TOTP secret
TOTP_ISSUER_NAME = "Black Rock Terminal"
INTERNAL_M0_M1_CARDS_FILE = "internal_m0_m1_cards.json" # Path to your internal M0/M1 cards JSON file

# --- Global variable to hold INTERNAL_M0_M1_CARDS data ---
# This will be loaded at startup. Balances are NOT tracked by this app.
INTERNAL_M0_M1_CARDS = {}

# --- Initialize the REAL BlockchainClient ---
# This will use the API keys and private keys loaded from production_config.py
blockchain_client = BlockchainClient()

# Validate production configuration on startup
if not validate_production_config(get_production_config()):
    logger.error("Production configuration validation failed. Please review production_config.py and environment variables.")
    # In a real app, you might want to exit or disable payout functionality here.

# User roles for access control (not fully implemented in this simplified version)
ROLES = {
    'ADMIN': 'admin',
    'OPERATOR': 'operator'
}

# --- Password and TOTP Management ---
def generate_password_hash(password):
    """Hashes a password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

def check_password_hash(hashed_password, raw_password):
    """Checks a raw password against a hashed password."""
    return generate_password_hash(raw_password) == hashed_password

def get_user_data():
    """Retrieves user data from the password.json file."""
    if not os.path.exists(PASSWORD_FILE):
        # Initialize with default admin if file doesn't exist
        with open(PASSWORD_FILE, "w") as f:
            json.dump({
                "username": USERNAME,
                "password_hash": generate_password_hash("Br_3339"),
                "totp_secret": None # No TOTP secret initially
            }, f, indent=2)
        logger.info(f"Initialized {PASSWORD_FILE} with default ADMIN user.")

    with open(PASSWORD_FILE, 'r') as f:
        return json.load(f)

def save_user_data(data):
    """Saves updated user data back to the password.json file."""
    with open(PASSWORD_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def login_required(f):
    """Decorator to enforce login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- TOTP Functions ---
def generate_totp_secret():
    """Generates a new TOTP secret and returns its base32 encoded version."""
    return pyotp.random_base32()

def get_totp_uri(secret, username):
    """Generates the TOTP provisioning URI for QR code generation."""
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name=TOTP_ISSUER_NAME
    )

def verify_totp(secret, otp_code):
    """Verifies a TOTP code against a secret."""
    totp = pyotp.TOTP(secret)
    return totp.verify(otp_code)

# --- Load INTERNAL_M0_M1_CARDS from JSON file (no balance logic) ---
def load_internal_m0_m1_cards():
    """Loads internal M0/M1 card data from a JSON file."""
    global INTERNAL_M0_M1_CARDS # Declare intent to modify the global variable
    if not os.path.exists(INTERNAL_M0_M1_CARDS_FILE):
        logger.error(f"Error: {INTERNAL_M0_M1_CARDS_FILE} not found. Internal M0/M1 card data will be empty.")
        INTERNAL_M0_M1_CARDS = {}
        return
    try:
        with open(INTERNAL_M0_M1_CARDS_FILE, 'r') as f:
            INTERNAL_M0_M1_CARDS = json.load(f)
            logger.info(f"Loaded {len(INTERNAL_M0_M1_CARDS)} internal M0/M1 cards from {INTERNAL_M0_M1_CARDS_FILE}.")
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding {INTERNAL_M0_M1_CARDS_FILE}: {e}")
        INTERNAL_M0_M1_CARDS = {}

# Load cards on app startup
load_internal_m0_m1_cards()

# --- In-memory Mock Database for Transactions (NO PERSISTENCE) ---
# This dictionary will store transaction data.
# This data WILL BE LOST when the application restarts (e.g., on Render redeploy).
MOCK_TRANSACTIONS_DB = {}

def generate_transaction_id():
    """Generates a unique transaction ID."""
    return f"TXN{datetime.now().strftime('%Y%m%d%H%M%S')}{random.randint(1000, 9999)}"

def get_transactions_collection_ref():
    """
    Returns a mock collection reference that interacts with the in-memory dictionary.
    This simulates a collection for transactions.
    """
    class MockDocumentRef:
        def __init__(self, doc_id):
            self.doc_id = doc_id

        def set(self, data):
            MOCK_TRANSACTIONS_DB[self.doc_id] = data
            logger.info(f"MOCK DB: Stored document {self.doc_id}")

        def get(self):
            class MockDocSnapshot:
                def __init__(self, exists, data):
                    self.exists = exists
                    self._data = data
                def to_dict(self):
                    return self._data
            data = MOCK_TRANSACTIONS_DB.get(self.doc_id)
            return MockDocSnapshot(data is not None, data)

    class MockCollectionRef:
        def document(self, doc_id):
            return MockDocumentRef(doc_id)

        def stream(self):
            # Simulate streaming by returning all values
            sorted_transactions = sorted(
                MOCK_TRANSACTIONS_DB.values(),
                key=lambda x: x.get('timestamp', ''),
                reverse=True
            )
            return sorted_transactions

        # Add mock methods for order_by and limit for compatibility with history screen
        def order_by(self, field, direction):
            return self # Chaining not fully implemented, just returns self

        def limit(self, count):
            return self # Chaining not fully implemented, just returns self

    return MockCollectionRef()

def add_transaction_to_mock_db(transaction_data):
    """Adds a new transaction record to the in-memory mock database."""
    get_transactions_collection_ref().document(transaction_data['transaction_id']).set(transaction_data)
    logger.info(f"Transaction {transaction_data['transaction_id']} added to MOCK DB.")

def get_transaction_details_from_mock_db(transaction_id):
    """Retrieves a single transaction's details from the in-memory mock database."""
    doc = get_transactions_collection_ref().document(transaction_id).get()
    if doc.exists:
        return doc.to_dict()
    return None

# --- PROTOCOLS and FIELD_39_RESPONSES (from your original app.py, moved here for clarity) ---
PROTOCOLS = {
    "POS Terminal -101.1 (4-digit approval)": 4,
    "POS Terminal -101.4 (6-digit approval)": 6,
    "POS Terminal -101.6 (Pre-authorization)": 6,
    "POS Terminal -101.7 (4-digit approval)": 4,
    "POS Terminal -101.8 (PIN-LESS transaction)": 4,
    "POS Terminal -201.1 (6-digit approval)": 6,
    "POS Terminal -201.3 (6-digit approval)": 6,
    "POS Terminal -201.5 (6-digit approval)": 6
}

FIELD_39_RESPONSES = {
    "05": "Do Not Honor",
    "14": "Terminal unable to resolve encrypted session state. Contact card issuer",
    "54": "Expired Card",
    "82": "Invalid CVV",
    "91": "Issuer Inoperative",
    "92": "Invalid Terminal Protocol",
    "99": "ISO Server Communication Error" # Custom code for socket errors
}


# --- Flask Routes ---

@app.before_request
def make_session_permanent():
    session.permanent = True

@app.route('/')
def index():
    """Root URL redirects to the consolidated transaction form if logged in, otherwise to login."""
    if session.get('logged_in'):
        # Pass the PROTOCOLS dictionary to the template
        return render_template('transaction_form.html', protocols=PROTOCOLS)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login authentication."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user_data = get_user_data()

        if username == user_data['username'] and check_password_hash(user_data['password_hash'], password):
            session['logged_in'] = True
            session['username'] = username
            session['login_time'] = datetime.now().isoformat()

            logger.info(f"User {username} logged in.")
            flash(f'Welcome, {username}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
            logger.warning(f"Failed login attempt for username: {username}")

    return render_template('login.html')

@app.route('/logout')
def logout():
    """Handles user logout, clearing the session."""
    username = session.get('username', 'Unknown')
    session.clear()
    flash(f'Goodbye, {username}!', 'info')
    logger.info(f"User {username} logged out")
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Allows authenticated user to change their password."""
    user_data = get_user_data()
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not check_password_hash(user_data['password_hash'], current_password):
            flash("Current password incorrect.", "error")
            return render_template('change_password.html')
        if new_password != confirm_password:
            flash("New password and confirmation do not match.", "error")
            return render_template('change_password.html')
        if len(new_password) < 8: # Example: enforce minimum password length
            flash("New password must be at least 8 characters long.", "error")
            return render_template('change_password.html')

        user_data['password_hash'] = generate_password_hash(new_password)
        save_user_data(user_data)
        flash("Password changed successfully!", "success")
        return redirect(url_for('index')) # Redirect to a main page after success
    return render_template('change_password.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    Handles the 'Forgot Password' flow.
    If a TOTP secret exists, it prompts for OTP.
    If no TOTP secret, it generates one and prompts for setup.
    """
    user_data = get_user_data()
    if request.method == 'POST':
        # This branch handles the submission after TOTP setup/verification
        if user_data.get('totp_secret'):
            # User is trying to verify OTP to reset password
            otp_code = request.form.get('otp_code')
            if verify_totp(user_data['totp_secret'], otp_code):
                session['totp_verified_for_reset'] = True # Mark session as verified
                flash("OTP verified. You can now reset your password.", "success")
                return redirect(url_for('reset_password'))
            else:
                flash("Invalid OTP. Please try again.", "error")
                return render_template('forgot_password.html', totp_setup_done=True)
        else:
            # User is trying to set up TOTP for the first time
            # This logic should ideally be in a separate admin setup route,
            # but for this flow, we'll allow it here.
            flash("TOTP not set up. Please set up TOTP first.", "error")
            return redirect(url_for('setup_totp'))

    # GET request: Check if TOTP is set up
    if user_data.get('totp_secret'):
        # TOTP is set up, prompt for OTP verification
        return render_template('forgot_password.html', totp_setup_done=True)
    else:
        # TOTP is not set up, prompt for setup
        return render_template('forgot_password.html', totp_setup_done=False)


@app.route('/setup_totp', methods=['GET', 'POST'])
def setup_totp():
    """
    Allows setting up TOTP for the admin user.
    Generates a secret and displays a QR code.
    """
    user_data = get_user_data()
    if user_data.get('totp_secret'):
        flash("TOTP is already set up. Use 'Forgot Password' to reset.", "info")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        # This branch is for verifying the OTP after scanning the QR code
        otp_code = request.form.get('otp_code')
        if verify_totp(session['temp_totp_secret'], otp_code):
            user_data['totp_secret'] = session['temp_totp_secret']
            save_user_data(user_data)
            session.pop('temp_totp_secret', None) # Clear temp secret
            flash("TOTP setup successful! You can now use it to reset your password.", "success")
            return redirect(url_for('login'))
        else:
            flash("Invalid OTP. Please try again.", "error")
            # Re-render the setup page with the same QR code
            totp_secret = session.get('temp_totp_secret')
            if totp_secret:
                totp_uri = get_totp_uri(totp_secret, USERNAME)
                qr_img = qrcode.make(totp_uri)
                buf = io.BytesIO()
                qr_img.save(buf, format="PNG")
                qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
                return render_template('setup_totp.html', qr_b64=qr_b64)
            else:
                flash("Error: TOTP secret missing. Please restart setup.", "error")
                return redirect(url_for('setup_totp'))

    # GET request: Generate new secret and QR code
    totp_secret = generate_totp_secret()
    session['temp_totp_secret'] = totp_secret # Store temporarily
    totp_uri = get_totp_uri(totp_secret, USERNAME)

    qr_img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return render_template('setup_totp.html', qr_b64=qr_b64)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """Allows resetting password after TOTP verification."""
    if not session.get('totp_verified_for_reset'):
        flash("Please verify OTP first via 'Forgot Password'.", "error")
        return redirect(url_for('forgot_password'))

    user_data = get_user_data()
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("New password and confirmation do not match.", "error")
            return render_template('reset_password.html')
        if len(new_password) < 8: # Example: enforce minimum password length
            flash("New password must be at least 8 characters long.", "error")
            return render_template('reset_password.html')

        user_data['password_hash'] = generate_password_hash(new_password)
        save_user_data(user_data)
        session.pop('totp_verified_for_reset', None) # Clear verification flag
        flash("Password reset successfully! Please log in with your new password.", "success")
        return redirect(url_for('login'))
    return render_template('reset_password.html')


# --- New Consolidated Transaction Processing Route ---
@app.route('/process_transaction', methods=['POST'])
@login_required
def process_transaction():
    """
    Handles the consolidated transaction form submission.
    Validates inputs against INTERNAL_M0_M1_CARDS, and triggers crypto payout.
    """
    # 1. Extract form data
    amount_str = request.form.get('amount', '').replace(',', '').strip()
    currency = request.form.get('currency')
    payout_method = request.form.get('payout_method')
    custom_wallet = request.form.get('custom_wallet', '').strip()
    pan = request.form.get('pan', '').replace(" ", "").replace("-", "")
    exp = request.form.get('expiry', '').replace("/", "")
    cvv = request.form.get('cvv')
    protocol = request.form.get('protocol')
    auth_code_entered = request.form.get('auth_code')

    # 2. Input Validations
    if not currency or currency not in ['USD', 'EUR']:
        flash("Please select a valid currency.", "error")
        return redirect(url_for('index')) # Redirect back to the form

    try:
        amount_float = float(amount_str)
        if amount_float <= 0:
            flash("Amount must be a positive number.", "error")
            return redirect(url_for('index'))
    except ValueError:
        flash('Please enter a valid amount.', 'error')
        return redirect(url_for('index'))

    # Determine the wallet address to use for payout
    wallet = ""
    if payout_method == 'ERC20':
        wallet = custom_wallet if custom_wallet else get_production_config()['DEFAULT_ERC20_WALLET']
        if not (wallet.startswith('0x') and len(wallet) == 42):
            flash('Invalid ERC-20 wallet address format.', 'error')
            return redirect(url_for('index'))
    elif payout_method == 'TRC20':
        wallet = custom_wallet if custom_wallet else get_production_config()['DEFAULT_TRC20_WALLET']
        if not (wallet.startswith('T') and len(wallet) >= 34): # TRC20 addresses vary in length, usually 34
            flash('Invalid TRC-20 wallet address format.', 'error')
            return redirect(url_for('index'))
    else:
        flash('Please select a payout method.', 'error')
        return redirect(url_for('index'))

    # Basic card number format validation (Luhn algorithm not implemented)
    def validate_card_number(card_num):
        return len(card_num) >= 13 and len(card_num) <= 19 and card_num.isdigit()

    if not validate_card_number(pan):
        flash('Invalid card number format.', 'error')
        return redirect(url_for('index'))

    if not re.match(r'^\d{4}$', exp):
        flash('Invalid expiry date format (MMYY).', 'error')
        return redirect(url_for('index'))

    if not re.match(r'^\d{3,4}$', cvv):
        flash('Invalid CVV format.', 'error')
        return redirect(url_for('index'))

    if protocol not in PROTOCOLS:
        flash('Invalid protocol selected.', 'error')
        return redirect(url_for('index'))

    expected_auth_length = PROTOCOLS[protocol]
    if len(auth_code_entered) != expected_auth_length or not auth_code_entered.isdigit():
        flash(f"Authorization code must be {expected_auth_length} digits and numeric.", "error")
        return redirect(url_for('index'))

    # Infer card type for receipt
    card_type = "UNKNOWN"
    if pan.startswith("4"):
        card_type = "VISA"
    elif pan.startswith("5"):
        card_type = "MASTERCARD"
    elif pan.startswith("3"):
        card_type = "AMEX"
    elif pan.startswith("6"):
        card_type = "DISCOVER"

    # Store necessary session data for receipt/history
    session['pan'] = pan
    session['amount'] = amount_str
    session['currency'] = currency
    session['payout_type'] = payout_method
    session['wallet'] = wallet
    session['protocol'] = protocol
    session['auth_code'] = auth_code_entered # Store entered auth code for potential later use
    session['card_type'] = card_type

    # 3. Internal M0/M1 Card Validation (against INTERNAL_M0_M1_CARDS)
    iso_response = {}
    transaction_status = "Declined"
    message = "Transaction declined by issuer."
    field39_resp = "05" # Default 'Do Not Honor'

    # Retrieve card data from the globally loaded INTERNAL_M0_M1_CARDS
    card_data = INTERNAL_M0_M1_CARDS.get(pan)

    if card_data:
        if exp != card_data['expiry']:
            message = FIELD_39_RESPONSES["54"]
            field39_resp = "54"
        elif cvv != card_data['cvv']:
            message = FIELD_39_RESPONSES["82"]
            field39_resp = "82"
        elif protocol != card_data['type']: # Check if protocol matches card's type
            message = FIELD_39_RESPONSES["92"]
            field39_resp = "92"
        elif auth_code_entered != card_data['auth']:
            message = FIELD_39_RESPONSES["05"] # Incorrect auth code
            field39_resp = "05"
        else:
            # All card details are valid. This is the "debiting" step (successful internal validation).
            transaction_status = "Approved"
            message = "Payment authorized."
            field39_resp = "00" # Approved
            iso_response['auth_code'] = card_data['auth'] # Use the auth code from card data
            logger.info(f"Internal M0/M1 Card {pan} successfully validated. Proceeding to payout.")

    else:
        # Card not found in our internal INTERNAL_M0_M1_CARDS list
        message = FIELD_39_RESPONSES["14"] # Terminal unable to resolve / Card not found
        field39_resp = "14"

    # Set final ISO response based on internal validation
    iso_response['status'] = transaction_status
    iso_response['message'] = message
    iso_response['field39'] = field39_resp

    # 4. Prepare Transaction Details for Mock DB
    current_transaction_details = {
        'transaction_id': generate_transaction_id(),
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'card_number': pan, # Store full PAN temporarily for receipt/history
        'amount': amount_float,
        'currency': currency,
        'protocol_type': protocol,
        'crypto_network_type': payout_method,
        'status': iso_response['status'],
        'auth_code_required': True if iso_response['status'] == 'Approved' else False, # Assume auth code always required if approved
        'payout_status': None,
        'crypto_payout_amount': 0.0,
        'simulated_gas_fee': 0.0,
        'crypto_address': wallet, # Store the actual wallet used
        'iso_field39': iso_response['field39'],
        'message': iso_response['message'],
        'auth_code': iso_response.get('auth_code') # Store the auth code returned by ISO (from card data)
    }

    # Store transaction in Mock In-Memory DB (NO PERSISTENCE)
    get_transactions_collection_ref().document(current_transaction_details['transaction_id']).set(current_transaction_details)
    logger.info(f"Mock DB: Stored initial transaction {current_transaction_details['transaction_id']}")


    # 5. Handle Redirection based on Internal Validation Response
    if iso_response['status'] == 'Approved':
        # Trigger real crypto payout immediately if internally approved
        recipient_wallet_info = get_wallet_config(current_transaction_details['crypto_network_type'])
        recipient_crypto_address = current_transaction_details['crypto_address'] # Use the wallet from form/default

        crypto_payout_result = blockchain_client.send_usdt(
            network=current_transaction_details['crypto_network_type'].lower(),
            to_address=recipient_crypto_address,
            amount_usd=current_transaction_details['amount']
        )

        current_transaction_details['crypto_payout_amount'] = crypto_payout_result.get('payout_amount_usdt', 0.0)
        current_transaction_details['simulated_gas_fee'] = crypto_payout_result.get('simulated_gas_fee_usdt', 0.0)
        current_transaction_details['payout_status'] = crypto_payout_result.get('status')
        current_transaction_details['blockchain_hash'] = crypto_payout_result.get('transaction_hash', 'N/A')
        current_transaction_details['message'] = crypto_payout_result.get('message', 'Payment and Crypto Payout Completed.')

        # Update overall transaction status based on payout
        if crypto_payout_result.get('status') == 'Success':
            current_transaction_details['status'] = 'Completed' # Final status if payout succeeded
            flash("Payment Approved and Payout Initiated!", "success")
        else:
            current_transaction_details['status'] = 'Payout Failed' # Final status if payout failed
            flash(f"Payment Approved, but Payout Failed: {current_transaction_details['message']}", "warning")

        # Update transaction in Mock DB after payout attempt
        get_transactions_collection_ref().document(current_transaction_details['transaction_id']).set(current_transaction_details)
        logger.info(f"Mock DB: Updated transaction {current_transaction_details['transaction_id']} after payout attempt.")

        return redirect(url_for('success_screen', transaction_id=current_transaction_details['transaction_id']))
    else:
        # Transaction declined by internal card check
        flash(f"Payment {iso_response['status']}: {iso_response['message']}", "error")
        return redirect(url_for('reject_screen', transaction_id=current_transaction_details['transaction_id']))


@app.route('/success_screen')
@login_required
def success_screen():
    """Renders the success screen with transaction details."""
    transaction_id = request.args.get('transaction_id')
    transaction = get_transaction_details_from_mock_db(transaction_id) # Use mock DB

    if not transaction:
        flash('Transaction details not found.', 'error')
        return redirect(url_for('index'))

    # Mask card number for display
    if 'card_number' in transaction and len(transaction['card_number']) > 4:
        transaction['card_number'] = transaction['card_number'][-4:]
    else:
        transaction['card_number'] = '' # Ensure it's not None if missing

    return render_template('success.html', transaction=transaction)

@app.route('/reject_screen')
@login_required
def reject_screen():
    """Renders the reject screen with transaction details."""
    transaction_id = request.args.get('transaction_id')
    transaction = get_transaction_details_from_mock_db(transaction_id) # Use mock DB

    if not transaction:
        flash('Transaction details not found.', 'error')
        return redirect(url_for('index'))

    # Mask card number for display
    if 'card_number' in transaction and len(transaction['card_number']) > 4:
        transaction['card_number'] = transaction['card_number'][-4:]
    else:
        transaction['card_number'] = '' # Ensure it's not None if missing

    return render_template('rejected.html', transaction=transaction)

@app.route("/receipt/<copy_type>") # Modified route to accept copy_type
@login_required
def receipt(copy_type):
    """Renders the receipt based on transaction ID from mock DB and copy type."""
    transaction_id = request.args.get('transaction_id')
    transaction = get_transaction_details_from_mock_db(transaction_id) # Use mock DB

    if not transaction:
        flash('Receipt details not found.', 'error')
        return redirect(url_for('index'))

    # Format amount for display
    amount_fmt = f"{transaction['amount']:,.2f}"

    # Extract protocol version and auth digits for display
    raw_protocol = transaction.get("protocol_type", "Unknown")
    match = re.search(r"-(\d+\.\d+)\s+\((\d+)-digit", raw_protocol)
    if match:
        protocol_version = match.group(1)
        auth_digits = int(match.group(2))
    else:
        protocol_version = "Unknown"
        auth_digits = 4 # Default if protocol name doesn't match pattern

    # Determine which template to render
    if copy_type == 'customer':
        template_name = "receipt_customer.html"
    elif copy_type == 'merchant':
        template_name = "receipt_merchant.html"
    else:
        flash("Invalid receipt copy type.", "error")
        return redirect(url_for('index'))

    return render_template(template_name,
        txn_id=transaction.get("transaction_id"),
        arn=transaction.get("blockchain_hash", "N/A"), # Using blockchain hash as ARN for crypto payouts
        pan=transaction.get("card_number", "")[-4:],
        amount=amount_fmt,
        payout=transaction.get("crypto_network_type"),
        wallet=transaction.get("crypto_address"),
        auth_code="*" * auth_digits,        # Masked auth code
        iso_field_18="5999",                # Default MCC
        iso_field_25="00",                  # POS condition
        field39=transaction.get("iso_field39"),
        card_type=session.get("card_type", "VISA"), # Use session card_type or derive from PAN if needed
        protocol_version=protocol_version,
        timestamp=transaction.get("timestamp")
    )


@app.route('/transaction_history')
@login_required
def transaction_history_screen():
    """Renders the transaction history screen."""
    transactions = []
    # Fetch all documents from the in-memory database
    mock_docs = get_transactions_collection_ref().stream()
    for txn in mock_docs:
        if 'timestamp' in txn:
            if isinstance(txn['timestamp'], str):
                pass
        # Mask card number for history display
        if 'card_number' in txn and len(txn['card_number']) > 4:
            txn['card_number_masked'] = "**** **** **** " + txn['card_number'][-4:]
        else:
            txn['card_number_masked'] = "N/A"
        transactions.append(txn)
    
    # Sort transactions by timestamp in reverse order (most recent first)
    transactions.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    logger.info(f"MOCK DB: Fetched and sorted {len(transactions)} transactions for history.")

    return render_template('transaction_history.html', transactions=transactions)


# --- Initialize application components (e.g., default user) ---
# This ensures the password.json file is created if it doesn't exist
# and the default ADMIN user is set up.
get_user_data()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False) # Set debug=True for development
