from flask import Flask, render_template, request, redirect, jsonify, session, url_for,flash
from werkzeug.utils import secure_filename
from datetime import datetime
from slugify import slugify
from models import db, Product, User, Order, OrderItem, StoreSettings, OTPVerification, MasterProduct, Offer
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date , timedelta
from functools import wraps
from collections import defaultdict
from PIL import Image
from dotenv import load_dotenv
import io
import csv
import json
import os
import re
import uuid
import qrcode
import random
import requests

# --------------------------------------------------------------------------------
# Flask App Setup
# --------------------------------------------------------------------------------

app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get("SECRET_KEY", "fallback-secret")
# MySQL Database configuration - 'hyperstore' naam ko restore kiya gaya hai
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# .env file load karo
load_dotenv()
TWOFACTOR_API_KEY = os.environ.get("TWOFACTOR_API_KEY")

OTP_EXPIRY_SECONDS = 2 * 60       # OTP valid for 5 minutes
OTP_RESEND_COOLDOWN = 60          # seconds before same number can request again
MAX_OTPS_PER_HOUR = 2             # basic throttle

# OTP storage (for a temporary check, in-memory)
otp_storage = {}

# Data Store Folders
UPLOAD_FOLDER = os.path.join('static', 'uploads')
OFFERS_FOLDER = os.path.join('static', 'offers')
QR_CODE_FOLDER = os.path.join('static', 'qr_codes')
MASTER_FOLDER = os.path.join('static','master_data')
os.makedirs(OFFERS_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QR_CODE_FOLDER, exist_ok=True)
os.makedirs(MASTER_FOLDER, exist_ok=True)
# Register in Flask config
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OFFERS_FOLDER'] = OFFERS_FOLDER
app.config['QR_CODE_FOLDER'] = QR_CODE_FOLDER
app.config['MASTER_FOLDER'] = MASTER_FOLDER
# --------------------------------------------------------------------------------
# Helper Functions
# --------------------------------------------------------------------------------

def generate_qr(data, filename=None):
    """
    QR code generate karta hai aur static/qr_codes folder mein save karta hai.
    Sahi relative path return karta hai jo database mein save hoga.
    """
    if not filename:
        filename = slugify(data) + "_qr.png"
    
    # Physical path jahan file save hogi
    filepath = os.path.join(QR_CODE_FOLDER, filename)
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    img = qrcode.make(data)
    img.save(filepath)
    
    # Relative path jo database aur url_for ke liye sahi hai
    return os.path.join("qr_codes", filename).replace("\\", "/")


def is_valid_phone(phone):
    if not phone.isdigit() or len(phone) != 10 or phone[0] not in '6789':
        return False
    blacklisted_numbers = {
        "9999999999", "8888888888", "7777777777",
        "0000000000", "1234567890"
    }
    if phone in blacklisted_numbers:
        return False
    return True

# Helper: verify OTP via 2factor.in
def verify_otp_2factor(session_id: str, otp_code: str):
    if not TWOFACTOR_API_KEY:
        return False, "OTP provider not configured"
    verify_url = f"https://2factor.in/API/V1/{TWOFACTOR_API_KEY}/SMS/VERIFY/{session_id}/{otp_code}"
    try:
        resp = requests.get(verify_url, timeout=10)
        data = resp.json()
    except Exception as e:
        return False, f"Network error: {e}"

    if data.get("Status") == "Success":
        return True, None
    else:
        return False, data.get("Details") or data.get("Message") or "Invalid OTP"
    
   # For Seller Registration  
def send_otp_2factor(phone: str, otp_code: str):
    """Send OTP via 2factor.in, return (ok:bool, details:str)."""
    if not TWOFACTOR_API_KEY:
        return False, "OTP provider not configured"
    url = f"https://2factor.in/API/V1/{TWOFACTOR_API_KEY}/SMS/{phone}/{otp_code}"
    try:
        resp = requests.get(url, timeout=10)
        data_text = resp.text
        # 2factor returns JSON-like text; check status robustly
        try:
            data = resp.json()
        except Exception:
            data = {}
        if resp.status_code == 200 and (data.get("Status") == "Success" or '"Status":"Success"' in data_text):
            return True, data.get("Details") or "Sent"
        else:
            # return provider message for debugging (not to user in prod)
            return False, data.get("Details") or data.get("Message") or data_text
    except Exception as e:
        return False, str(e)
    # For Forgot Password 
def send_otp_autogen(phone: str):
    """
    Request 2factor.in to generate & send OTP to `phone`.
    Returns (True, session_id) on success, else (False, error_message).
    """
    if not TWOFACTOR_API_KEY:
        return False, "OTP provider not configured"

    otp_url = f"https://2factor.in/API/V1/{TWOFACTOR_API_KEY}/SMS/{phone}/AUTOGEN"
    try:
        resp = requests.get(otp_url, timeout=10)
        data = resp.json()
    except Exception as e:
        return False, f"Network error: {e}"

    if data.get("Status") == "Success":
        return True, data.get("Details")   # Details = session_id
    else:
        return False, data.get("Details") or data.get("Message") or "Failed to send OTP"
    
# For Admin Login 
def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))  # admin_login route ka naam
        return f(*args, **kwargs)
    return decorated_function

# Image 
ALLOWED_EXTS = {'.png', '.jpg', '.jpeg', '.webp', '.gif'}
ALLOWED_MIMES = {'image/png', 'image/jpeg', 'image/webp', 'image/gif'}

def is_allowed_image(file_storage):
    # Extension check
    _, ext = os.path.splitext(file_storage.filename.lower())
    if ext not in ALLOWED_EXTS:
        return False, "Only image files are allowed (png, jpg, jpeg, webp, gif)."

    # Mimetype check (best-effort)
    if file_storage.mimetype not in ALLOWED_MIMES:
        return False, "Uploaded file is not a valid image type."

    # Content check (ensure it actually opens as an image)
    try:
        img = Image.open(file_storage.stream)
        img.verify()  # quick integrity check
        file_storage.stream.seek(0)  # reset pointer after verify
    except Exception:
        return False, "Corrupted or invalid image file."

    return True, None

# helper to parse YYYY-MM-DD
def parse_date(s):
    if not s:
        return None
    try:
        return datetime.strptime(s, '%Y-%m-%d').date()
    except ValueError:
        return None
# --------------------------------------------------------------------------------
# Flask Routes
# --------------------------------------------------------------------------------

# Home Page Route 
@app.route("/")
def home():
    return render_template("Home.html")  # keep exact filename
# ---- Admin Login ----
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        # Env se credentials load karo
        admin_user = os.environ.get("ADMIN_USERNAME")
        admin_pass = os.environ.get("ADMIN_PASSWORD")

        if username == admin_user and password == admin_pass:
            session['admin_logged_in'] = True
            flash("Welcome Admin!", "success")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid admin credentials", "danger")

    return render_template('admin_login.html')
# admin logout route
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

# ---- Admin Dashboard ----
@app.route('/admin/dashboard')
@admin_login_required
def admin_dashboard():
    # Top cards
    total_sellers = db.session.query(func.count(User.id)).scalar()
    total_orders = db.session.query(func.count(Order.id)).scalar()
    total_master_products = db.session.query(func.count(MasterProduct.id)).scalar()

    # Today metrics
    today = date.today()
    orders_today = (db.session.query(func.count(Order.id))
                    .filter(func.date(Order.created_at) == today).scalar())
    sellers_today = (db.session.query(func.count(User.id))
                     .filter(func.date(User.registered_at) == today).scalar())

    # Recent tables (last 10)
    recent_sellers = (User.query.order_by(User.registered_at.desc()).limit(10).all())
    recent_orders = (db.session.query(Order, User.store_name)
                     .join(User, Order.seller_id == User.id)
                     .order_by(Order.created_at.desc())
                     .limit(10).all())

    return render_template('admin_dashboard.html',
                           total_sellers=total_sellers,
                           total_orders=total_orders,
                           total_master_products=total_master_products,
                           orders_today=orders_today,
                           sellers_today=sellers_today,
                           recent_sellers=recent_sellers,
                           recent_orders=recent_orders)

# admin seller management route 
@app.route('/admin/sellers')
@admin_login_required
def admin_sellers():
    # search q, page & per_page
    q = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 25, type=int)

    query = User.query

    if q:
        like = f"%{q.lower()}%"
        # search by store_name or phone or owner_name (case-insensitive)
        query = query.filter(
            func.lower(User.store_name).like(like) |
            func.lower(User.phone).like(like) |
            func.lower(func.coalesce(User.owner_name, '')).like(like)
        )

    paginated = query.order_by(User.registered_at.desc()).paginate(page=page, per_page=per_page, error_out=False)

    return render_template('admin_sellers.html',
                           sellers=paginated.items,
                           pagination=paginated,
                           q=q,
                           per_page=per_page)


@app.route('/admin/sellers/<int:seller_id>')
@admin_login_required
def admin_view_seller(seller_id):
    seller = User.query.get_or_404(seller_id)
    # eager load products and orders count for display if needed
    products = seller.products  # lazy='select' in models
    orders_count = Order.query.filter_by(seller_id=seller.id).count()
    return render_template('admin_view_seller.html', seller=seller, products=products, orders_count=orders_count)


@app.route('/admin/sellers/<int:seller_id>/edit', methods=['GET', 'POST'])
@admin_login_required
def admin_edit_seller(seller_id):
    seller = User.query.get_or_404(seller_id)
    if request.method == 'POST':
        # basic server-side validation
        store_name = request.form.get('store_name', '').strip()
        owner_name = request.form.get('owner_name', '').strip()
        phone = request.form.get('phone', '').strip()
        address = request.form.get('address', '').strip()
        category = request.form.get('category', '').strip()

        if not store_name:
            flash('Store name is required.', 'danger')
            return redirect(request.url)

        # check phone uniqueness (if changed)
        if phone and phone != seller.phone:
            existing = User.query.filter(User.phone == phone).first()
            if existing:
                flash('Phone number already used by another seller.', 'danger')
                return redirect(request.url)
            # optionally validate digits and length
            if not phone.isdigit() or len(phone) != 10:
                flash('Phone must be 10 digits.', 'danger')
                return redirect(request.url)

        seller.store_name = store_name
        seller.owner_name = owner_name or None
        seller.phone = phone or seller.phone
        seller.address = address or None
        seller.category = category or None

        try:
            db.session.commit()
            flash('Seller updated successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.exception('Error updating seller')
            flash('Error while updating seller.', 'danger')

        return redirect(url_for('admin_sellers'))

    # GET -> render edit form
    return render_template('admin_edit_seller.html', seller=seller)


@app.route('/admin/sellers/<int:seller_id>/delete', methods=['POST'])
@admin_login_required
def admin_delete_seller(seller_id):
    # destructive action must be POST + CSRF
    seller = User.query.get_or_404(seller_id)

    # optional safety: prevent deleting if seller has active orders
    active_orders = Order.query.filter(Order.seller_id == seller.id, Order.status != 'Delivered', Order.status != 'Cancelled').count()
    if active_orders > 0:
        flash('Cannot delete seller with active/pending orders. Cancel or complete orders first.', 'warning')
        return redirect(url_for('admin_sellers'))

    try:
        db.session.delete(seller)
        db.session.commit()
        # log audit if you use AdminAudit model
        # db.session.add(AdminAudit(admin_username=session.get('admin_username'), action='delete_seller', details=f'deleted seller_id={seller_id}'))
        # db.session.commit()
        flash('Seller deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Error deleting seller')
        flash('Error while deleting seller.', 'danger')

    return redirect(url_for('admin_sellers'))
# admin order management route 
@app.route('/admin/orders')
@admin_login_required
def admin_orders():
    # filters from querystring
    status = request.args.get('status', '').strip()
    store = request.args.get('store', '').strip()
    cleared = request.args.get('cleared', '').strip()  # 'yes'/'no'/''
    date_from = parse_date(request.args.get('from', '').strip())
    date_to = parse_date(request.args.get('to', '').strip())

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 25, type=int)

    q = db.session.query(Order, User.store_name).join(User, Order.seller_id == User.id)

    if status:
        q = q.filter(Order.status == status)
    if store:
        q = q.filter(func.lower(User.store_name) == store.lower())
    if cleared == 'yes':
        q = q.filter(Order.is_cleared_by_seller.is_(True))
    elif cleared == 'no':
        q = q.filter(Order.is_cleared_by_seller.is_(False))
    if date_from:
        q = q.filter(func.date(Order.created_at) >= date_from)
    if date_to:
        q = q.filter(func.date(Order.created_at) <= date_to)

    paginated = q.order_by(Order.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)

    # gather distinct statuses for filter dropdown
    statuses = [r[0] for r in db.session.query(Order.status).distinct().all()]
    return render_template('admin_orders.html',
                           orders=paginated.items,
                           pagination=paginated,
                           statuses=statuses,
                           filters={'status': status, 'store': store, 'cleared': cleared, 'from': request.args.get('from',''), 'to': request.args.get('to','')},
                           per_page=per_page)


@app.route('/admin/orders/<int:order_id>')
@admin_login_required
def admin_view_order(order_id):
    order = Order.query.get_or_404(order_id)
    seller = User.query.get(order.seller_id)
    items = order.items  # order.order_items
    return render_template('admin_order_view.html', order=order, seller=seller, items=items)


@app.route('/admin/orders/<int:order_id>/status', methods=['POST'])
@admin_login_required
def admin_update_order_status(order_id):
    new_status = request.form.get('status', '').strip()
    order = Order.query.get_or_404(order_id)
    if new_status:
        order.status = new_status
        # optionally auto-mark cleared_by_seller when Delivered
        if new_status.lower() == 'delivered':
            order.is_cleared_by_seller = True
        try:
            db.session.commit()
            flash('Order status updated', 'success')
        except Exception:
            db.session.rollback()
            flash('Error updating order status', 'danger')
    return redirect(url_for('admin_view_order', order_id=order_id))


@app.route('/admin/orders/<int:order_id>/delete', methods=['POST'])
@admin_login_required
def admin_delete_order(order_id):
    order = Order.query.get_or_404(order_id)
    try:
        db.session.delete(order)
        db.session.commit()
        flash('Order deleted', 'success')
    except Exception:
        db.session.rollback()
        flash('Error deleting order', 'danger')
    return redirect(url_for('admin_orders'))
# -----------------------------------------
# Admin: Master Products CRUD
# -----------------------------------------
@app.route('/admin/master-products', methods=['GET', 'POST'])
@admin_login_required
def admin_master_products():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        category = request.form.get('category', '').strip()
        unit = request.form.get('unit', '').strip()
        image_url = request.form.get('image_url', '').strip()  # ya file upload path

        if name and category:
            # avoid duplicates
            existing = MasterProduct.query.filter_by(name=name).first()
            if existing:
                flash('Product already exists!', 'warning')
            else:
                mp = MasterProduct(
                    name=name,
                    category=category,
                    unit=unit or None,
                    image_url=image_url or None
                )
                db.session.add(mp)
                db.session.commit()
                flash('Master product added', 'success')

        return redirect(url_for('admin_master_products'))

    mps = MasterProduct.query.order_by(MasterProduct.name.asc()).all()
    return render_template('admin_master_products.html', master_products=mps)


# -----------------------------------------
# Admin: Delete Master Product
# -----------------------------------------
@app.route('/admin/master-products/<int:mp_id>/delete', methods=['POST'])
@admin_login_required
def admin_delete_master_product(mp_id):
    mp = MasterProduct.query.get_or_404(mp_id)
    db.session.delete(mp)
    db.session.commit()
    flash('Master product deleted', 'success')
    return redirect(url_for('admin_master_products'))


# -----------------------------------------
# Admin: Import Master Products from CSV
# -----------------------------------------
@app.route('/admin/import_master_products', methods=['GET', 'POST'])
@admin_login_required
def admin_import_master_products():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        if file and file.filename.endswith('.csv'):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['MASTER_FOLDER'], filename)
            file.save(filepath)

            try:
                with open(filepath, newline='', encoding='utf-8-sig') as csvfile:
                    reader = csv.DictReader(csvfile)
                    required_fields = ['Product', 'Brands', 'Unit', 'Image URL']

                    # Validate headers
                    if not all(field in reader.fieldnames for field in required_fields):
                        flash(f'CSV file missing required columns. Found: {reader.fieldnames}', 'danger')
                        return redirect(request.url)

                    imported, skipped = 0, 0
                    for row in reader:
                        product_name = row['Product'].strip()
                        brand = row['Brands'].strip()
                        unit = row['Unit'].strip()
                        image_url = row['Image URL'].strip()

                        if not product_name:
                            skipped += 1
                            continue  # skip blank rows

                        # Avoid duplicates
                        existing = MasterProduct.query.filter_by(name=product_name).first()
                        if not existing:
                            mp = MasterProduct(
                                name=product_name,
                                category=brand,   # treat Brands as Category
                                unit=unit,
                                image_url=image_url or None
                            )
                            db.session.add(mp)
                            imported += 1
                        else:
                            skipped += 1

                    db.session.commit()
                    flash(f'{imported} products imported, {skipped} skipped (duplicates/blank).', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Error while importing: {str(e)}', 'danger')

            return redirect(url_for('admin_master_products'))
        else:
            flash('Invalid file format. Please upload a CSV.', 'danger')
            return redirect(request.url)

    return render_template('admin_import_master_products.html')

# Registration seller route
@app.route('/register', methods=['GET', 'POST'])
def register_store():
    if request.method == 'POST':
        try:
            if request.form.get("otp_verified") != "true":
                return "Phone number not verified. Please verify OTP before registering."
            
            store_name = (request.form.get("store_name") or "").strip()
            owner_name = (request.form.get("owner_name") or "").strip()
            phone = (request.form.get("phone") or "").strip()
            store_address = (request.form.get("store_address") or "").strip()
            store_category = request.form.get("store_category")
            password = request.form.get("password")
            confirm_password = request.form.get("confirm_password")

            if password != confirm_password:
                return "Passwords do not match."

            if not is_valid_phone(phone):
                return "Invalid phone number. Enter a valid 10-digit Indian mobile number."

            if User.query.filter_by(phone=phone).first():
                return "A store with this phone number already exists."

            base_slug = slugify(store_name)
            slug = base_slug
            counter = 1
            while User.query.filter_by(slug=slug).first():
                slug = f"{base_slug}-{counter}"
                counter += 1

            store_url = url_for('store_home', slug=slug, _external=True)
            qr_filename = f"{slug}_qr.png"
            qr_code_path = generate_qr(store_url, filename=qr_filename)

            hashed_password = generate_password_hash(password)
            new_user = User(
                store_name=store_name,
                owner_name=owner_name,
                phone=phone,
                password=hashed_password,
                slug=slug,
                address=store_address,
                category=store_category,
                qr_code_path=qr_code_path
            )

            db.session.add(new_user)
            db.session.commit()

            store_settings = StoreSettings(seller_id=new_user.id, is_open=True, upi_id="")
            db.session.add(store_settings)
            db.session.commit()

            session['seller_id'] = new_user.id
            session['store_name'] = new_user.store_name

            return redirect('/dashboard')
        except Exception as e:
            db.session.rollback()
            return f"Registration failed: {str(e)}"
    return render_template("register.html")

# Login Seller route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        try:
            user = User.query.filter_by(phone=phone).first()
            if user and check_password_hash(user.password, password):
                session['seller_id'] = user.id
                session['store_name'] = user.store_name
                return redirect('/dashboard')
            else:
                error = "Invalid phone number or password."
                return render_template('login.html', error=error)
        except SQLAlchemyError as e:
            error = "Database error occurred. Please try again."
            print(f"Database Error: {str(e)}")
            return render_template('login.html', error=error)
    return render_template('login.html')

# ---- Forgot password route (uses helper) ----
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        phone_raw = request.form.get('phone', '').strip()
        # normalize phone: remove spaces, dashes
        phone = re.sub(r'\D', '', phone_raw)

        # if phone is 10 digits, consider adding country code (2factor often expects 91XXXXXXXXXX)
        if len(phone) == 10:
            phone_to_use = '91' + phone
        else:
            phone_to_use = phone  # assume user gave full international format

        app.logger.info(f"[forgot_password] requested for phone_raw={phone_raw} normalized={phone_to_use}")

        # Check seller exists - try both formats: stored with or without country code
        seller = User.query.filter_by(phone=phone).first()
        if not seller:
            seller = User.query.filter_by(phone=phone_to_use).first()

        if not seller:
            app.logger.warning(f"[forgot_password] No seller found for {phone_raw}")
            flash("No account found with this phone number.", "warning")
            return render_template('forgot_password.html')

        # send OTP using AUTOGEN helper
        ok, result = send_otp_autogen(phone_to_use)
        app.logger.info(f"[forgot_password] send_otp_autogen result for {phone_to_use}: ok={ok} result={result}")

        if ok:
            session['reset_phone'] = phone_to_use
            session['reset_session_id'] = result
            session['reset_otp_attempts'] = 0
            flash("OTP sent to your phone. Enter the code to reset password.", "success")
            return redirect(url_for('verify_reset_otp'))
        else:
            # show provider error in logs; user sees friendly message
            app.logger.error(f"[forgot_password] OTP send failed: {result}")
            flash("Error sending OTP. Please try again after some time.", "danger")
            return render_template('forgot_password.html')

    return render_template('forgot_password.html')

# ---- Verify reset OTP route ----
@app.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    # Ensure flow started
    if 'reset_phone' not in session or 'reset_session_id' not in session:
        flash("Please start the password reset process first.", "warning")
        return redirect(url_for('forgot_password'))

    # Initialize attempts if absent
    attempts = session.get('reset_otp_attempts', 0)
    MAX_ATTEMPTS = 5

    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        if not otp:
            flash("Please enter the OTP.", "danger")
            return render_template('verify_reset_otp.html')

        # limit attempts
        if attempts >= MAX_ATTEMPTS:
            # too many attempts — clear session and ask to restart
            session.pop('reset_session_id', None)
            session.pop('reset_phone', None)
            session.pop('reset_otp_attempts', None)
            flash("Too many incorrect OTP attempts. Please request a new OTP.", "danger")
            return redirect(url_for('forgot_password'))

        session_id = session.get('reset_session_id')
        ok, err = verify_otp_2factor(session_id, otp)
        if ok:
            # OTP verified — allow user to reset password
            # Keep reset_phone in session so reset_password route knows which user
            flash("OTP verified. You can now set a new password.", "success")
            return redirect(url_for('reset_password'))
        else:
            # increment attempts
            attempts += 1
            session['reset_otp_attempts'] = attempts
            remaining = MAX_ATTEMPTS - attempts
            flash(f"Invalid OTP. {remaining} attempts remaining.", "danger")
            return render_template('verify_reset_otp.html')

    return render_template('verify_reset_otp.html')

# reset Password route
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_phone' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            return "Passwords do not match."

        # Password hash karo (security ke liye)
        from werkzeug.security import generate_password_hash
        hashed_password = generate_password_hash(new_password)

        # DB me update karo
        seller = User.query.filter_by(phone=session['reset_phone']).first()
        if seller:
            seller.password = hashed_password
            db.session.commit()

            # Session clear
            session.pop('reset_phone', None)
            session.pop('reset_session_id', None)

            return redirect(url_for('login'))

        return "User not found."

    return render_template('reset_password.html')

# Seller Dashboard Route
@app.route('/dashboard')
def dashboard():
    if 'seller_id' not in session:
        return redirect('/login')
    user = User.query.get(session['seller_id'])
    if not user:
        return redirect('/logout')
    session['store_name'] = user.store_name
    
    # Ab offer database se fetch ho raha hai
    offer = Offer.query.filter_by(seller_id=user.id).first()

    qr_code = None
    if user.qr_code_path:
        qr_code = url_for('static', filename=user.qr_code_path)
    
    settings = StoreSettings.query.filter_by(seller_id=user.id).first()
    store_status = "open" if not settings or settings.is_open else "closed"
    
    return render_template(
        'dashboard.html',
        user=user,
        qr_code=qr_code,
        store_status=store_status,
        offer=offer
    )

# Seller ADD offer route 
@app.route('/add_offer', methods=['POST'])
def add_offer():
    if 'seller_id' not in session:
        return redirect('/login')

    seller_id = session.get('seller_id')
    seller = User.query.get(seller_id)
    if not seller:
        return "Store not found", 404

    # Remove any existing offer (and its image)
    existing_offer = Offer.query.filter_by(seller_id=seller.id).first()
    if existing_offer:
        if existing_offer.image_path:
            old_image_path = os.path.join(app.static_folder, existing_offer.image_path)
            if os.path.exists(old_image_path):
                try:
                    os.remove(old_image_path)
                except Exception:
                    pass
        db.session.delete(existing_offer)
        db.session.commit()

    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()
    image = request.files.get('image')

    if not title:
        flash("Title is required.", "danger")
        return redirect(url_for('dashboard'))

    if not image or image.filename == '':
        flash("Please choose an image.", "danger")
        return redirect(url_for('dashboard'))

    ok, err = is_allowed_image(image)
    if not ok:
        flash(err, "danger")
        return redirect(url_for('dashboard'))

    # Ensure offers folder exists
    os.makedirs(OFFERS_FOLDER, exist_ok=True)

    # Keep safe filename with UUID prefix
    _, ext = os.path.splitext(image.filename)
    filename = f"{uuid.uuid4().hex}_{secure_filename(os.path.splitext(image.filename)[0])}{ext.lower()}"
    save_path = os.path.join(OFFERS_FOLDER, filename)

    try:
        image.save(save_path)
    except Exception as e:
        flash(f"Failed to save image: {e}", "danger")
        return redirect(url_for('dashboard'))

    image_path = os.path.join('offers', filename).replace("\\", "/")

    # Save new offer
    offer = Offer(
        seller_id=seller.id,
        title=title,
        description=description or None,
        image_path=image_path
    )
    db.session.add(offer)
    db.session.commit()

    flash("Offer updated successfully.", "success")
    return redirect(url_for('dashboard'))

# Delete Offer Route
@app.route('/delete_offer', methods=['POST'])
def delete_offer():
    if 'seller_id' not in session:
        return redirect('/login')

    seller_id = session.get('seller_id')
    offer = Offer.query.filter_by(seller_id=seller_id).first()

    if offer:
        try:
            if offer.image_path:
                image_full_path = os.path.join(app.static_folder, offer.image_path)
                if os.path.exists(image_full_path):
                    os.remove(image_full_path)
            db.session.delete(offer)
            db.session.commit()
            flash("Offer deleted.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error deleting offer: {e}", "danger")

    return redirect(url_for('dashboard'))
# Master product route in seller dashboard  
@app.route('/dashboard/master-products', methods=['GET', 'POST'])
def master_products():
    if 'seller_id' not in session:
        return redirect(url_for('login'))

    seller_id = session['seller_id']
    master_products = MasterProduct.query.all()

    if request.method == 'POST':
        selected_ids = request.form.getlist('product_ids')

        for mp_id in selected_ids:
            mp = MasterProduct.query.get(mp_id)
            if not mp:
                continue  # Skip if master product not found

            price_str = request.form.get(f'price_{mp_id}', '').strip()
            qty_str = request.form.get(f'qty_{mp_id}', '').strip()
            unit = request.form.get(f'unit_{mp_id}', '').strip()

            # Validate numeric inputs
            try:
                price = float(price_str)
                qty = int(qty_str)
            except ValueError:
                continue  # Skip if invalid number

            # Check if product already exists for this seller
            existing = Product.query.filter_by(
                seller_id=seller_id,
                product_name=mp.name
            ).first()

            if not existing:
                new_product = Product(
                    seller_id=seller_id,
                    product_name=mp.name,
                    price=price,
                    quantity=qty,
                    unit=unit,
                    image_url=mp.image_url
                )
                db.session.add(new_product)

        db.session.commit()
        return redirect(url_for('my_products'))

    return render_template(
        'master_products.html',
        master_products=master_products
    )

# ADD product route
@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if 'seller_id' not in session:
        return redirect('/login')
    
    if request.method == 'POST':
        product_name = request.form.get('product_name')
        price = request.form.get('price')
        quantity = request.form.get('quantity')
        unit = request.form.get('unit')  # New line for unit
        image_file = request.files['image']

        if not product_name or not price or not quantity or not unit or not image_file:
            return "Please fill all fields and upload an image."

        filename = f"{uuid.uuid4().hex}_{secure_filename(image_file.filename)}"
        image_path = os.path.join(UPLOAD_FOLDER, filename)
        image_file.save(image_path)
        image_url = f"uploads/{filename}"

        try:
            new_product = Product(
                seller_id=session['seller_id'],
                product_name=product_name,
                price=float(price),
                quantity=int(quantity),
                unit=unit,  # Store unit
                image_url=image_url
            )
            db.session.add(new_product)
            db.session.commit()
            return redirect('/my_products')
        except SQLAlchemyError as e:
            db.session.rollback()
            return f"Database error: {str(e)}"
    
    return render_template('add_product.html')

# my Product Ruote for sellers
@app.route('/my_products')
def my_products():
    if 'seller_id' not in session:
        return redirect('/login')
    seller = User.query.get(session['seller_id'])
    if not seller:
        return "Seller not found"
    seller_products = Product.query.filter_by(seller_id=seller.id).all()
    return render_template('my_products.html', products=seller_products)

# delete poduct route 
@app.route('/delete_product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    # product find karo
    product = Product.query.get_or_404(product_id)

    # delete karo
    db.session.delete(product)
    db.session.commit()

    flash('Product deleted successfully!', 'success')
    return redirect(url_for('my_products'))

# Edit product info route in my product
@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)

    if request.method == 'POST':
        # Only update price and unit
        product.price = request.form.get('price')
        product.unit = request.form.get('unit')

        db.session.commit()
        return redirect(url_for('my_products'))

    return render_template('edit_product.html', product=product)

# Store open/close Status
@app.route('/update_store_status', methods=['POST'])
def update_store_status():
    if 'seller_id' not in session:
        return redirect('/login')
    seller_id = session['seller_id']
    new_status = request.form.get('status')
    user = User.query.get(seller_id)
    if not user:
        return redirect('/logout')
    settings = StoreSettings.query.filter_by(seller_id=user.id).first()
    if not settings:
        settings = StoreSettings(seller_id=user.id)
    settings.is_open = True if new_status == "open" else False
    db.session.add(settings)
    db.session.commit()
    return redirect('/dashboard')

# Track Order Status route for Customer 
@app.route('/track_order/<int:order_id>')
def track_order(order_id):
    order = Order.query.get(order_id)
    if not order:
        return "Order not found", 404
    return render_template("track_order.html", order=order)

#DashBoard View_order Seller
@app.route("/dashboard/orders")
def view_orders():
    if "seller_id" not in session:
        return redirect(url_for("seller_login"))

    seller_id = session["seller_id"]
    orders = Order.query.filter(
        Order.seller_id == seller_id,
        Order.status.in_(["Pending", "Accepted", "Out for Delivery"])
    ).order_by(Order.created_at.desc()).all()

    seller = User.query.get(seller_id)
    return render_template("dashboard_orders.html", orders=orders, store_name=seller.store_name)
# Customer Order Page Route
@app.route('/store/<slug>')
def store_home(slug):
    # Find seller by slug (unique URL friendly field)
    seller = User.query.filter_by(slug=slug).first()

    if not seller:
        return "Store not found", 404

    # Fetch store settings (open/close)
    settings = StoreSettings.query.filter_by(seller_id=seller.id).first()
    store_status = "open" if not settings or settings.is_open else "closed"

    # Get search query from URL
    search_query = request.args.get("q", "").strip()

    # Base query for products
    products_query = Product.query.filter_by(seller_id=seller.id)

    # If search query exists, filter products
    if search_query:
        products_query = products_query.filter(
            func.lower(Product.product_name).like(f"%{search_query.lower()}%")
        )

    products = products_query.all()

    # Fetch offer from DB
    offer = Offer.query.filter_by(seller_id=seller.id).first()

    # If no products and store is closed
    if not products and store_status == "closed":
        return "This store is currently closed."

    return render_template(
        "store_home.html",
        store_name=seller.store_name,  # yaha seller.store_name show karna hai
        slug=seller.slug,
        products=products,
        store_status=store_status,
        offer=offer,
        search_query=search_query
    )

# Submit Order route Customer 
# Submit Order route Customer 
@app.route('/submit_order', methods=['POST'])
def submit_order():
    slug = request.form.get("slug")   # ✅ ab slug le rahe hai
    phone = request.form.get("phone")
    delivery_type = request.form.get("delivery_type")
    address = request.form.get("address", "").strip()
    items_json = request.form.get("items_json")
    total_price = float(request.form.get("total_price", 0))

    # Seller by slug ✅
    seller = User.query.filter_by(slug=slug).first()
    if not seller:
        return "Store not found", 404

    # fake numbers validation
    fake_numbers = ["1234567890","9999999999","8888888888","7777777777",
                    "6666666666","5555555555","4444444444","3333333333",
                    "2222222222","1111111111","0000000000"]
    if phone in fake_numbers:
        return "Invalid phone number", 400
    if delivery_type == "delivery" and len(address) < 5:
        return "Invalid address", 400

    try:
        items = json.loads(items_json)
    except:
        return "Invalid items", 400

    base_total = 0
    order_items = []
    for item in items:
        name = item.get("name")
        quantity = int(item.get("quantity", 1))
        price = float(item.get("price", 0))
        subtotal = quantity * price
        base_total += subtotal
        order_items.append({"name": name, "quantity": quantity, "price": price})

    # delivery charge rules
    delivery_charge = 0
    if delivery_type == "delivery":
        if base_total < 100:
            return "Delivery not allowed under ₹100", 400
        elif base_total < 500:
            delivery_charge = round(base_total * 0.10)
        else:
            delivery_charge = round(base_total * 0.05)

    final_total = base_total + delivery_charge

    # Save Order
    new_order = Order(
        seller_id=seller.id,
        customer_phone=phone,
        customer_address=address if delivery_type == "delivery" else "",
        delivery_mode=delivery_type,
        delivery_charge=delivery_charge,
        total_amount=final_total,
        status='Pending',
        created_at=datetime.utcnow()
    )
    db.session.add(new_order)
    db.session.commit()

    # Save Order Items
    for item in order_items:
        order_item = OrderItem(
            order_id=new_order.id,
            product_name=item['name'],
            quantity=item['quantity'],
            unit_price=item['price']
        )
        db.session.add(order_item)
    db.session.commit()

    return render_template("thank_you.html", store_name=seller.store_name, order_id=new_order.id)

# Global dictionary
# Notification Route For Seller 
last_checked = {}

@app.route('/check_new_orders')
def check_new_orders():
    seller_id = session.get('seller_id')
    if not seller_id:
        return jsonify({'new_order': False})

    # Seller 
    recent_order = Order.query.filter_by(seller_id=seller_id).order_by(Order.created_at.desc()).first()

    if not recent_order:
        return jsonify({'new_order': False})

    # Seller ka last check time lo
    last_time = last_checked.get(seller_id)

   
    if not last_time:
        last_checked[seller_id] = recent_order.created_at
        return jsonify({'new_order': False})

    if recent_order.created_at > last_time:
        last_checked[seller_id] = recent_order.created_at
        return jsonify({'new_order': True})

    return jsonify({'new_order': False})

# Separate: Route for showing order summary for Customer 
@app.route('/your_order', methods=['GET'])
def your_order():
    phone = request.args.get('phone')
    store_name = request.args.get('store_name')
    if not phone or not store_name:
        return "Missing phone/store", 400
    seller = db.session.query(User).filter(func.lower(User.store_name) == store_name.lower()).first()
    if not seller:
        return "Store not found", 404
    order = Order.query.filter_by(seller_id=seller.id, customer_phone=phone).order_by(Order.created_at.desc()).first()
    if not order:
        return "No order found", 404
    items = OrderItem.query.filter_by(order_id=order.id).all()
    item_list = [{'name': item.product_name, 'quantity': item.quantity, 'price': item.unit_price, 'subtotal': item.quantity * item.unit_price} for item in items]
    return render_template('your_order.html', store_name=store_name, items=item_list, total=order.total_amount)

# Customer Order route
@app.route('/order_review', methods=['POST'])
def order_review():
    slug = request.form.get("slug")  # ✅ ab slug le rahe hai
    items_json = request.form.get("items_json")
    try:
        items = json.loads(items_json)
    except Exception as e:
        print("Item JSON Error:", e)
        items = []
    item_list = []
    total = 0
    for item in items:
        name = item.get("name", "")
        quantity = int(item.get("quantity", 1))
        price = float(item.get("price", 0))
        subtotal = quantity * price
        item_list.append({"name": name, "quantity": quantity, "price": price, "subtotal": subtotal})
        total += subtotal
    return render_template('your_order.html', store_name=slug, slug=slug, items=item_list, total=total)

# Order Status route for Seller 
@app.route('/update_order_status', methods=['POST'])
def update_order_status():
    order_id = request.form.get('order_id')
    new_status = request.form.get('new_status')
    store_name = session.get('store_name')

    if not order_id or not store_name:
        return redirect(url_for('dashboard'))

    seller = User.query.filter_by(store_name=store_name).first()
    if not seller:
        return "Store not found", 404

    order = Order.query.filter_by(id=order_id, seller_id=seller.id).first()
    if not order:
        return "Order not found", 404

    allowed = ['Pending', 'Accepted', 'Out for Delivery', 'Delivered', 'Cancelled']
    if new_status not in allowed:
        return "Invalid status", 400

    # If cancelling, ask for confirmation server-side (no template change needed)
    if new_status == 'Cancelled' and request.form.get('confirm_cancel') != '1':
        # minimal confirmation HTML so tum template touch na karo
        return f"""
        <!doctype html>
        <html><head><meta charset="utf-8"><title>Confirm Cancel</title></head>
        <body style="font-family:Arial;padding:20px;">
          <h3>Cancel Order #{order.id}?</h3>
          <p>This will move the order to History.</p>
          <form method="POST" action="{url_for('update_order_status')}">
            <input type="hidden" name="order_id" value="{order.id}">
            <input type="hidden" name="new_status" value="Cancelled">
            <input type="hidden" name="confirm_cancel" value="1">
            <button type="submit" style="padding:8px 12px;background:#ef4444;color:#fff;border:none;border-radius:6px;cursor:pointer;">Yes, Cancel</button>
          </form>
          <p style="margin-top:10px;">
            <a href="{request.referrer or url_for('view_orders')}">No, go back</a>
          </p>
        </body></html>
        """

    # Proceed with update
    order.status = new_status
    db.session.commit()

    final_like = ['Delivered', 'Completed', 'Cancelled']
    # After final states, show history; else go back to orders
    if new_status in final_like:
        # If you have a history route, use it; else fallback to orders
        try:
            return redirect(url_for('orders_history'))
        except Exception:
            return redirect(url_for('view_orders'))
    else:
        return redirect(request.referrer or url_for('view_orders'))


# Clear Order - Move to history (status-based)
@app.route('/clear_order', methods=['POST'])
def clear_order():
    order_id = request.form.get('order_id')
    store_name = session.get('store_name')

    if not order_id or not store_name:
        return redirect(url_for('dashboard'))

    seller = User.query.filter_by(store_name=store_name).first()
    if not seller:
        return "Store not found", 404

    order = Order.query.filter_by(id=order_id, seller_id=seller.id).first()
    if not order:
        return "Order not found", 404

    # Allow clear only if final statuses; don't force-change status here
    final_like = ['Delivered', 'Completed', 'Cancelled']
    if order.status not in final_like:
        # Not final yet -> go back to orders list
        return redirect(request.referrer or url_for('view_orders'))

    # Final state hai -> "history" pe le jao (yaha sirf redirect; archive ka kaam tumhari history view pe depend karega)
    try:
        return redirect(url_for('orders_history'))
    except Exception:
        return redirect(url_for('view_orders'))


# Order History - Show only completed/delivered/cancelled
@app.route("/dashboard/order_history")
# @login_required  # optional if you're already checking session
def order_history():
    # Session guard (keep as-is if not using login_required)
    if "seller_id" not in session:
        return redirect(url_for("seller_login"))

    seller_id = session["seller_id"]

    # --- Optional pagination ---
    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        page = 1
    per_page = 20  # tweak as needed
    q = Order.query.filter(
        Order.seller_id == seller_id,
        Order.status.in_(["Completed", "Delivered", "Cancelled"])
    ).order_by(Order.created_at.desc(), Order.id.desc())

    # If you want simple list (no pagination), use .all()
    # orders = q.all()

    # Paginated
    pagination = q.paginate(page=page, per_page=per_page, error_out=False)
    orders = pagination.items

    # Group orders by date (YYYY-MM-DD)
    grouped_orders = defaultdict(list)
    for order in orders:
        # Ensure created_at exists and is datetime
        order_date = order.created_at.strftime("%Y-%m-%d")
        grouped_orders[order_date].append(order)

    # Sort each day's orders by latest first
    for date in grouped_orders:
        grouped_orders[date].sort(key=lambda x: (x.created_at, x.id), reverse=True)

    # Sort groups by date desc
    sorted_grouped_orders = sorted(grouped_orders.items(), key=lambda x: x[0], reverse=True)

    return render_template(
        "order_history.html",
        grouped_orders=sorted_grouped_orders,
        pagination=pagination  # pass if you keep pagination
    )
# Logout route fr Seller Dashboard 
@app.route('/logout')
def logout():
    session.pop('seller_id', None)
    session.pop('store_name', None)
    return redirect('/login')

# ---- Send OTP route for Seller Number OTP (updated) ----
@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.get_json() or {}
    phone = (data.get('phone') or "").strip()

    if not is_valid_phone(phone):
        return jsonify({'success': False, 'error': 'Invalid phone number'}), 400

    # Basic throttle: count OTPs in last hour for this phone
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    recent_otps_count = OTPVerification.query.filter(
        OTPVerification.phone == phone,
        OTPVerification.created_at >= one_hour_ago
    ).count()

    if recent_otps_count >= MAX_OTPS_PER_HOUR:
        return jsonify({'success': False, 'error': 'Too many OTP requests. Try after some time.'}), 429

    # Check last OTP entry to enforce resend cooldown
    last_entry = OTPVerification.query.filter_by(phone=phone).order_by(OTPVerification.created_at.desc()).first()
    now = datetime.utcnow()
    if last_entry:
        # If last OTP was created recently, prevent immediate resend
        if (now - last_entry.created_at).total_seconds() < OTP_RESEND_COOLDOWN:
            remaining = OTP_RESEND_COOLDOWN - int((now - last_entry.created_at).total_seconds())
            return jsonify({'success': False, 'error': f'Please wait {remaining}s before requesting a new OTP.'}), 429

    # generate OTP
    otp = str(random.randint(100000, 999999))

    # Upsert: update existing or create new entry; set created_at = now and store otp
    try:
        if last_entry:
            last_entry.otp = otp
            last_entry.created_at = now
            db.session.add(last_entry)
        else:
            new_entry = OTPVerification(phone=phone, otp=otp, created_at=now)
            db.session.add(new_entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Database error', 'details': str(e)}), 500

    # send via provider
    ok, details = send_otp_2factor(phone, otp)
    if ok:
        # do NOT return the OTP in response. return success and maybe a masked phone.
        return jsonify({'success': True, 'message': 'OTP sent'}), 200
    else:
        # Provider failed — consider removing DB entry or marking as failed (we leave it but you may delete)
        # Optionally: delete the OTP record so user can retry without hitting cooldown
        try:
            # remove the OTP row so the user can retry immediately if provider failed
            entry = OTPVerification.query.filter_by(phone=phone).order_by(OTPVerification.created_at.desc()).first()
            if entry:
                db.session.delete(entry)
                db.session.commit()
        except Exception:
            db.session.rollback()
        return jsonify({'success': False, 'error': 'Failed to send OTP', 'details': str(details)}), 502
# Verify OTP route for seller 
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    phone = data.get('phone')
    otp = data.get('otp')
    entry = OTPVerification.query.filter_by(phone=phone).first()
    if entry and entry.otp == otp:
        return jsonify({'verified': True})
    else:
        return jsonify({'verified': False})
# Run the app and initialize DB
if __name__ == '__main__':
    with app.app_context():
        db.init_app(app)
        db.create_all()
    app.run(debug=True)
