# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# User table for sellers
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(10), unique=True, nullable=False)
    store_name = db.Column(db.String(80), nullable=False)
    slug = db.Column(db.String(120), unique=True, nullable=False)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    owner_name = db.Column(db.String(100), nullable=True)
    password = db.Column(db.String(200), nullable=False)
    address = db.Column(db.String(200), nullable=True)
    category = db.Column(db.String(50), nullable=True)
    qr_code_path = db.Column(db.String(255), nullable=True)
    reset_token = db.Column(db.String(100), nullable=True)
    products = db.relationship('Product', backref='seller', lazy=True, cascade="all, delete-orphan")
    orders = db.relationship('Order', backref='seller', lazy=True, cascade="all, delete-orphan")
    settings = db.relationship('StoreSettings', backref='seller', lazy=True, uselist=False, cascade="all, delete-orphan")
    offers = db.relationship('Offer', backref='seller', lazy=True, cascade="all, delete-orphan")

# Product table for seller's products
class Product(db.Model):
    __tablename__ = 'product'
    id = db.Column(db.Integer, primary_key=True)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit = db.Column(db.String(50), nullable=True)
    image_url = db.Column(db.String(255), nullable=False)

# Order table for customer orders
class Order(db.Model):
    __tablename__ = 'order'
    id = db.Column(db.Integer, primary_key=True)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    customer_phone = db.Column(db.String(10), nullable=False)
    customer_address = db.Column(db.String(255), nullable=True)
    delivery_mode = db.Column(db.String(50), nullable=True)
    delivery_charge = db.Column(db.Float, default=0.0)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_cleared_by_seller = db.Column(db.Boolean, default=False)  # << NEW
    items = db.relationship('OrderItem', backref='order', lazy=True, cascade="all, delete-orphan")

# Order items table
class OrderItem(db.Model):
    __tablename__ = 'order_item'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Float, nullable=False)

# Store settings table
class StoreSettings(db.Model):
    __tablename__ = 'store_settings'
    id = db.Column(db.Integer, primary_key=True)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    is_open = db.Column(db.Boolean, default=True)
    upi_id = db.Column(db.String(255), nullable=True)
    allows_delivery = db.Column(db.Boolean, default=False, nullable=False)
# OTP verification table
class OTPVerification(db.Model):
    __tablename__ = 'otp_verification'
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(10), unique=True, nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Master product table (if needed for a master list)
class MasterProduct(db.Model):
    __tablename__ = 'master_product'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    image_url = db.Column(db.String(255), nullable=True)
    unit = db.Column(db.String(50), nullable=True) 
# Offer table for store offers
class Offer(db.Model):
    __tablename__ = 'offer'
    id = db.Column(db.Integer, primary_key=True)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    image_path = db.Column(db.String(255), nullable=True)
