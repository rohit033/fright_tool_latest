from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
from app import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked = db.Column(db.Boolean, default=False)
    requests = db.relationship('FreightRequest', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_reset_token(self):
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
        db.session.commit()
        return self.reset_token

class FreightRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pol = db.Column(db.String(100), nullable=False)
    pod = db.Column(db.String(100), nullable=False)
    container_type = db.Column(db.String(20), nullable=False)
    cargo_type = db.Column(db.String(100), nullable=False)
    weight = db.Column(db.Float, nullable=False)
    free_days = db.Column(db.Integer, nullable=False)
    cargo_readiness = db.Column(db.DateTime, nullable=False)
    remarks = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # pending, completed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    response = db.relationship('PricingResponse', backref='request', uselist=False)

class PricingResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ocean_freight = db.Column(db.Float, nullable=False)
    free_days = db.Column(db.Integer, nullable=False)
    vessel_name = db.Column(db.String(100), nullable=False)
    vessel_number = db.Column(db.String(50), nullable=False)
    departure_date = db.Column(db.DateTime, nullable=False)
    local_charges_file = db.Column(db.String(200), nullable=False)
    destination_charges_file = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    request_id = db.Column(db.Integer, db.ForeignKey('freight_request.id'), nullable=False)

class UserMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    
    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

class SearchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    search_query = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('search_history', lazy=True)) 