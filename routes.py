from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, send_file, Response
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import csv
import io
import secrets
from functools import wraps
import logging
from app import db, User, FreightRequest, PricingResponse, UserMessage, SearchHistory

bp = Blueprint('main', __name__)
logger = logging.getLogger(__name__)

@bp.route('/')
def home():
    return render_template('home.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.account_locked:
            flash('Account is locked. Please reset your password.')
            return redirect(url_for('main.forgot_password'))
        
        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.utcnow()
            user.failed_login_attempts = 0
            db.session.commit()
            return redirect(url_for('main.dashboard'))
        
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.account_locked = True
                user.generate_reset_token()
                db.session.commit()
                flash('Account locked due to too many failed attempts. Please reset your password.')
                return redirect(url_for('main.forgot_password'))
            db.session.commit()
        
        flash('Invalid username or password')
    return render_template('login.html')

@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')
        
        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('main.signup'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('main.signup'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('main.signup'))
        
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Account created successfully. Please login.')
        return redirect(url_for('main.login'))
    
    return render_template('signup.html')

@bp.route('/dashboard')
@login_required
def dashboard():
    # Get search and filter parameters
    search = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    # Save search to history if search parameter is present
    if search:
        search_history = SearchHistory(
            user_id=current_user.id,
            search_query=search
        )
        db.session.add(search_history)
        db.session.commit()
    
    # Base query
    query = FreightRequest.query.filter_by(user_id=current_user.id)
    
    # Apply filters
    if search:
        query = query.filter(
            (FreightRequest.pol.ilike(f'%{search}%')) |
            (FreightRequest.pod.ilike(f'%{search}%')) |
            (FreightRequest.cargo_type.ilike(f'%{search}%'))
        )
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    if date_from:
        query = query.filter(FreightRequest.created_at >= datetime.strptime(date_from, '%Y-%m-%d'))
    
    if date_to:
        query = query.filter(FreightRequest.created_at <= datetime.strptime(date_to, '%Y-%m-%d'))
    
    # Get requests
    requests = query.order_by(FreightRequest.created_at.desc()).all()
    
    return render_template('dashboard.html', requests=requests)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.home'))

@bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            user.generate_reset_token()
            flash('Password reset instructions have been sent to your email.')
        else:
            flash('Email address not found.')
        return redirect(url_for('main.login'))
    
    return render_template('forgot_password.html')

# Add all other routes from app.py here, making sure to:
# 1. Change url_for calls to include 'main.' prefix
# 2. Move the route functions here
# 3. Keep the same functionality 