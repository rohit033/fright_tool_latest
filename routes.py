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
import tempfile
from models import User, FreightRequest, PricingResponse, UserMessage, SearchHistory
from app import db

bp = Blueprint('main', __name__)
logger = logging.getLogger(__name__)

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'jpeg', 'png'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def admin_required(f):
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            flash('Admin access required')
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

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
    
    # Get recent search history
    recent_searches = SearchHistory.query.filter_by(user_id=current_user.id)\
        .order_by(SearchHistory.created_at.desc())\
        .limit(5).all()
    
    # Base query
    if current_user.role == 'sales':
        query = FreightRequest.query.filter_by(user_id=current_user.id)
    elif current_user.role == 'pricing':
        query = FreightRequest.query.filter_by(status='pending')
    else:  # admin
        query = FreightRequest.query
    
    # Apply filters
    if search:
        query = query.filter(
            db.or_(
                FreightRequest.pol.ilike(f'%{search}%'),
                FreightRequest.pod.ilike(f'%{search}%'),
                FreightRequest.cargo_type.ilike(f'%{search}%')
            )
        )
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    if date_from:
        query = query.filter(FreightRequest.cargo_readiness >= datetime.strptime(date_from, '%Y-%m-%d'))
    
    if date_to:
        query = query.filter(FreightRequest.cargo_readiness <= datetime.strptime(date_to, '%Y-%m-%d'))
    
    # Get requests
    requests = query.order_by(FreightRequest.created_at.desc()).all()
    
    # Get unread message count
    unread_count = UserMessage.query.filter_by(receiver_id=current_user.id, is_read=False).count()
    
    return render_template('dashboard.html', 
                         requests=requests, 
                         unread_count=unread_count,
                         search=search,
                         status_filter=status_filter,
                         date_from=date_from,
                         date_to=date_to,
                         recent_searches=recent_searches)

@bp.route('/new_request', methods=['GET', 'POST'])
@login_required
def new_request():
    if current_user.role != 'sales':
        flash('Only sales users can create new requests')
        return redirect(url_for('main.dashboard'))
        
    if request.method == 'POST':
        freight_request = FreightRequest(
            pol=request.form.get('pol'),
            pod=request.form.get('pod'),
            container_type=request.form.get('container_type'),
            cargo_type=request.form.get('cargo_type'),
            weight=float(request.form.get('weight')),
            free_days=int(request.form.get('free_days')),
            cargo_readiness=datetime.strptime(request.form.get('cargo_readiness'), '%Y-%m-%d'),
            remarks=request.form.get('remarks'),
            user_id=current_user.id
        )
        db.session.add(freight_request)
        db.session.commit()
        flash('Request created successfully')
        return redirect(url_for('main.dashboard'))
        
    return render_template('new_request.html')

@bp.route('/request/<int:request_id>/pricing', methods=['GET', 'POST'])
@login_required
def provide_pricing(request_id):
    if current_user.role != 'pricing':
        flash('Only pricing team can provide pricing')
        return redirect(url_for('main.dashboard'))
    
    freight_request = FreightRequest.query.get_or_404(request_id)
    if freight_request.status != 'pending':
        flash('This request has already been processed')
        return redirect(url_for('main.dashboard'))
    
    if freight_request.response:
        flash('Pricing has already been provided for this request')
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        # Handle file uploads with security checks
        local_charges_file = request.files.get('local_charges_file')
        destination_charges_file = request.files.get('destination_charges_file')
        
        if not local_charges_file or not destination_charges_file:
            flash('Please upload both local and destination charges files')
            return redirect(url_for('main.provide_pricing', request_id=request_id))
        
        # Validate file types
        if not local_charges_file.filename.endswith('.pdf') or not destination_charges_file.filename.endswith('.pdf'):
            flash('Only PDF files are allowed')
            return redirect(url_for('main.provide_pricing', request_id=request_id))
        
        # Generate secure filenames
        local_charges_filename = f'local_charges_{request_id}_{secrets.token_hex(8)}.pdf'
        destination_charges_filename = f'destination_charges_{request_id}_{secrets.token_hex(8)}.pdf'
        
        # Save files
        local_charges_path = os.path.join(current_app.config['UPLOAD_FOLDER'], local_charges_filename)
        destination_charges_path = os.path.join(current_app.config['UPLOAD_FOLDER'], destination_charges_filename)
        
        try:
            local_charges_file.save(local_charges_path)
            destination_charges_file.save(destination_charges_path)
        except Exception as e:
            flash('Error saving files. Please try again.')
            return redirect(url_for('main.provide_pricing', request_id=request_id))
        
        # Create pricing response
        pricing_response = PricingResponse(
            ocean_freight=float(request.form.get('ocean_freight')),
            free_days=int(request.form.get('free_days')),
            vessel_name=request.form.get('vessel_name'),
            vessel_number=request.form.get('vessel_number'),
            departure_date=datetime.strptime(request.form.get('departure_date'), '%Y-%m-%d'),
            local_charges_file=local_charges_filename,
            destination_charges_file=destination_charges_filename,
            request_id=request_id
        )
        
        db.session.add(pricing_response)
        freight_request.status = 'completed'
        db.session.commit()
        
        flash('Pricing response submitted successfully')
        return redirect(url_for('main.dashboard'))
    
    return render_template('pricing_response.html', request=freight_request)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.home'))

@bp.route('/download/<path:filename>')
@login_required
def download_file(filename):
    try:
        return send_file(
            os.path.join(current_app.config['UPLOAD_FOLDER'], filename),
            as_attachment=True
        )
    except Exception as e:
        flash('Error downloading file')
        return redirect(url_for('main.dashboard'))

@bp.route('/admin')
@admin_required
def admin_dashboard():
    # Get statistics
    stats = {
        'total_requests': FreightRequest.query.count(),
        'pending_requests': FreightRequest.query.filter_by(status='pending').count(),
        'completed_requests': FreightRequest.query.filter_by(status='completed').count()
    }
    
    # Get recent requests
    recent_requests = FreightRequest.query.order_by(FreightRequest.created_at.desc()).limit(10).all()
    
    return render_template('admin_dashboard.html', stats=stats, recent_requests=recent_requests)

@bp.route('/admin/export/sales')
@admin_required
def export_sales_data():
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'Request ID', 'Created By', 'POL', 'POD', 'Container Type', 
        'Cargo Type', 'Weight', 'Free Days', 'Cargo Readiness',
        'Status', 'Created At'
    ])
    
    # Write data
    requests = FreightRequest.query.all()
    for req in requests:
        writer.writerow([
            req.id, req.user.username, req.pol, req.pod, req.container_type,
            req.cargo_type, req.weight, req.free_days, req.cargo_readiness.strftime('%Y-%m-%d'),
            req.status, req.created_at.strftime('%Y-%m-%d %H:%M')
        ])
    
    # Create response
    output.seek(0)
    return Response(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=sales_data_{datetime.now().strftime("%Y%m%d")}.csv'}
    )

@bp.route('/admin/export/pricing')
@admin_required
def export_pricing_data():
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'Request ID', 'Sales Person', 'POL', 'POD', 'Ocean Freight',
        'Free Days', 'Vessel Name', 'Vessel Number', 'Departure Date',
        'Local Charges File', 'Destination Charges File', 'Created At'
    ])
    
    # Write data
    responses = PricingResponse.query.all()
    for resp in responses:
        writer.writerow([
            resp.request_id, resp.request.user.username, resp.request.pol, resp.request.pod,
            resp.ocean_freight, resp.free_days, resp.vessel_name, resp.vessel_number,
            resp.departure_date.strftime('%Y-%m-%d'), resp.local_charges_file,
            resp.destination_charges_file, resp.created_at.strftime('%Y-%m-%d %H:%M')
        ])
    
    # Create response
    output.seek(0)
    return Response(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=pricing_data_{datetime.now().strftime("%Y%m%d")}.csv'}
    )

@bp.route('/messages')
@login_required
def messages():
    # Get all messages for the current user
    received_messages = UserMessage.query.filter_by(receiver_id=current_user.id).order_by(UserMessage.created_at.desc()).all()
    sent_messages = UserMessage.query.filter_by(sender_id=current_user.id).order_by(UserMessage.created_at.desc()).all()
    
    # Get all users for the message form
    if current_user.role == 'sales':
        users = User.query.filter_by(role='pricing').all()
    elif current_user.role == 'pricing':
        users = User.query.filter_by(role='sales').all()
    else:
        users = User.query.filter(User.id != current_user.id).all()
    
    return render_template('messages.html', 
                         received_messages=received_messages,
                         sent_messages=sent_messages,
                         users=users)

@bp.route('/send_message', methods=['POST'])
@login_required
def send_message():
    receiver_id = request.form.get('receiver_id')
    content = request.form.get('content')
    
    if not content:
        flash('Message content cannot be empty')
        return redirect(url_for('main.messages'))
        
    message = UserMessage(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        content=content
    )
    
    db.session.add(message)
    db.session.commit()
    
    flash('Message sent successfully')
    return redirect(url_for('main.messages'))

@bp.route('/mark_message_read/<int:message_id>')
@login_required
def mark_message_read(message_id):
    message = UserMessage.query.get_or_404(message_id)
    
    if message.receiver_id != current_user.id:
        flash('Unauthorized')
        return redirect(url_for('main.messages'))
        
    message.is_read = True
    db.session.commit()
    
    return redirect(url_for('main.messages'))

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

@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user or not user.reset_token_expiry or user.reset_token_expiry < datetime.utcnow():
        flash('Invalid or expired reset token.')
        return redirect(url_for('main.forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match.')
            return render_template('reset_password.html')
        
        user.set_password(password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        flash('Password has been reset successfully. Please login.')
        return redirect(url_for('main.login'))
    
    return render_template('reset_password.html')

@bp.route('/request/<int:request_id>')
@login_required
def view_request(request_id):
    request = FreightRequest.query.get_or_404(request_id)
    
    # Check if user has permission to view this request
    if current_user.role == 'sales' and request.user_id != current_user.id:
        flash('You do not have permission to view this request.')
        return redirect(url_for('main.dashboard'))
    
    # Get unread message count
    unread_count = UserMessage.query.filter_by(receiver_id=current_user.id, is_read=False).count()
    
    return render_template('view_request.html', request=request, unread_count=unread_count)

@bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        try:
            # Create a temporary file
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1])
            file.save(temp_file.name)
            
            # Process the file here
            # ...
            
            # Clean up
            os.unlink(temp_file.name)
            flash('File uploaded successfully')
        except Exception as e:
            logger.error(f"Error uploading file: {str(e)}")
            flash('Error uploading file')
    return redirect(url_for('main.dashboard')) 