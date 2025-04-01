from flask import Flask, render_template, request, redirect, url_for, flash, current_app, send_file, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import os
import csv
import io
import secrets
from dotenv import load_dotenv
from functools import wraps
import logging
import tempfile
from flask_migrate import Migrate
from config import config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

def create_app(config_name='default'):
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config[config_name])
    
    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    
    # Register blueprints
    from routes import bp as main_bp
    app.register_blueprint(main_bp)
    
    return app

# Create the application instance
app = create_app(os.getenv('FLASK_ENV', 'development'))

# Import models after app is created to avoid circular imports
from models import User, FreightRequest, PricingResponse, UserMessage, SearchHistory

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def init_db():
    try:
        with app.app_context():
            db.create_all()
            logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Error creating database tables: {str(e)}")
        raise

# Initialize database on startup
try:
    init_db()
except Exception as e:
    logger.error(f"Failed to initialize database: {str(e)}")

if __name__ == '__main__':
    app.run(debug=True) 