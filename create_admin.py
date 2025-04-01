from app import create_app, db
from models import User

def create_admin_user():
    app = create_app()
    with app.app_context():
        # Check if admin user already exists
        admin = User.query.filter_by(username='admin').first()
        if admin:
            print("Admin user already exists")
            return
        
        # Create new admin user
        admin = User(
            username='admin',
            email='admin@frighttool.com',
            role='admin'
        )
        admin.set_password('Admin@123')
        
        try:
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully")
        except Exception as e:
            db.session.rollback()
            print(f"Error creating admin user: {str(e)}")

if __name__ == '__main__':
    create_admin_user() 