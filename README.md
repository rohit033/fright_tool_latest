# Freight Pricing System

A modern web application that helps the pricing department and salespeople work together better by managing ocean freight rates, local charges, and vessel schedules.

## Features

- User authentication with role-based access (Sales, Pricing, Admin)
- Create and manage freight requests
- Track vessel schedules and availability
- Manage ocean freight rates and local charges
- Modern and responsive UI using Tailwind CSS

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd freight-pricing-system
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
python app.py
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Open your web browser and navigate to `http://localhost:5000`

3. Create a new account with one of the following roles:
   - Sales: Can create and view freight requests
   - Pricing: Can approve/reject requests and manage rates
   - Admin: Full access to all features

## User Roles

### Sales Team
- Create new freight requests
- View their own requests
- Track request status

### Pricing Team
- View pending requests
- Approve or reject requests
- Manage rates and charges

### Admin
- Full access to all features
- Manage user accounts
- View all requests and responses

## Database Schema

### Users
- Username
- Email
- Password (hashed)
- Role (sales/pricing/admin)

### Freight Requests
- Port of Loading (POL)
- Port of Discharge (POD)
- Container Type
- Cargo Type
- Weight
- Free Days
- Cargo Readiness Date
- Remarks
- Status (pending/approved/rejected)
- Created At
- User ID (foreign key)

### Pricing Responses
- Ocean Freight Rate
- POL Charges
- POD Charges
- Free Days
- Vessel Name
- Vessel Number
- Departure Date
- Created At
- Request ID (foreign key)

## Security

- Passwords are hashed using Werkzeug's security functions
- Role-based access control
- Session management with Flask-Login
- CSRF protection with Flask-WTF

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 