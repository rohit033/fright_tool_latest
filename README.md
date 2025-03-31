# Freight Pricing System

A modern web application for managing freight requests, pricing, and vessel schedules. This system helps sales and pricing teams collaborate efficiently on freight pricing and scheduling.

## Features

- User authentication with role-based access (Sales, Pricing, Admin)
- Create and manage freight requests
- Track vessel schedules and availability
- Manage ocean freight rates and local charges
- Modern and responsive UI using Tailwind CSS
- File upload support for local and destination charges
- Messaging system between sales and pricing teams
- Admin dashboard with data export capabilities

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/freight_tool.git
cd freight_tool
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
Create a `.env` file in the root directory with the following:
```
SECRET_KEY=your-secret-key-here
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-email-password
```

5. Initialize the database:
```bash
python app.py
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Open your web browser and navigate to `http://localhost:5000`

3. Default admin credentials:
   - Username: `admin`
   - Password: `admin123`
   - Email: `admin@example.com`

4. Create new user accounts with appropriate roles:
   - Sales: Can create and view freight requests
   - Pricing: Can provide pricing and manage rates
   - Admin: Full access to all features

## User Roles

### Sales Team
- Create new freight requests
- View their own requests
- Track request status
- Send messages to pricing team

### Pricing Team
- View pending requests
- Provide pricing details
- Upload local and destination charges
- Send messages to sales team

### Admin
- Full access to all features
- View all requests and responses
- Export sales and pricing data
- Access admin dashboard

## Security Features

- Password hashing
- Email verification
- Account locking after failed attempts
- Password reset functionality
- Role-based access control
- Secure file upload handling

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository or contact the administrator. 