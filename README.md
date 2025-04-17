# User Management System

A modern web application for managing users, transactions, and notifications with a responsive design and real-time updates.

## Features

- **User Authentication**
  - Secure login and registration
  - JWT-based authentication
  - Password reset functionality
  - Role-based access control (Admin/User)

- **User Management**
  - View and manage user profiles
  - Edit user details
  - Delete user accounts
  - Search and filter users
  - Sort users by various criteria

- **Transaction System**
  - Send and receive money between users
  - View transaction history
  - Filter transactions by type and date
  - Real-time balance updates

- **Notifications**
  - Real-time notification system
  - Unread notification counter
  - Notification history

- **UI/UX Features**
  - Responsive design
  - Dark/Light mode toggle
  - Collapsible sidebar
  - Smooth transitions and animations
  - Modern gradient header
  - Toast notifications

## Tech Stack

- **Frontend**
  - HTML5
  - CSS3 (with CSS Variables)
  - JavaScript (ES6+)
  - Font Awesome Icons
  - Toastify.js for notifications

- **Backend**
  - Node.js
  - Express.js
  - PostgreSQL
  - JWT for authentication
  - Bcrypt for password hashing

## Prerequisites

- Node.js (v14 or higher)
- PostgreSQL (v12 or higher)
- npm or yarn

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd simple-postgres-app
```

2. Install dependencies:
```bash
npm install
```

3. Set up the database:
- Create a PostgreSQL database
- Create a `.env` file in the root directory with your database configuration (see Environment Variables section below)
- The application will automatically use these environment variables for database connection

4. Create necessary tables:
```bash
npm run setup
```

5. Start the server:
```bash
npm start
```

The application will be available at `http://localhost:3001`

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```
JWT_SECRET=your_jwt_secret
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=your_db_name
```

## API Endpoints

### Authentication
- `POST /api/register` - Register a new user
- `POST /api/login` - User login
- `POST /api/users/forgot-password` - Request password reset
- `POST /api/users/reset-password` - Reset password

### Users
- `GET /api/users` - Get all users (admin only)
- `GET /api/users/me` - Get current user profile
- `PUT /api/users/me` - Update current user profile
- `PUT /api/users/:id` - Update user (admin only)
- `DELETE /api/users/:id` - Delete user (admin only)

### Transactions
- `POST /api/transfer` - Transfer money between users
- `GET /api/transactions/my` - Get user's transactions
- `GET /api/transactions` - Get all transactions (admin only)

### Notifications
- `GET /api/notifications` - Get user's notifications
- `POST /api/notifications` - Create notification (admin only)
- `PUT /api/notifications/:id/read` - Mark notification as read
- `DELETE /api/notifications/:id` - Delete notification

## Security Features

- Password hashing with bcrypt
- JWT-based authentication
- Protected routes
- Input validation
- SQL injection prevention
- XSS protection
- CSRF protection

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Font Awesome for icons
- Toastify.js for notifications
- Poppins font from Google Fonts 