#  Secure Nomination System

A full-stack web application demonstrating secure coding practices with user authentication, multi-address management, and nomination tracking.

## Security Features

| Feature | Implementation |
|---------|---------------|
| Password Hashing | Bcrypt (10 salt rounds) |
| Authentication | JWT tokens (24h expiry) |
| SQL Injection Prevention | Parameterized queries |
| Input Validation | Server-side email/password validation |
| CORS Protection | Restricted origin access |
| Audit Trail | Address change history tracking |
| Secure IDs | UUID v4 (non-enumerable) |

## Tech Stack

- **Frontend:** React 18, CSS3
- **Backend:** Node.js, Express.js
- **Database:** PostgreSQL
- **Auth:** JWT, Bcrypt

## Project Structure

```
waitlist-system/
├── client/          # React Frontend
│   └── src/
│       ├── App.js   # Main component
│       └── App.css  # Styles
├── server/          # Node.js Backend
│   ├── server.js    # Express API
│   └── .env         # Environment variables
└── database/
    └── database.sql # Schema
```

### Database Setup
```bash
# Create database
psql -c "CREATE DATABASE secure_db;"

# Enable UUID extension
psql -d secure_db -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"

# Run schema
psql -d secure_db -f database/database.sql
```

### Backend Setup
```bash
cd server
npm install

# Create .env file
cat > .env << EOF
DB_USER=your_username
DB_HOST=localhost
DB_NAME=secure_db
DB_PASSWORD=your_password
DB_PORT=5432
PORT=5001
JWT_SECRET=your-super-secret-key
EOF

npm start
```

### Frontend Setup
```bash
cd client
npm install
npm start
```

Visit `http://localhost:3002`



## 📝 License

MIT
