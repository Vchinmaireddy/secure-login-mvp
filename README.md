# Secure Login System with 2FA Authentication

A secure authentication system that provides user login functionality with Two-Factor Authentication (2FA) for enhanced account protection and cybersecurity.

---

## Features

* User registration and login
* Secure password hashing
* Two-Factor Authentication (2FA)
* OTP verification via Email/SMS
* Session management
* Password strength validation
* Forgot password functionality
* User-friendly interface

---

## Technologies Used

* Python / Node.js / Java
* Flask / Django / Express.js
* SQLite / MySQL / MongoDB
* HTML, CSS, JavaScript
* JWT Authentication
* OTP API (Twilio / Email Service)

---

## Project Structure

```bash id="l8wlrv"
secure-login-2fa/
│
├── templates/
│   ├── login.html
│   ├── register.html
│   ├── verify_otp.html
│   └── dashboard.html
│
├── static/
│   ├── style.css
│   └── script.js
│
├── database/
│   └── users.db
│
├── app.py
├── requirements.txt
└── README.md
```

---

## Installation

1. Clone the repository:

```bash id="6fd5a9"
git clone https://github.com/your-username/secure-login-2fa.git
```

2. Navigate to the project directory:

```bash id="9p13fg"
cd secure-login-2fa
```

3. Install dependencies:

```bash id="klw5p0"
pip install -r requirements.txt
```

4. Run the application:

```bash id="g20tb8"
python app.py
```

5. Open the browser and visit:

```bash id="d0m6fh"
http://127.0.0.1:5000
```

---

## How It Works

1. User registers an account
2. Password is securely hashed and stored
3. User logs in with username and password
4. System generates a One-Time Password (OTP)
5. OTP is sent via Email or SMS
6. User verifies OTP to gain access

This additional verification layer improves account security and prevents unauthorized access.

---

## Security Features

* Password hashing using bcrypt
* OTP expiration system
* Session timeout handling
* Protection against brute-force attacks
* Secure token-based authentication
* Input validation and sanitization

---

## Example Workflow

| Step | Action                        |
| ---- | ----------------------------- |
| 1    | User enters login credentials |
| 2    | System validates credentials  |
| 3    | OTP generated and sent        |
| 4    | User enters OTP               |
| 5    | Access granted                |

---

## Future Improvements

* Biometric authentication
* QR code authenticator support
* Google Authenticator integration
* CAPTCHA verification
* Multi-device login alerts

---

## Security Notice

This project is developed for educational and security learning purposes. Always follow best practices for storing credentials and handling authentication systems in production environments.

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Push to your branch
5. Open a Pull Request

---

## License

This project is licensed under the MIT License.

---

## Author

Developed by VEMPALLA CHINMAI REDDY
