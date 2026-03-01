# Secure-User-Authentication-System
A secure user authentication system developed as part of a *Computer Networks* project.  
The system demonstrates secure client-server communication using *TCP socket programming, with a **Python server* and *Java client, along with a **Flask-based web interface* for authentication and access control.

This project focuses on implementing secure credential management, password hashing, and network-based authentication in a distributed environment.


##  Project Overview

The Secure User Authentication System simulates a real-world authentication architecture using socket programming and web technologies.

It consists of:

-  *Java Client* – Sends user credentials via TCP socket
-  *Python Socket Server* – Validates credentials securely
-  *Flask Web Interface* – Handles login sessions and access control
-  *Password Hashing* – Ensures secure storage of credentials

The system prevents plaintext password storage and enforces secure validation mechanisms.


##  Project Objectives

- Implement TCP-based client-server authentication
- Secure user credentials using hashing algorithms
- Prevent plaintext password exposure
- Enforce authentication-based access control
- Demonstrate networking concepts in a practical application


##  System Architecture


Java Client  →  Python Socket Server  →  Credential Storage (Hashed Passwords)
                                     ↓
                               Flask Web Interface



##  Technology Stack

###  Backend
- Python
- Flask
- Socket Programming (TCP)

###  Client
- Java (Socket Programming)

###  Security
- Password Hashing (e.g., SHA-256 / bcrypt)

###  Networking
- TCP Sockets


##  Key Features

- Secure TCP client-server communication
- Password hashing for secure credential storage
- No plaintext password storage
- Server-side credential validation
- Flask-based authentication interface
- Session-based access control
- Modular architecture

##  Functional Workflow

### 1️ Socket-Based Authentication

1. User enters username and password in the Java client.
2. Java client sends credentials to the Python server via TCP socket.
3. Python server:
   - Receives credentials
   - Hashes the password
   - Compares with stored hashed password
   - Sends authentication result back to client
4. Client displays login success or failure message.


### 2️ Web-Based Authentication (Flask)

1. User accesses the Flask login page.
2. Credentials are submitted via web form.
3. Server validates credentials against stored hashed passwords.
4. On success:
   - A session is created
   - Access to protected routes is granted
5. On failure:
   - Access denied message is displayed

##  Installation & Setup

### 1️ Clone the Repository

bash
git clone <repository-url>
cd secure-user-authentication-system


### 2️ Install Python Dependencies

bash
pip install flask


### 3️ Run the Python Socket Server

bash
python server.py


### 4️ Run the Flask Application

bash
python app.py


### 5️ Compile and Run Java Client

Compile:

bash
javac Client.java


Run:

bash
java Client


##  Security Implementation Details

- Passwords are hashed before storage.
- Server performs secure hash comparison.
- Authentication logic is centralized on server.
- Client does not store sensitive data.
- Flask sessions enforce access control.
- Prevents unauthorized access to protected routes.

##  Networking Concepts Demonstrated

- TCP Socket Programming
- Client-Server Architecture
- Request-Response Communication
- Secure Credential Handling
- Session Management
- Access Control Mechanisms

##  Learning Outcomes

- Practical implementation of secure socket communication
- Integration of networking with web technologies
- Understanding of password hashing and authentication flows
- Implementation of secure system design principles

##  Future Improvements

- Add SSL/TLS encryption for secure socket communication
- Implement JWT-based authentication
- Integrate a relational database (PostgreSQL/MySQL)
- Add Multi-Factor Authentication (MFA)
- Implement logging and monitoring
- Add rate limiting to prevent brute-force attacks


##  Author

Developed as part of a *Computer Networks* course project focusing on secure authentication systems using socket programming and web integration.
