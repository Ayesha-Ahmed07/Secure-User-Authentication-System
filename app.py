from flask import Flask, render_template, request, redirect, url_for, session, flash
import socket
import json
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from datetime import timedelta
import atexit

app = Flask(__name__)
app.secret_key = 'your-very-secret-key-123'
app.permanent_session_lifetime = timedelta(minutes=30)

# Authentication Server Configuration
AUTH_SERVER_HOST = 'localhost'
AUTH_SERVER_PORT = 65432
SECRET_KEY = b'mysecretpassword'  # Must be 16, 24 or 32 bytes long

def encrypt_data(data):
    iv = os.urandom(16)  # Generate a random 16-byte IV
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv_b64 = base64.b64encode(iv).decode('utf-8')
    ct_b64 = base64.b64encode(ct_bytes).decode('utf-8')
    return json.dumps({'iv': iv_b64, 'ciphertext': ct_b64})

def decrypt_data(encrypted_data):
    try:
        b64 = json.loads(encrypted_data)
        iv = base64.b64decode(b64['iv'])
        ct = base64.b64decode(b64['ciphertext'])
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except (ValueError, KeyError, Exception) as e:
        print(f"Decryption error: {e}")
        return None

def send_to_auth_server(request_data):
    try:
        # Add user agent to identify this as web client
        request_data['user_agent'] = 'Flask Web Client'
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)  # 5 second timeout
            s.connect((AUTH_SERVER_HOST, AUTH_SERVER_PORT))
            encrypted_request = encrypt_data(json.dumps(request_data))
            s.sendall(encrypted_request.encode())
            encrypted_response = s.recv(4096).decode()
            return decrypt_data(encrypted_response)
    except Exception as e:
        print(f"Auth server communication error: {e}")
        return None

# Function to send exit signal to server when Flask app shuts down
def send_exit_signal():
    try:
        send_to_auth_server({
            'action': 'exit',
            'username': 'system',
            'password': 'exit',
            'user_agent': 'Flask Web Server Shutdown'
        })
        print("Sent exit signal to authentication server")
    except Exception as e:
        print(f"Failed to send exit signal: {e}")

# Register the exit function to be called when the app shuts down
atexit.register(send_exit_signal)

@app.route('/')
def home():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Both username and password are required', 'danger')
            return render_template('login.html', username=username)
        
        response = send_to_auth_server({
            'action': 'login',
            'username': username,
            'password': password
        })
        
        if response == "LOGIN_SUCCESS":
            session.permanent = True
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        elif response == "ACCOUNT_LOCKED":
            flash('Account locked due to too many failed attempts', 'danger')
        elif response == "USER_NOT_FOUND":
            flash('User not found', 'danger')
        else:
            flash('Invalid username or password', 'danger')
        
        return render_template('login.html', username=username)
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if len(password) < 8:
            flash('Password must be at least 8 characters', 'danger')
            return render_template('register.html', username=username)
            
        response = send_to_auth_server({
            'action': 'register',
            'username': username,
            'password': password
        })
        
        if response == "REGISTRATION_SUCCESS":
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        elif response == "USER_EXISTS":
            flash('Username already exists', 'danger')
        elif response == "WEAK_PASSWORD":
            flash('Password is too weak. It must be at least 8 characters.', 'danger')
        else:
            flash('Registration failed', 'danger')
        
        return render_template('register.html', username=username)
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/shutdown', methods=['GET'])
def shutdown():
    # Send exit signal to auth server
    response = send_to_auth_server({
        'action': 'exit',
        'username': 'system',
        'password': 'exit'
    })
    
    flash('Authentication server shutdown initiated.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)