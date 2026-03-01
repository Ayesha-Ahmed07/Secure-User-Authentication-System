import socket
import hashlib
import json
import os
from threading import Thread, active_count, Lock
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from datetime import datetime
import traceback
import time
import signal
import sys

# Configuration
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 65432
BUFFER_SIZE = 4096
SECRET_KEY = b'mysecretpassword'  # 16-byte key for AES-128
USER_DB = 'users.json'

# Global variables for tracking
connected_clients = {}
active_users = {}
client_counter = 0
lock = Lock()  # To protect shared variables
server_running = True  # Flag to control server loop
log_entries = []  # Store log entries to persist across screen updates

def log_event(message):
    """Add a timestamped entry to the log"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    print(log_entry)
    log_entries.append(log_entry)
    # Keep log size manageable
    if len(log_entries) > 100:
        log_entries.pop(0)

def initialize_db():
    if not os.path.exists(USER_DB):
        with open(USER_DB, 'w') as f:
            json.dump({}, f)
        log_event(f"Created new user database: {USER_DB}")
    else:
        log_event(f"Loaded existing user database: {USER_DB}")

def encrypt_data(data):
    iv = os.urandom(16)  # Generate a random 16-byte IV
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv_b64 = base64.b64encode(iv).decode('utf-8')
    ct_b64 = base64.b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv': iv_b64, 'ciphertext': ct_b64})
    return result

def decrypt_data(encrypted_data):
    try:
        json_data = json.loads(encrypted_data)
        iv = base64.b64decode(json_data['iv'])
        ct = base64.b64decode(json_data['ciphertext'])
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        result = pt.decode('utf-8')
        return result
    except Exception as e:
        log_event(f"Decryption error: {e}")
        log_event(f"Encrypted data: {encrypted_data[:50]}..." if len(encrypted_data) > 50 else encrypted_data)
        traceback.print_exc()
        return None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def is_password_complex(password):
    return len(password) >= 8

def register_user(username, password, client_info):
    """Register a new user with client information"""
    if not is_password_complex(password):
        log_event(f"Registration FAILED for '{username}' from {client_info} - Password too weak")
        return "WEAK_PASSWORD"
        
    with open(USER_DB, 'r+') as f:
        users = json.load(f)
        if username in users:
            log_event(f"Registration FAILED for '{username}' from {client_info} - Username already exists")
            return "USER_EXISTS"
        users[username] = {
            'password_hash': hash_password(password),
            'failed_attempts': 0,
            'locked': False,
            'last_login': None,
            'registered_at': datetime.now().isoformat(),
            'registered_from': client_info
        }
        f.seek(0)
        json.dump(users, f)
        f.truncate()
    
    log_event(f"Registration SUCCESS for '{username}' from {client_info}")
    return "REGISTRATION_SUCCESS"

def verify_user(username, password, client_info):
    """Verify user login with client information"""
    with open(USER_DB, 'r+') as f:
        users = json.load(f)
        if username not in users:
            log_event(f"Login FAILED for '{username}' from {client_info} - User not found")
            return "USER_NOT_FOUND"
        
        user = users[username]
        if user['locked']:
            log_event(f"Login FAILED for '{username}' from {client_info} - Account locked")
            return "ACCOUNT_LOCKED"
        
        if user['password_hash'] == hash_password(password):
            user['failed_attempts'] = 0
            user['last_login'] = datetime.now().isoformat()
            f.seek(0)
            json.dump(users, f)
            f.truncate()
            
            # Add to active users
            with lock:
                active_users[username] = {
                    'login_time': datetime.now().isoformat(),
                    'client_info': client_info
                }
            
            log_event(f"Login SUCCESS for '{username}' from {client_info}")
            return "LOGIN_SUCCESS"
        else:
            user['failed_attempts'] += 1
            log_event(f"Login FAILED for '{username}' from {client_info} - Incorrect password (Attempt {user['failed_attempts']})")
            
            if user['failed_attempts'] >= 3:
                user['locked'] = True
                log_event(f"Account LOCKED for '{username}' - Too many failed attempts")
                
            f.seek(0)
            json.dump(users, f)
            f.truncate()
            return "LOGIN_FAILED"

def get_client_source(client_id, addr, request):
    """Determine the likely source of the client (Web, Java, etc.)"""
    action = request.get('action')
    user_agent = request.get('user_agent', 'Unknown')
    
    if 'web' in user_agent.lower():
        return f"Web Client (Flask) - {addr[0]}:{addr[1]}"
    elif 'java' in user_agent.lower():
        return f"Java Client - {addr[0]}:{addr[1]}"
    elif action == 'exit' and request.get('username') == 'system':
        return f"System Exit Signal - {addr[0]}:{addr[1]}"
    else:
        return f"Client #{client_id} ({addr[0]}:{addr[1]})"

def handle_client(conn, addr):
    global client_counter
    
    with lock:
        client_counter += 1
        client_id = client_counter
        connected_clients[addr] = {
            'id': client_id,
            'connected_at': datetime.now().isoformat(),
            'username': None,
            'client_type': 'Unknown'
        }
    
    log_event(f"NEW CONNECTION from {addr[0]}:{addr[1]} (Client #{client_id})")
    update_status()
    
    try:
        # Read client data
        data = conn.recv(BUFFER_SIZE).decode('utf-8')
        
        if not data:
            log_event(f"No data received from Client #{client_id}")
            return
        
        # Try to decrypt
        plaintext = decrypt_data(data)
        if not plaintext:
            log_event(f"Failed to decrypt data from Client #{client_id}")
            conn.send(encrypt_data("INVALID_REQUEST").encode())
            return
            
        try:
            # Parse the request
            request = json.loads(plaintext)
        except json.JSONDecodeError as e:
            log_event(f"JSON decode error from Client #{client_id}: {e}")
            conn.send(encrypt_data("INVALID_REQUEST").encode())
            return
        
        action = request.get('action')
        username = request.get('username')
        password = request.get('password')
        
        # Try to determine client type
        user_agent = request.get('user_agent', 'Unknown')
        client_source = get_client_source(client_id, addr, request)
        
        # Update client info
        with lock:
            if addr in connected_clients:
                connected_clients[addr]['username'] = username
                connected_clients[addr]['client_type'] = 'Web' if 'web' in user_agent.lower() else 'Java' if 'java' in user_agent.lower() else 'Unknown'
        
        log_event(f"Processing {action.upper()} request for user: '{username}' from {client_source}")
        
        # Process the request
        if action == 'register':
            response = register_user(username, password, client_source)
        elif action == 'login':
            response = verify_user(username, password, client_source)
        elif action == 'exit':
            # Handle client exit
            response = "SERVER_SHUTDOWN"
            log_event(f"EXIT signal received from {client_source}")
            global server_running
            server_running = False
        else:
            log_event(f"INVALID ACTION '{action}' from {client_source}")
            response = "INVALID_ACTION"
        
        log_event(f"Sending response to {client_source}: {response}")
        encrypted_response = encrypt_data(response)
        conn.send(encrypted_response.encode())
    
    except Exception as e:
        log_event(f"ERROR with Client #{client_id} ({addr}): {e}")
        traceback.print_exc()
    finally:
        with lock:
            if addr in connected_clients:
                client_info = connected_clients[addr]
                del connected_clients[addr]
        
        conn.close()
        log_event(f"DISCONNECTED: Client #{client_id} ({addr[0]}:{addr[1]})")
        
        # Check if this was the last client and show shutdown message if all clients are gone
        if len(connected_clients) == 0 and not server_running:
            log_event("SHUTDOWN: Server is shutting down as all clients have disconnected.")
        
        update_status()

def update_status():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"=== Authentication Server Status ===")
    print(f"Running on {SERVER_HOST}:{SERVER_PORT}")
    print(f"Active connections: {active_count() - 1}")  # Subtract main thread
    print(f"Connected clients: {len(connected_clients)}")
    
    if connected_clients:
        print("\nCurrent connections:")
        print(f"{'ID':<5} {'Client Address':<20} {'Type':<10} {'Username':<15} {'Connected At':<25}")
        print("-" * 75)
        for addr, client in connected_clients.items():
            client_addr = f"{addr[0]}:{addr[1]}"
            print(f"{client['id']:<5} {client_addr:<20} {client['client_type']:<10} {client['username'] or 'N/A':<15} {client['connected_at']:<25}")
    
    if active_users:
        print("\nActive logged in users:")
        print(f"{'Username':<15} {'Login Time':<25} {'Client Info':<35}")
        print("-" * 75)
        for username, info in active_users.items():
            print(f"{username:<15} {info['login_time']:<25} {info['client_info']:<35}")
    
    print("\nServer Log (recent events):")
    print("-" * 75)
    # Show the most recent log entries (up to 10)
    for entry in log_entries[-10:]:
        print(entry)

def signal_handler(sig, frame):
    log_event("SHUTDOWN: Server is shutting down (Signal received).")
    global server_running
    server_running = False

def start_server():
    initialize_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((SERVER_HOST, SERVER_PORT))
    server.listen()
    
    # Set server socket to non-blocking mode
    server.settimeout(1.0)
    
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    update_status()
    log_event(f"LISTENING: Authentication server running on {SERVER_HOST}:{SERVER_PORT}")
    
    global server_running
    try:
        while server_running:
            try:
                conn, addr = server.accept()
                thread = Thread(target=handle_client, args=(conn, addr))
                thread.daemon = True  # Daemon threads terminate when main thread ends
                thread.start()
            except socket.timeout:
                # This allows the server to check the server_running flag periodically
                continue
    except KeyboardInterrupt:
        log_event("SHUTDOWN: Server is shutting down (Keyboard Interrupt).")
    finally:
        server.close()
        log_event("SHUTDOWN COMPLETE: Server has been shut down.")

if __name__ == "__main__":
    start_server()