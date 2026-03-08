"""
Authentication Server for Secure File Vault
Handles user registration, login, and brute force protection
"""

import socket
import threading
import json
import hashlib
import os
import time
from datetime import datetime

class AuthServer:
    def __init__(self):
        self.host = '0.0.0.0'
        self.port = 8888
        self.users = {}  # username: {password_hash, salt, attempts, locked_until}
        self.load_users()
        
    def load_users(self):
        """Load users from file"""
        try:
            if os.path.exists('users.json'):
                with open('users.json', 'r') as f:
                    self.users = json.load(f)
            print(f"✅ Loaded {len(self.users)} users")
        except:
            self.users = {}
    
    def save_users(self):
        """Save users to file"""
        with open('users.json', 'w') as f:
            json.dump(self.users, f)
    
    def hash_password(self, password, salt=None):
        """Custom password hashing (not using built-in)"""
        if salt is None:
            salt = os.urandom(16).hex()
        
        # Simple but effective custom hash
        hash_value = password + salt
        for i in range(1000):  # 1000 iterations
            hash_value = hashlib.sha256(hash_value.encode()).hexdigest()
        
        return {'hash': hash_value, 'salt': salt}
    
    def check_rate_limit(self, username):
        """Prevent brute force attacks"""
        if username in self.users:
            user = self.users[username]
            if 'attempts' not in user:
                user['attempts'] = 0
            
            if 'locked_until' in user:
                if time.time() < user['locked_until']:
                    return False, "Account locked. Try again later."
            
            if user['attempts'] >= 5:
                user['locked_until'] = time.time() + 300  # Lock for 5 minutes
                self.save_users()
                return False, "Too many attempts. Account locked for 5 minutes."
        
        return True, "OK"
    
    def handle_client(self, client_socket):
        """Handle client requests"""
        try:
            data = client_socket.recv(4096).decode()
            if not data:
                return
            
            request = json.loads(data)
            command = request.get('command')
            
            if command == 'register':
                self.handle_register(request, client_socket)
            elif command == 'login':
                self.handle_login(request, client_socket)
            else:
                client_socket.send(json.dumps({'status': 'error', 'message': 'Unknown command'}).encode())
        
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()
    
    def handle_register(self, request, client_socket):
        """Handle user registration"""
        username = request.get('username')
        password = request.get('password')
        
        # Check if user exists
        if username in self.users:
            response = {'status': 'error', 'message': 'Username already exists'}
        else:
            # Hash password
            hashed = self.hash_password(password)
            self.users[username] = {
                'password_hash': hashed['hash'],
                'salt': hashed['salt'],
                'attempts': 0,
                'created': time.time()
            }
            self.save_users()
            response = {'status': 'success', 'message': 'Registration successful'}
            print(f"✅ New user registered: {username}")
        
        client_socket.send(json.dumps(response).encode())
    
    def handle_login(self, request, client_socket):
        """Handle user login with rate limiting"""
        username = request.get('username')
        password = request.get('password')
        
        # Check rate limiting
        ok, message = self.check_rate_limit(username)
        if not ok:
            client_socket.send(json.dumps({'status': 'error', 'message': message}).encode())
            return
        
        # Check if user exists
        if username not in self.users:
            response = {'status': 'error', 'message': 'Invalid credentials'}
        else:
            user = self.users[username]
            # Hash password with stored salt
            hashed = self.hash_password(password, user['salt'])
            
            if hashed['hash'] == user['password_hash']:
                # Success - reset attempts
                user['attempts'] = 0
                if 'locked_until' in user:
                    del user['locked_until']
                self.save_users()
                response = {'status': 'success', 'message': 'Login successful'}
                print(f"✅ User logged in: {username}")
            else:
                # Failed attempt
                user['attempts'] = user.get('attempts', 0) + 1
                self.save_users()
                response = {'status': 'error', 'message': 'Invalid credentials'}
        
        client_socket.send(json.dumps(response).encode())
    
    def start(self):
        """Start the server"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        
        print("\n" + "="*50)
        print("🔐 SECURE FILE VAULT - AUTH SERVER")
        print("="*50)
        print(f"Server running on {self.host}:{self.port}")
        print(f"Users loaded: {len(self.users)}")
        print("="*50 + "\n")
        
        while True:
            client, addr = server.accept()
            thread = threading.Thread(target=self.handle_client, args=(client,))
            thread.daemon = True
            thread.start()

if __name__ == "__main__":
    server = AuthServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n👋 Server shutting down...")