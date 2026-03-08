"""
Client module for Secure File Vault
Handles authentication with server
"""

import socket
import json

class AuthClient:
    def __init__(self, server_host='localhost', server_port=8888):
        self.server = (server_host, server_port)
    
    def send_request(self, command, username, password):
        """Send request to auth server"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(self.server)
            
            request = {
                'command': command,
                'username': username,
                'password': password
            }
            
            s.send(json.dumps(request).encode())
            response = s.recv(4096).decode()
            s.close()
            
            return json.loads(response)
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def register(self, username, password):
        """Register new user"""
        return self.send_request('register', username, password)
    
    def login(self, username, password):
        """Login user"""
        return self.send_request('login', username, password)