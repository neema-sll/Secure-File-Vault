"""
File Encryption Module
Implements AES-256 encryption for files
"""

import os
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class FileEncryptor:
    def __init__(self):
        self.block_size = AES.block_size
    
    def derive_key(self, password, salt=None):
        """Derive encryption key from password (custom implementation)"""
        if salt is None:
            salt = os.urandom(16)
        
        # PBKDF2-like implementation
        key = password.encode('utf-8')
        for i in range(100000):  # 100,000 iterations
            key = hashlib.sha256(key + salt + str(i).encode()).digest()
        
        return {'key': key, 'salt': salt}
    
    def encrypt_file(self, input_file, output_file, password):
        """Encrypt a file with AES-256"""
        try:
            # Generate key and IV
            salt = os.urandom(16)
            iv = os.urandom(16)
            
            # Derive key from password
            key_data = self.derive_key(password, salt)
            key = key_data['key']
            
            # Read input file
            with open(input_file, 'rb') as f:
                plaintext = f.read()
            
            # Pad data
            padding_length = self.block_size - (len(plaintext) % self.block_size)
            padded_data = plaintext + bytes([padding_length]) * padding_length
            
            # Encrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(padded_data)
            
            # Save salt + iv + ciphertext
            with open(output_file, 'wb') as f:
                f.write(salt)
                f.write(iv)
                f.write(ciphertext)
            
            return True, "Encryption successful"
        except Exception as e:
            return False, str(e)
    
    def decrypt_file(self, input_file, output_file, password):
        """Decrypt a file"""
        try:
            # Read encrypted file
            with open(input_file, 'rb') as f:
                salt = f.read(16)
                iv = f.read(16)
                ciphertext = f.read()
            
            # Derive key from password
            key_data = self.derive_key(password, salt)
            key = key_data['key']
            
            # Decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_data = cipher.decrypt(ciphertext)
            
            # Remove padding
            padding_length = padded_data[-1]
            plaintext = padded_data[:-padding_length]
            
            # Save decrypted file
            with open(output_file, 'wb') as f:
                f.write(plaintext)
            
            return True, "Decryption successful"
        except Exception as e:
            return False, str(e)
    
    def encrypt_text(self, text, password):
        """Encrypt text string"""
        try:
            salt = os.urandom(16)
            iv = os.urandom(16)
            key_data = self.derive_key(password, salt)
            key = key_data['key']
            
            # Pad data
            data = text.encode('utf-8')
            padding_length = self.block_size - (len(data) % self.block_size)
            padded_data = data + bytes([padding_length]) * padding_length
            
            # Encrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(padded_data)
            
            # Combine and encode
            result = base64.b64encode(salt + iv + ciphertext).decode()
            return True, result
        except Exception as e:
            return False, str(e)
    
    def decrypt_text(self, encrypted_text, password):
        """Decrypt text string"""
        try:
            data = base64.b64decode(encrypted_text)
            salt = data[:16]
            iv = data[16:32]
            ciphertext = data[32:]
            
            key_data = self.derive_key(password, salt)
            key = key_data['key']
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_data = cipher.decrypt(ciphertext)
            
            padding_length = padded_data[-1]
            plaintext = padded_data[:-padding_length]
            
            return True, plaintext.decode('utf-8')
        except Exception as e:
            return False, str(e)