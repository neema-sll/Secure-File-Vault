"""
Simple Unit Test for Secure File Vault
Tests the core encryption functionality
"""

import unittest
import os
import tempfile
from client.encryptor import FileEncryptor

class TestEncryption(unittest.TestCase):
    """Test cases for encryption functionality"""
    
    def setUp(self):
        """Setup before each test - creates a temporary test file"""
        self.encryptor = FileEncryptor()
        self.password = "test123"
        
        # Create a simple test file with "Hello World" content
        self.test_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
        self.test_file.write(b"Hello World")
        self.test_file.close()
    
    def tearDown(self):
        """Cleanup after each test - removes all temporary files"""
        files = [
            self.test_file.name,
            self.test_file.name + '.encrypted',
            self.test_file.name + '.decrypted'
        ]
        for file in files:
            if os.path.exists(file):
                os.unlink(file)
    
    def test_encrypt_decrypt(self):
        """
        Test 1: Verify that a file can be encrypted and then decrypted back to original
        
        This test:
        1. Takes a simple text file with "Hello World"
        2. Encrypts it using the password "test123"
        3. Decrypts the encrypted file using the same password
        4. Compares the decrypted content with the original
        """
        print("\n📁 Test 1: File Encryption/Decryption Cycle")
        print("-" * 40)
        
        # Step 1: Encrypt the file
        result, msg = self.encryptor.encrypt_file(
            self.test_file.name,           # Input file
            self.test_file.name + '.encrypted',  # Output encrypted file
            self.password                    # Password
        )
        print(f"   Encryption: {msg}")
        self.assertTrue(result)  # Verify encryption succeeded
        
        # Step 2: Decrypt the file
        result, msg = self.encryptor.decrypt_file(
            self.test_file.name + '.encrypted',  # Input encrypted file
            self.test_file.name + '.decrypted',   # Output decrypted file
            self.password                         # Same password
        )
        print(f"   Decryption: {msg}")
        self.assertTrue(result)  # Verify decryption succeeded
        
        # Step 3: Compare original and decrypted content
        with open(self.test_file.name, 'rb') as f1:
            original = f1.read()
        with open(self.test_file.name + '.decrypted', 'rb') as f2:
            decrypted = f2.read()
        
        # Verify they are identical
        self.assertEqual(original, decrypted)
        print(f"   Original: {original}")
        print(f"   Decrypted: {decrypted}")
        print("   ✅ Test passed: File encrypted and decrypted successfully")
    
    def test_wrong_password(self):
        """
        Test 2: Verify that wrong password cannot decrypt the file
        
        This test ensures security by checking that:
        1. File encrypted with correct password
        2. Attempting to decrypt with wrong password FAILS
        3. This proves encryption is working properly
        """
        print("\n🔐 Test 2: Wrong Password Rejection")
        print("-" * 40)
        
        # Step 1: Encrypt with correct password
        self.encryptor.encrypt_file(
            self.test_file.name,
            self.test_file.name + '.encrypted',
            self.password
        )
        print(f"   ✅ File encrypted with password: {self.password}")
        
        # Step 2: Try to decrypt with wrong password
        result, msg = self.encryptor.decrypt_file(
            self.test_file.name + '.encrypted',
            self.test_file.name + '.decrypted',
            'wrongpassword'  # Different password
        )
        print(f"   Attempt with wrong password: {msg}")
        
        # Step 3: Verify decryption FAILED (result should be False)
        self.assertFalse(result)
        print("   ✅ Test passed: Wrong password correctly rejected")
    
    def test_text_encryption(self):
        """
        Test 3: Verify that text can be encrypted and decrypted
        
        This test:
        1. Takes a simple text string "Hello World"
        2. Encrypts it to base64 encoded string
        3. Decrypts it back to original text
        4. Verifies the text matches
        """
        print("\n📝 Test 3: Text Encryption/Decryption")
        print("-" * 40)
        
        original = "Hello World"
        print(f"   Original text: {original}")
        
        # Step 1: Encrypt the text
        result, encrypted = self.encryptor.encrypt_text(original, self.password)
        self.assertTrue(result)
        print(f"   Encrypted (base64): {encrypted[:20]}...")  # Show first 20 chars
        
        # Step 2: Decrypt the text
        result, decrypted = self.encryptor.decrypt_text(encrypted, self.password)
        self.assertTrue(result)
        print(f"   Decrypted text: {decrypted}")
        
        # Step 3: Verify they match
        self.assertEqual(original, decrypted)
        print("   ✅ Test passed: Text encrypted and decrypted successfully")

if __name__ == '__main__':
    print("\n" + "="*50)
    print("🔐 SECURE FILE VAULT - UNIT TESTS")
    print("="*50)
    print("Testing encryption functionality...")
    unittest.main(verbosity=2)