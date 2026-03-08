import unittest
import os
import tempfile
from client.encryptor import FileEncryptor

class TestEncryptor(unittest.TestCase):
    def setUp(self):
        self.encryptor = FileEncryptor()
        self.password = "test123"
        self.test_data = b"Hello World! This is a test."
        
        # Create temp file
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file.write(self.test_data)
        self.temp_file.close()
    
    def tearDown(self):
        os.unlink(self.temp_file.name)
        if os.path.exists(self.temp_file.name + '.encrypted'):
            os.unlink(self.temp_file.name + '.encrypted')
        if os.path.exists(self.temp_file.name + '.decrypted'):
            os.unlink(self.temp_file.name + '.decrypted')
    
    def test_encrypt_decrypt_file(self):
        # Encrypt
        success, _ = self.encryptor.encrypt_file(
            self.temp_file.name, 
            self.temp_file.name + '.encrypted', 
            self.password
        )
        self.assertTrue(success)
        self.assertTrue(os.path.exists(self.temp_file.name + '.encrypted'))
        
        # Decrypt
        success, _ = self.encryptor.decrypt_file(
            self.temp_file.name + '.encrypted',
            self.temp_file.name + '.decrypted',
            self.password
        )
        self.assertTrue(success)
        
        # Verify
        with open(self.temp_file.name + '.decrypted', 'rb') as f:
            decrypted_data = f.read()
        self.assertEqual(self.test_data, decrypted_data)
    
    def test_wrong_password(self):
        # Encrypt
        self.encryptor.encrypt_file(
            self.temp_file.name, 
            self.temp_file.name + '.encrypted', 
            self.password
        )
        
        # Try to decrypt with wrong password
        success, _ = self.encryptor.decrypt_file(
            self.temp_file.name + '.encrypted',
            self.temp_file.name + '.decrypted',
            'wrongpassword'
        )
        self.assertFalse(success)

if __name__ == '__main__':
    unittest.main()