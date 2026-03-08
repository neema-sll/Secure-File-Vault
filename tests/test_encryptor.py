import unittest
import os
import tempfile
import shutil
import time
from pathlib import Path
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from encryptor import FileEncryptor, EncryptionError

class TestFileEncryptor(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.encryptor = FileEncryptor()
        self.test_file = Path(self.test_dir) / "test.txt"
        self.test_file.write_text("Test content")
        self.key = self.encryptor.generate_key()
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    def test_generate_key(self):
        key = self.encryptor.generate_key()
        self.assertEqual(len(key), 44)
    
    def test_encrypt_decrypt_file(self):
        encrypted = self.test_dir / "encrypted.enc"
        decrypted = self.test_dir / "decrypted.txt"
        
        self.encryptor.encrypt_file(self.test_file, encrypted, self.key)
        self.encryptor.decrypt_file(encrypted, decrypted, self.key)
        
        self.assertEqual(self.test_file.read_text(), decrypted.read_text())
    
    def test_wrong_key_fails(self):
        encrypted = self.test_dir / "encrypted.enc"
        decrypted = self.test_dir / "decrypted.txt"
        wrong_key = self.encryptor.generate_key()
        
        self.encryptor.encrypt_file(self.test_file, encrypted, self.key)
        
        with self.assertRaises(EncryptionError):
            self.encryptor.decrypt_file(encrypted, decrypted, wrong_key)
    
    def test_encrypt_decrypt_binary(self):
        binary_file = Path(self.test_dir) / "test.bin"
        binary_file.write_bytes(os.urandom(1024))
        encrypted = self.test_dir / "encrypted.enc"
        decrypted = self.test_dir / "decrypted.bin"
        
        self.encryptor.encrypt_file(binary_file, encrypted, self.key)
        self.encryptor.decrypt_file(encrypted, decrypted, self.key)
        
        self.assertEqual(binary_file.read_bytes(), decrypted.read_bytes())
    
    def test_large_file(self):
        large_file = Path(self.test_dir) / "large.bin"
        large_file.write_bytes(os.urandom(5 * 1024 * 1024))  # 5MB
        encrypted = self.test_dir / "large.enc"
        decrypted = self.test_dir / "large_decrypted.bin"
        
        start = time.time()
        self.encryptor.encrypt_file(large_file, encrypted, self.key)
        encrypt_time = time.time() - start
        
        start = time.time()
        self.encryptor.decrypt_file(encrypted, decrypted, self.key)
        decrypt_time = time.time() - start
        
        self.assertEqual(large_file.read_bytes(), decrypted.read_bytes())
        self.assertLess(encrypt_time, 5)
        self.assertLess(decrypt_time, 5)

if __name__ == '__main__':
    unittest.main()
