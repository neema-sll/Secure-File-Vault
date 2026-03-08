import unittest
import os
import tempfile
import shutil
from pathlib import Path
import sys
import time
# Add the src directory to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from encryptor import FileEncryptor, EncryptionError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2

class TestFileEncryptor(unittest.TestCase):
    """Test cases for FileEncryptor class."""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.test_dir = tempfile.mkdtemp()
        self.encryptor = FileEncryptor()
        self.test_file = Path(self.test_dir) / "test.txt"
        self.test_file.write_text("This is test content for encryption testing.")
        
        # Create a binary test file
        self.binary_file = Path(self.test_dir) / "test.bin"
        with open(self.binary_file, 'wb') as f:
            f.write(os.urandom(1024))  # 1KB random data
            
        # Create a large test file (10MB)
        self.large_file = Path(self.test_dir) / "large.bin"
        with open(self.large_file, 'wb') as f:
            f.write(os.urandom(10 * 1024 * 1024))
    
    def tearDown(self):
        """Clean up test fixtures after each test method."""
        shutil.rmtree(self.test_dir)
    
    def test_generate_key(self):
        """Test key generation functionality."""
        key = self.encryptor.generate_key()
        self.assertIsNotNone(key)
        self.assertEqual(len(key), 44)  # Fernet keys are 32 bytes base64-encoded
        
        # Verify it's a valid Fernet key
        try:
            fernet = Fernet(key)
            self.assertIsNotNone(fernet)
        except Exception as e:
            self.fail(f"Generated key is not a valid Fernet key: {e}")
    
    def test_derive_key_from_password(self):
        """Test key derivation from password."""
        password = "test_password_123"
        salt = os.urandom(16)
        
        # Test with salt
        key1 = self.encryptor.derive_key_from_password(password, salt)
        self.assertEqual(len(key1), 44)
        
        # Test without salt (should generate one)
        key2, salt2 = self.encryptor.derive_key_from_password(password)
        self.assertEqual(len(key2), 44)
        self.assertEqual(len(salt2), 16)
        
        # Same password with same salt should produce same key
        key3 = self.encryptor.derive_key_from_password(password, salt)
        self.assertEqual(key1, key3)
        
        # Different password should produce different key
        key4 = self.encryptor.derive_key_from_password("different", salt)
        self.assertNotEqual(key1, key4)
    
    def test_encrypt_file(self):
        """Test file encryption."""
        key = self.encryptor.generate_key()
        encrypted_path = self.test_dir / "encrypted.enc"
        
        # Encrypt the file
        result = self.encryptor.encrypt_file(self.test_file, encrypted_path, key)
        
        self.assertTrue(result)
        self.assertTrue(encrypted_path.exists())
        self.assertGreater(encrypted_path.stat().st_size, 0)
        
        # Encrypted file should be different from original
        with open(self.test_file, 'rb') as f1, open(encrypted_path, 'rb') as f2:
            original_content = f1.read()
            encrypted_content = f2.read()
            self.assertNotEqual(original_content, encrypted_content)
    
    def test_decrypt_file(self):
        """Test file decryption."""
        key = self.encryptor.generate_key()
        encrypted_path = self.test_dir / "encrypted.enc"
        decrypted_path = self.test_dir / "decrypted.txt"
        
        # Encrypt then decrypt
        self.encryptor.encrypt_file(self.test_file, encrypted_path, key)
        result = self.encryptor.decrypt_file(encrypted_path, decrypted_path, key)
        
        self.assertTrue(result)
        self.assertTrue(decrypted_path.exists())
        
        # Decrypted content should match original
        original_content = self.test_file.read_text()
        decrypted_content = decrypted_path.read_text()
        self.assertEqual(original_content, decrypted_content)
    
    def test_encrypt_decrypt_binary_file(self):
        """Test encryption and decryption of binary files."""
        key = self.encryptor.generate_key()
        encrypted_path = self.test_dir / "binary.enc"
        decrypted_path = self.test_dir / "binary_decrypted.bin"
        
        # Encrypt binary file
        self.encryptor.encrypt_file(self.binary_file, encrypted_path, key)
        
        # Decrypt binary file
        self.encryptor.decrypt_file(encrypted_path, decrypted_path, key)
        
        # Compare original and decrypted binary content
        with open(self.binary_file, 'rb') as f1, open(decrypted_path, 'rb') as f2:
            original = f1.read()
            decrypted = f2.read()
            self.assertEqual(original, decrypted)
    
    def test_encrypt_large_file(self):
        """Test encryption of large files (streaming)."""
        key = self.encryptor.generate_key()
        encrypted_path = self.test_dir / "large.enc"
        decrypted_path = self.test_dir / "large_decrypted.bin"
        
        # Encrypt large file
        start_time = time.time()
        self.encryptor.encrypt_file(self.large_file, encrypted_path, key)
        encrypt_time = time.time() - start_time
        
        # Decrypt large file
        start_time = time.time()
        self.encryptor.decrypt_file(encrypted_path, decrypted_path, key)
        decrypt_time = time.time() - start_time
        
        # Verify integrity
        with open(self.large_file, 'rb') as f1, open(decrypted_path, 'rb') as f2:
            # Compare first and last chunks
            f1.seek(0)
            f2.seek(0)
            self.assertEqual(f1.read(1024), f2.read(1024))
            
            f1.seek(-1024, 2)
            f2.seek(-1024, 2)
            self.assertEqual(f1.read(1024), f2.read(1024))
        
        # Performance assertions (adjust thresholds as needed)
        self.assertLess(encrypt_time, 5.0)  # Should encrypt in under 5 seconds
        self.assertLess(decrypt_time, 5.0)  # Should decrypt in under 5 seconds
    
    def test_encrypt_with_metadata(self):
        """Test encryption with metadata attachment."""
        key = self.encryptor.generate_key()
        encrypted_path = self.test_dir / "metadata.enc"
        
        metadata = {
            'filename': 'test.txt',
            'owner': 'test_user',
            'timestamp': '2024-01-01T00:00:00',
            'version': '1.0'
        }
        
        # Encrypt with metadata
        result = self.encryptor.encrypt_file(
            self.test_file, 
            encrypted_path, 
            key, 
            metadata=metadata
        )
        
        self.assertTrue(result)
        
        # Decrypt and verify metadata
        decrypted_path = self.test_dir / "with_metadata.txt"
        extracted_metadata = self.encryptor.decrypt_file(
            encrypted_path, 
            decrypted_path, 
            key, 
            extract_metadata=True
        )
        
        self.assertEqual(metadata['filename'], extracted_metadata['filename'])
        self.assertEqual(metadata['owner'], extracted_metadata['owner'])
    
    def test_encryption_with_wrong_key(self):
        """Test decryption with incorrect key."""
        key = self.encryptor.generate_key()
        wrong_key = self.encryptor.generate_key()
        encrypted_path = self.test_dir / "encrypted.enc"
        decrypted_path = self.test_dir / "decrypted.txt"
        
        # Encrypt with correct key
        self.encryptor.encrypt_file(self.test_file, encrypted_path, key)
        
        # Attempt decryption with wrong key
        with self.assertRaises(EncryptionError):
            self.encryptor.decrypt_file(encrypted_path, decrypted_path, wrong_key)
        
        # Decrypted file should not exist
        self.assertFalse(decrypted_path.exists())
    
    def test_encrypt_nonexistent_file(self):
        """Test encryption of non-existent file."""
        key = self.encryptor.generate_key()
        nonexistent = Path(self.test_dir) / "nonexistent.txt"
        encrypted_path = self.test_dir / "encrypted.enc"
        
        with self.assertRaises(FileNotFoundError):
            self.encryptor.encrypt_file(nonexistent, encrypted_path, key)
    
    def test_decrypt_corrupted_file(self):
        """Test decryption of corrupted encrypted file."""
        key = self.encryptor.generate_key()
        encrypted_path = self.test_dir / "encrypted.enc"
        decrypted_path = self.test_dir / "decrypted.txt"
        
        # Encrypt file
        self.encryptor.encrypt_file(self.test_file, encrypted_path, key)
        
        # Corrupt the encrypted file
        with open(encrypted_path, 'r+b') as f:
            f.seek(100)
            f.write(b'X' * 10)
        
        # Attempt decryption
        with self.assertRaises(EncryptionError):
            self.encryptor.decrypt_file(encrypted_path, decrypted_path, key)
    
    def test_stream_encryption_decryption(self):
        """Test streaming encryption and decryption."""
        key = self.encryptor.generate_key()
        encrypted_path = self.test_dir / "stream.enc"
        decrypted_path = self.test_dir / "stream_decrypted.txt"
        
        # Test with a generator/stream input
        def data_stream():
            chunks = ["Hello ", "World ", "from ", "stream ", "encryption"]
            for chunk in chunks:
                yield chunk.encode()
        
        # Encrypt stream
        self.encryptor.encrypt_stream(
            data_stream(), 
            encrypted_path, 
            key
        )
        
        # Decrypt to stream
        decrypted_chunks = []
        def chunk_handler(chunk):
            decrypted_chunks.append(chunk.decode())
        
        self.encryptor.decrypt_stream(
            encrypted_path, 
            key, 
            chunk_handler
        )
        
        # Verify
        result = ''.join(decrypted_chunks)
        self.assertEqual(result, "Hello World from stream encryption")
    
    def test_key_rotation(self):
        """Test key rotation functionality."""
        old_key = self.encryptor.generate_key()
        new_key = self.encryptor.generate_key()
        encrypted_path = self.test_dir / "rotate.enc"
        reencrypted_path = self.test_dir / "reencrypted.enc"
        
        # Encrypt with old key
        self.encryptor.encrypt_file(self.test_file, encrypted_path, old_key)
        
        # Re-encrypt with new key
        self.encryptor.reencrypt_file(encrypted_path, reencrypted_path, old_key, new_key)
        
        # Decrypt with new key
        decrypted_path = self.test_dir / "rotated_decrypted.txt"
        self.encryptor.decrypt_file(reencrypted_path, decrypted_path, new_key)
        
        # Verify content
        original = self.test_file.read_text()
        decrypted = decrypted_path.read_text()
        self.assertEqual(original, decrypted)
    
    def test_multiple_file_encryption(self):
        """Test encrypting multiple files with same key."""
        key = self.encryptor.generate_key()
        
        # Create multiple test files
        files = []
        for i in range(5):
            file_path = Path(self.test_dir) / f"test_{i}.txt"
            file_path.write_text(f"Content for file {i}")
            files.append(file_path)
        
        # Encrypt all files
        encrypted_files = []
        for file_path in files:
            encrypted_path = Path(self.test_dir) / f"{file_path.stem}.enc"
            self.encryptor.encrypt_file(file_path, encrypted_path, key)
            encrypted_files.append(encrypted_path)
        
        # Decrypt all files
        for i, enc_path in enumerate(encrypted_files):
            dec_path = Path(self.test_dir) / f"decrypted_{i}.txt"
            self.encryptor.decrypt_file(enc_path, dec_path, key)
            
            # Verify content
            original = files[i].read_text()
            decrypted = dec_path.read_text()
            self.assertEqual(original, decrypted)
    
    def test_encryption_performance(self):
        """Test encryption performance metrics."""
        key = self.encryptor.generate_key()
        
        # Test with different file sizes
        sizes = [1024, 10240, 102400]  # 1KB, 10KB, 100KB
        results = {}
        
        for size in sizes:
            # Create test file
            test_file = Path(self.test_dir) / f"perf_{size}.bin"
            with open(test_file, 'wb') as f:
                f.write(os.urandom(size))
            
            encrypted_path = Path(self.test_dir) / f"perf_{size}.enc"
            
            # Measure encryption time
            import time
            start = time.perf_counter()
            self.encryptor.encrypt_file(test_file, encrypted_path, key)
            end = time.perf_counter()
            
            results[size] = end - start
        
        # Log results
        for size, time_taken in results.items():
            print(f"Size: {size} bytes, Time: {time_taken:.4f}s, Rate: {size/time_taken:.2f} bytes/s")
        
        # Basic performance assertion
        self.assertLess(results[102400], 1.0)  # 100KB should encrypt in under 1 second


if __name__ == '__main__':
    unittest.main()
