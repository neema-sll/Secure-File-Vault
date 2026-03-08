import unittest
import os
import tempfile
import shutil
import json
import time
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import sys

# Add the src directory to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from client import SecureVaultClient, ClientError
from encryptor import FileEncryptor

class TestSecureVaultClient(unittest.TestCase):
    """Test cases for SecureVaultClient class."""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Create temporary directories
        self.test_dir = tempfile.mkdtemp()
        self.vault_dir = Path(self.test_dir) / "vault"
        self.vault_dir.mkdir()
        self.config_dir = Path(self.test_dir) / "config"
        self.config_dir.mkdir()
        
        # Create test files
        self.test_file = Path(self.test_dir) / "test.txt"
        self.test_file.write_text("This is test content for client operations.")
        
        self.test_file2 = Path(self.test_dir) / "test2.txt"
        self.test_file2.write_text("Another test file for batch operations.")
        
        # Create subdirectory with test files
        self.test_subdir = Path(self.test_dir) / "subdir"
        self.test_subdir.mkdir()
        self.subdir_file = self.test_subdir / "subfile.txt"
        self.subdir_file.write_text("File in subdirectory.")
        
        # Initialize client with test configuration
        self.config = {
            'vault_path': str(self.vault_dir),
            'config_path': str(self.config_dir / 'client_config.json'),
            'key_file': str(self.config_dir / 'master.key'),
            'default_algorithm': 'AES-256-GCM',
            'compression_enabled': True,
            'verify_integrity': True
        }
        
        self.client = SecureVaultClient(self.config)
        
        # Create a password for testing
        self.test_password = "SecureVaultPassword123!"
    
    def tearDown(self):
        """Clean up test fixtures after each test method."""
        shutil.rmtree(self.test_dir)
    
    def test_initialize_vault(self):
        """Test vault initialization."""
        # Initialize vault
        result = self.client.initialize_vault(self.test_password)
        
        self.assertTrue(result)
        self.assertTrue(self.client.initialized)
        
        # Check that vault directory was created
        self.assertTrue(self.vault_dir.exists())
        
        # Check that master key was created and encrypted
        key_file = Path(self.config['key_file'])
        self.assertTrue(key_file.exists())
        
        # Check that config file was created
        config_file = Path(self.config['config_path'])
        self.assertTrue(config_file.exists())
        
        # Verify config contents
        with open(config_file, 'r') as f:
            saved_config = json.load(f)
            self.assertEqual(saved_config['vault_path'], str(self.vault_dir))
            self.assertEqual(saved_config['default_algorithm'], 'AES-256-GCM')
    
    def test_unlock_vault(self):
        """Test vault unlocking."""
        # Initialize vault first
        self.client.initialize_vault(self.test_password)
        
        # Create a new client instance to test unlocking
        new_client = SecureVaultClient(self.config)
        
        # Unlock vault
        result = new_client.unlock_vault(self.test_password)
        
        self.assertTrue(result)
        self.assertTrue(new_client.unlocked)
        self.assertIsNotNone(new_client.master_key)
        
        # Test unlock with wrong password
        with self.assertRaises(ClientError):
            new_client.unlock_vault("WrongPassword123!")
    
    def test_lock_vault(self):
        """Test vault locking."""
        # Initialize and unlock vault
        self.client.initialize_vault(self.test_password)
        self.client.unlock_vault(self.test_password)
        
        # Lock vault
        result = self.client.lock_vault()
        
        self.assertTrue(result)
        self.assertFalse(self.client.unlocked)
        self.assertIsNone(self.client.master_key)
    
    def test_store_file(self):
        """Test storing a single file in the vault."""
        # Initialize and unlock vault
        self.client.initialize_vault(self.test_password)
        self.client.unlock_vault(self.test_password)
        
        # Store file
        vault_path = self.client.store_file(
            self.test_file,
            encrypt=True,
            compress=True,
            tags=['test', 'important']
        )
        
        self.assertIsNotNone(vault_path)
        
        # Check that file exists in vault
        stored_path = self.vault_dir / Path(vault_path).name
        self.assertTrue(stored_path.exists())
        
        # Check that metadata was created
        metadata_path = stored_path.with_suffix('.meta')
        self.assertTrue(metadata_path.exists())
        
        # Verify metadata
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
            self.assertEqual(metadata['original_name'], 'test.txt')
            self.assertEqual(metadata['encrypted'], True)
            self.assertEqual(metadata['compressed'], True)
            self.assertEqual(set(metadata['tags']), {'test', 'important'})
    
    def test_retrieve_file(self):
        """Test retrieving a file from the vault."""
        # Initialize and unlock vault
        self.client.initialize_vault(self.test_password)
        self.client.unlock_vault(self.test_password)
        
        # Store file
        vault_path = self.client.store_file(self.test_file)
        
        # Retrieve file
        retrieved_path = Path(self.test_dir) / "retrieved.txt"
        result = self.client.retrieve_file(
            Path(vault_path).name,
            retrieved_path
        )
        
        self.assertTrue(result)
        self.assertTrue(retrieved_path.exists())
        
        # Verify content
        original_content = self.test_file.read_text()
        retrieved_content = retrieved_path.read_text()
        self.assertEqual(original_content, retrieved_content)
    
    def test_delete_file(self):
        """Test deleting a file from the vault."""
        # Initialize and unlock vault
        self.client.initialize_vault(self.test_password)
        self.client.unlock_vault(self.test_password)
        
        # Store file
        vault_path = self.client.store_file(self.test_file)
        filename = Path(vault_path).name
        
        # Delete file
        result = self.client.delete_file(filename)
        
        self.assertTrue(result)
        
        # Check that file and metadata are gone
        stored_path = self.vault_dir / filename
        metadata_path = stored_path.with_suffix('.meta')
        self.assertFalse(stored_path.exists())
        self.assertFalse(metadata_path.exists())
    
    def test_list_files(self):
        """Test listing files in the vault."""
        # Initialize and unlock vault
        self.client.initialize_vault(self.test_password)
        self.client.unlock_vault(self.test_password)
        
        # Store multiple files
        self.client.store_file(self.test_file, tags=['tag1'])
        self.client.store_file(self.test_file2, tags=['tag2'])
        self.client.store_file(self.subdir_file, tags=['tag1', 'tag2'])
        
        # List all files
        files = self.client.list_files()
        self.assertEqual(len(files), 3)
        
        # List files by tag
        tag1_files = self.client.list_files(tag='tag1')
        self.assertEqual(len(tag1_files), 2)
        
        tag2_files = self.client.list_files(tag='tag2')
        self.assertEqual(len(tag2_files), 2)
        
        # Verify file information
        for file_info in files:
            self.assertIn('name', file_info)
            self.assertIn('size', file_info)
            self.assertIn('created', file_info)
            self.assertIn('tags', file_info)
    
    def test_search_files(self):
        """Test searching for files."""
        # Initialize and unlock vault
        self.client.initialize_vault(self.test_password)
        self.client.unlock_vault(self.test_password)
        
        # Store files with metadata
        self.client.store_file(
            self.test_file,
            metadata={'author': 'John Doe', 'project': 'Alpha'}
        )
        self.client.store_file(
            self.test_file2,
            metadata={'author': 'Jane Smith', 'project': 'Beta'}
        )
        
        # Search by metadata
        results = self.client.search_files({'author': 'John Doe'})
        self.assertEqual(len(results), 1)
        
        # Search by filename pattern
        results = self.client.search_files(name_pattern='*test*')
        self.assertEqual(len(results), 2)
    
    def test_batch_operations(self):
        """Test batch operations."""
        # Initialize and unlock vault
        self.client.initialize_vault(self.test_password)
        self.client.unlock_vault(self.test_password)
        
        # Batch store
        files_to_store = [self.test_file, self.test_file2, self.subdir_file]
        results = self.client.batch_store(files_to_store)
        
        self.assertEqual(len(results['success']), 3)
        self.assertEqual(len(results['failed']), 0)
        
        # Batch retrieve
        retrieve_dir = Path(self.test_dir) / "batch_retrieve"
        retrieve_dir.mkdir()
        
        results = self.client.batch_retrieve(
            [Path(f).name for f in results['success']],
            retrieve_dir
        )
        
        self.assertEqual(len(results['success']), 3)
        
        # Verify retrieved files
        for i, original in enumerate(files_to_store):
            retrieved = retrieve_dir / original.name
            self.assertTrue(retrieved.exists())
            self.assertEqual(
                original.read_text(),
                retrieved.read_text()
            )
        
        # Batch delete
        results = self.client.batch_delete([Path(f).name for f in files_to_store])
        self.assertEqual(len(results['success']), 3)
        
        # Verify deletion
        self.assertEqual(len(self.client.list_files()), 0)
    
    def test_file_versioning(self):
        """Test file versioning functionality."""
        # Initialize and unlock vault
        self.client.initialize_vault(self.test_password)
        self.client.unlock_vault(self.test_password)
        
        # Store initial version
        vault_path1 = self.client.store_file(self.test_file)
        filename = Path(vault_path1).name
        
        # Modify and store new version
        self.test_file.write_text("Updated content for version 2")
        vault_path2 = self.client.store_file(
            self.test_file,
            version_of=filename
        )
        
        # Get version history
        versions = self.client.get_file_versions(filename)
        self.assertEqual(len(versions), 2)
        
        # Retrieve specific version
        retrieved_v1 = Path(self.test_dir) / "retrieved_v1.txt"
        self.client.retrieve_version(filename, 1, retrieved_v1)
        
        self.assertEqual(
            retrieved_v1.read_text(),
            "This is test content for client operations."
        )
        
        # Retrieve latest version
        retrieved_v2 = Path(self.test_dir) / "retrieved_v2.txt"
        self.client.retrieve_file(filename, retrieved_v2)
        
        self.assertEqual(
            retrieved_v2.read_text(),
            "Updated content for version 2"
        )
    
    def test_file_sharing(self):
        """Test file sharing functionality."""
        # Initialize and unlock vault
        self.client.initialize_vault(self.test_password)
        self.client.unlock_vault(self.test_password)
        
        # Store file
        vault_path = self.client.store_file(self.test_file)
        filename = Path(vault_path).name
        
        # Generate share link
        share_token = self.client.create_share_link(
            filename,
            expires_in=3600,  # 1 hour
            max_access_count=5
        )
        
        self.assertIsNotNone(share_token)
        
        # Verify share link exists
        share_info = self.client.get_share_info(share_token)
        self.assertEqual(share_info['filename'], filename)
        self.assertFalse(share_info['expired'])
        self.assertEqual(share_info['access_count'], 0)
        
        # Access shared file (simulate another client)
        shared_content = self.client.access_shared_file(share_token)
        self.assertIsNotNone(shared_content)
        
        # Verify access count increased
        share_info = self.client.get_share_info(share_token)
        self.assertEqual(share_info['access_count'], 1)
        
        # Revoke share
        result = self.client.revoke_share(share_token)
        self.assertTrue(result)
        
        # Attempt to access revoked share
        with self.assertRaises(ClientError):
            self.client.access_shared_file(share_token)
    
    def test_backup_and_restore(self):
        """Test vault backup and restore functionality."""
        # Initialize and unlock vault
        self.client.initialize_vault(self.test_password)
        self.client.unlock_vault(self.test_password)
        
        # Store some files
        self.client.store_file(self.test_file)
        self.client.store_file(self.test_file2)
        
        # Create backup
        backup_dir = Path(self.test_dir) / "backup"
        backup_dir.mkdir()
        
        backup_result = self.client.create_backup(backup_dir)
        self.assertTrue(backup_result['success'])
        self.assertEqual(backup_result['file_count'], 2)
        
        # Delete files from vault
        self.client.delete_all_files()
        self.assertEqual(len(self.client.list_files()), 0)
        
        # Restore from backup
        restore_result = self.client.restore_from_backup(
            backup_dir / "vault_backup.zip",
            self.test_password
        )
        
        self.assertTrue(restore_result['success'])
        self.assertEqual(restore_result['file_count'], 2)
        
        # Verify restored files
        files = self.client.list_files()
        self.assertEqual(len(files), 2)
    
    def test_audit_logging(self):
        """Test audit logging functionality."""
        # Initialize and unlock vault
        self.client.initialize_vault(self.test_password)
        self.client.unlock_vault(self.test_password)
        
        # Perform operations
        self.client.store_file(self.test_file)
        self.client.store_file(self.test_file2)
        self.client.list_files()
        
        # Get audit logs
        logs = self.client.get_audit_logs(
            start_time=time.time() - 3600,
            end_time=time.time() + 3600
        )
        
        self.assertGreaterEqual(len(logs), 3)
        
        # Verify log entries
        operations = [log['operation'] for log in logs]
        self.assertIn('store_file', operations)
        self.assertIn('list_files', operations)
        
        # Test log filtering by user
        user_logs = self.client.get_audit_logs(user='test_user')
        # Should return logs for test operations
    
    def test_quota_management(self):
        """Test storage quota management."""
        # Initialize with quota
        self.config['quota_bytes'] = 1024 * 1024  # 1MB quota
        client = SecureVaultClient(self.config)
        
        client.initialize_vault(self.test_password)
        client.unlock_vault(self.test_password)
        
        # Check initial quota
        quota_info = client.get_quota_info()
        self.assertEqual(quota_info['quota_bytes'], 1024 * 1024)
        self.assertEqual(quota_info['used_bytes'], 0)
        
        # Store a small file
        client.store_file(self.test_file)
        
        # Update quota info
        quota_info = client.get_quota_info()
        self.assertGreater(quota_info['used_bytes'], 0)
        self.assertLess(quota_info['used_bytes'], 1024 * 1024)
        
        # Try to exceed quota (would need large file)
        # This test would require a file larger than remaining quota
    
    def test_concurrent_access(self):
        """Test concurrent access to the vault."""
        import threading
        
        # Initialize and unlock vault
        self.client.initialize_vault(self.test_password)
        self.client.unlock_vault(self.test_password)
        
        results = []
        errors = []
        
        def concurrent_store(file_num):
            try:
                # Create a unique file for this thread
                thread_file = Path(self.test_dir) / f"thread_{file_num}.txt"
                thread_file.write_text(f"Thread {file_num} content")
                
                # Store file
                result = self.client.store_file(thread_file)
                results.append((file_num, True, result))
            except Exception as e:
                errors.append((file_num, str(e)))
        
        # Run concurrent operations
        threads = []
        for i in range(10):
            t = threading.Thread(target=concurrent_store, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Verify results
        self.assertEqual(len(errors), 0)
        self.assertEqual(len(results), 10)
        self.assertEqual(len(self.client.list_files()), 10)
    
    def test_error_handling(self):
        """Test error handling in various scenarios."""
        # Initialize vault but don't unlock
        self.client.initialize_vault(self.test_password)
        
        # Try operations without unlocking
        with self.assertRaises(ClientError):
            self.client.store_file(self.test_file)
        
        with self.assertRaises(ClientError):
            self.client.list_files()
        
        # Unlock vault
        self.client.unlock_vault(self.test_password)
        
        # Try to store non-existent file
        with self.assertRaises(FileNotFoundError):
            self.client.store_file(Path(self.test_dir) / "nonexistent.txt")
        
        # Try to retrieve non-existent file
        with self.assertRaises(ClientError):
            self.client.retrieve_file("nonexistent.enc", "output.txt")
        
        # Try to delete non-existent file
        with self.assertRaises(ClientError):
            self.client.delete_file("nonexistent.enc")
    
    def test_configuration_persistence(self):
        """Test that configuration persists correctly."""
        # Initialize vault
        self.client.initialize_vault(self.test_password)
        
        # Modify configuration
        self.client.set_config('compression_enabled', False)
        self.client.set_config('default_algorithm', 'AES-256-CBC')
        
        # Create new client instance
        new_client = SecureVaultClient(self.config)
        
        # Verify configuration was loaded
        self.assertEqual(
            new_client.get_config('compression_enabled'),
            False
        )
        self.assertEqual(
            new_client.get_config('default_algorithm'),
            'AES-256-CBC'
        )
    
    def test_compression_ratio(self):
        """Test compression effectiveness."""
        # Initialize and unlock vault
        self.client.initialize_vault(self.test_password)
        self.client.unlock_vault(self.test_password)
        
        # Create highly compressible file
        compressible_file = Path(self.test_dir) / "compressible.txt"
        compressible_file.write_text("A" * 10000)  # 10KB of repeated 'A'
        
        # Store with compression
        vault_path = self.client.store_file(
            compressible_file,
            compress=True
        )
        
        # Get file info
        file_info = self.client.get_file_info(Path(vault_path).name)
        
        # Calculate compression ratio
        original_size = compressible_file.stat().st_size
        stored_size = file_info['stored_size']
        ratio = original_size / stored_size
        
        # Compression should achieve good ratio for repeated data
        self.assertGreater(ratio, 5)  # At least 5:1 compression
    
    def test_integrity_verification(self):
        """Test file integrity verification."""
        # Initialize and unlock vault
        self.client.initialize_vault(self.test_password)
        self.client.unlock_vault(self.test_password)
        
        # Store file
        vault_path = self.client.store_file(self.test_file)
        filename = Path(vault_path).name
        
        # Verify integrity
        is_valid = self.client.verify_integrity(filename)
        self.assertTrue(is_valid)
        
        # Corrupt the stored file
        stored_file = self.vault_dir / filename
        with open(stored_file, 'r+b') as f:
            f.seek(100)
            f.write(b'X')
        
        # Verify integrity should fail
        is_valid = self.client.verify_integrity(filename)
        self.assertFalse(is_valid)


if __name__ == '__main__':
    unittest.main()
