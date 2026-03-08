import unittest
import os
import tempfile
import shutil
import json
from pathlib import Path
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from client import SecureVaultClient, ClientError

class TestSecureVaultClient(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.vault_dir = Path(self.test_dir) / "vault"
        self.vault_dir.mkdir()
        
        self.config = {
            'vault_path': str(self.vault_dir),
            'config_path': str(self.test_dir / 'config.json'),
            'key_file': str(self.test_dir / 'master.key')
        }
        
        self.client = SecureVaultClient(self.config)
        self.test_file = Path(self.test_dir) / "test.txt"
        self.test_file.write_text("Test content")
        self.password = "test123"
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    def test_initialize_and_unlock(self):
        self.assertTrue(self.client.initialize_vault(self.password))
        self.assertTrue(self.client.unlock_vault(self.password))
        self.assertTrue(self.client.unlocked)
    
    def test_wrong_password_fails(self):
        self.client.initialize_vault(self.password)
        with self.assertRaises(ClientError):
            self.client.unlock_vault("wrong")
    
    def test_lock_vault(self):
        self.client.initialize_vault(self.password)
        self.client.unlock_vault(self.password)
        self.client.lock_vault()
        self.assertFalse(self.client.unlocked)
    
    def test_store_and_retrieve(self):
        self.client.initialize_vault(self.password)
        self.client.unlock_vault(self.password)
        
        vault_path = self.client.store_file(self.test_file)
        self.assertTrue(Path(vault_path).exists())
        
        retrieved = Path(self.test_dir) / "retrieved.txt"
        self.client.retrieve_file(Path(vault_path).name, retrieved)
        self.assertEqual(self.test_file.read_text(), retrieved.read_text())
    
    def test_delete_file(self):
        self.client.initialize_vault(self.password)
        self.client.unlock_vault(self.password)
        
        vault_path = self.client.store_file(self.test_file)
        filename = Path(vault_path).name
        
        self.client.delete_file(filename)
        self.assertFalse(Path(vault_path).exists())
        self.assertFalse(Path(vault_path).with_suffix('.meta').exists())
    
    def test_list_files(self):
        self.client.initialize_vault(self.password)
        self.client.unlock_vault(self.password)
        
        self.client.store_file(self.test_file, tags=['test'])
        files = self.client.list_files()
        
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]['tags'], ['test'])
    
    def test_batch_operations(self):
        self.client.initialize_vault(self.password)
        self.client.unlock_vault(self.password)
        
        file2 = Path(self.test_dir) / "test2.txt"
        file2.write_text("More content")
        
        results = self.client.batch_store([self.test_file, file2])
        self.assertEqual(len(results['success']), 2)
        
        files = self.client.list_files()
        self.assertEqual(len(files), 2)
    
    def test_quota(self):
        self.config['quota_bytes'] = 1024
        client = SecureVaultClient(self.config)
        client.initialize_vault(self.password)
        client.unlock_vault(self.password)
        
        quota = client.get_quota_info()
        self.assertEqual(quota['quota_bytes'], 1024)
        self.assertEqual(quota['used_bytes'], 0)
    
    def test_operations_without_unlock_fail(self):
        self.client.initialize_vault(self.password)
        
        with self.assertRaises(ClientError):
            self.client.store_file(self.test_file)
        
        with self.assertRaises(ClientError):
            self.client.list_files()

if __name__ == '__main__':
    unittest.main()
