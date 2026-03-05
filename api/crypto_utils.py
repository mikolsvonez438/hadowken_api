import os
import json
import base64
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

class DataEncryption:
    """
    Encryption utility for API responses
    Uses AES-256-GCM for authenticated encryption
    """
    
    def __init__(self):
        # Master key from environment (32 bytes for AES-256)
        self.master_key = self._get_or_create_key()
        self.salt = os.environ.get('ENCRYPTION_SALT', 'netflix_checker_salt_v1')
        
    def _get_or_create_key(self):
        """Get encryption key from environment or generate new one"""
        key = os.environ.get('API_ENCRYPTION_KEY')
        if not key:
            # Generate a new key if not exists (store this in env!)
            key = base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256)).decode()
            print(f"WARNING: Generated new encryption key. Store this in API_ENCRYPTION_KEY: {key}")
        return base64.urlsafe_b64decode(key.encode())
    
    def derive_key(self, context: str) -> bytes:
        """Derive context-specific key from master key"""
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt.encode(),
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.master_key + context.encode())
    
    def encrypt_field(self, plaintext: str, field_name: str = "default") -> dict:
        """
        Encrypt a single field and return encrypted payload
        Returns dict with: ciphertext (base64), iv (base64), tag (base64), field
        """
        if not plaintext:
            return {"value": "", "encrypted": False}
            
        try:
            # Derive field-specific key
            key = self.derive_key(field_name)
            
            # Generate random IV
            iv = secrets.token_bytes(12)  # 96 bits for GCM
            
            # Create cipher and encrypt
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)
            
            # Split ciphertext and auth tag (last 16 bytes)
            tag = ciphertext[-16:]
            encrypted_data = ciphertext[:-16]
            
            return {
                "v": base64.b64encode(encrypted_data).decode('utf-8'),
                "i": base64.b64encode(iv).decode('utf-8'),
                "t": base64.b64encode(tag).decode('utf-8'),
                "f": field_name,
                "e": True  # encrypted flag
            }
        except Exception as e:
            print(f"Encryption error for field {field_name}: {e}")
            return {"value": plaintext, "encrypted": False, "error": str(e)}
    
    def encrypt_response_data(self, data: dict, sensitive_fields: list = None) -> dict:
        """
        Encrypt specific fields in a response object
        Common sensitive fields: email, token, netflix_id, login_urls
        """
        if sensitive_fields is None:
            sensitive_fields = ['email', 'token', 'netflix_id', 'login_urls', 'cookie_data']
        
        if not isinstance(data, dict):
            return data
            
        encrypted_data = {}
        
        for key, value in data.items():
            if key in sensitive_fields and value:
                if key == 'login_urls' and isinstance(value, dict):
                    # Encrypt each URL in login_urls
                    encrypted_urls = {}
                    for url_key, url_value in value.items():
                        if url_value:
                            encrypted_urls[url_key] = self.encrypt_field(url_value, f"login_url_{url_key}")
                        else:
                            encrypted_urls[url_key] = {"value": "", "encrypted": False}
                    encrypted_data[key] = encrypted_urls
                else:
                    encrypted_data[key] = self.encrypt_field(str(value), key)
            elif isinstance(value, dict):
                # Recursively encrypt nested dicts
                encrypted_data[key] = self.encrypt_response_data(value, sensitive_fields)
            elif isinstance(value, list):
                # Handle lists (encrypt dict items, pass through others)
                encrypted_list = []
                for item in value:
                    if isinstance(item, dict):
                        encrypted_list.append(self.encrypt_response_data(item, sensitive_fields))
                    else:
                        encrypted_list.append(item)
                encrypted_data[key] = encrypted_list
            else:
                encrypted_data[key] = value
                
        return encrypted_data
    
    def decrypt_field(self, encrypted_payload: dict) -> str:
        """Decrypt a single field (for internal use if needed)"""
        if not encrypted_payload.get("e"):
            return encrypted_payload.get("value", "")
            
        try:
            key = self.derive_key(encrypted_payload["f"])
            encrypted_data = base64.b64decode(encrypted_payload["v"])
            iv = base64.b64decode(encrypted_payload["i"])
            tag = base64.b64decode(encrypted_payload["t"])
            
            # Reconstruct ciphertext + tag
            ciphertext = encrypted_data + tag
            
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
            return plaintext.decode('utf-8')
        except Exception as e:
            print(f"Decryption error: {e}")
            return "[decryption_failed]"

# Global instance
crypto = DataEncryption()

def encrypt_api_response(data: dict, sensitive_fields: list = None) -> dict:
    """Helper function to encrypt API response data"""
    return crypto.encrypt_response_data(data, sensitive_fields)

def create_encrypted_wrapper(data: dict, status: str = "success", message: str = None) -> dict:
    """Create standard API response wrapper with encrypted data"""
    response = {
        "status": status,
        "encrypted": True,
        "version": "1.0",
        "data": encrypt_api_response(data) if data else {}
    }
    if message:
        response["message"] = message
    return response
