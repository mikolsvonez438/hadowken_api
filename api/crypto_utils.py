# api/crypto_utils.py - PyCryptodome version
import os
import json
import base64
import hashlib
import hmac
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class PureEncryption:
    def __init__(self):
        self.master_key = self._get_key()
        self.salt = os.environ.get('ENCRYPTION_SALT', 'netflix_checker_salt_v1')
    
    def _get_key(self):
        key = os.environ.get('API_ENCRYPTION_KEY')
        if not key:
            raise ValueError("API_ENCRYPTION_KEY required")
        # Ensure 32 bytes for AES-256
        key_bytes = base64.urlsafe_b64decode(key + '=' * (4 - len(key) % 4))
        return hashlib.sha256(key_bytes).digest()[:32]
    
    def _derive_key(self, field_name: str) -> bytes:
        """Derive field-specific key"""
        info = f"{self.salt}:{field_name}".encode()
        return hashlib.sha256(self.master_key + info).digest()
    
    def encrypt_field(self, plaintext: str, field_name: str = "default") -> dict:
        if not plaintext:
            return {"value": "", "encrypted": False}
        
        try:
            key = self._derive_key(field_name)
            iv = secrets.token_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded = pad(plaintext.encode('utf-8'), AES.block_size)
            ciphertext = cipher.encrypt(padded)
            
            return {
                "v": base64.b64encode(ciphertext).decode('utf-8'),
                "i": base64.b64encode(iv).decode('utf-8'),
                "t": base64.b64encode(hashlib.sha256(ciphertext).digest()[:16]).decode('utf-8'),
                "f": field_name,
                "e": True
            }
        except Exception as e:
            print(f"Encryption error: {e}")
            return {"value": plaintext, "encrypted": False}
    
    def encrypt_response_data(self, data: dict, sensitive_fields: list = None) -> dict:
        """Encrypt sensitive fields"""
        if sensitive_fields is None:
            sensitive_fields = ['email', 'token', 'netflix_id', 'login_urls', 'cookie_data']
        
        if not isinstance(data, dict):
            return data
        
        encrypted = {}
        for key, value in data.items():
            if key in sensitive_fields and value:
                if key == 'login_urls' and isinstance(value, dict):
                    encrypted[key] = {
                        k: self.encrypt_field(str(v), f"login_url_{k}") if v else {"value": "", "encrypted": False}
                        for k, v in value.items()
                    }
                else:
                    encrypted[key] = self.encrypt_field(str(value), key)
            elif isinstance(value, dict):
                encrypted[key] = self.encrypt_response_data(value, sensitive_fields)
            elif isinstance(value, list):
                encrypted[key] = [
                    self.encrypt_response_data(item, sensitive_fields) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                encrypted[key] = value
        
        return encrypted

# Create global instance
crypto = PureEncryption()

# Standalone function exports
def encrypt_api_response(data: dict, sensitive_fields: list = None) -> dict:
    """Encrypt API response data using the global crypto instance"""
    return crypto.encrypt_response_data(data, sensitive_fields)

def create_encrypted_wrapper(data: dict, status: str = "success", message: str = None) -> dict:
    """Create a standard encrypted response wrapper"""
    return {
        "status": status,
        "encrypted": True,
        "version": "1.0",
        "data": crypto.encrypt_response_data(data) if data else {},
        "message": message
    }
