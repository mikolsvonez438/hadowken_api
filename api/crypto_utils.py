import os
import json
import base64
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import hashlib
import hmac

class DataEncryption:
    """
    Encryption utility using PyCryptodome (Vercel-compatible)
    Uses AES-256-CBC with HMAC-SHA256 for authentication
    """
    
    def __init__(self):
        self.master_key = self._get_or_create_key()
        self.salt = os.environ.get('ENCRYPTION_SALT', 'netflix_checker_salt_v1')
        
    def _get_or_create_key(self):
        """Get encryption key from environment"""
        key = os.environ.get('API_ENCRYPTION_KEY')
        if not key:
            # For Vercel, you MUST set this in environment variables
            raise ValueError("API_ENCRYPTION_KEY environment variable is required")
        # Decode base64 key (ensure proper padding)
        key += '=' * (4 - len(key) % 4) if len(key) % 4 else ''
        return base64.urlsafe_b64decode(key)
    
    def derive_key(self, context: str) -> bytes:
        """Derive context-specific key from master key"""
        return PBKDF2(
            self.master_key + context.encode(),
            self.salt.encode(),
            dkLen=32,  # 256 bits
            count=100000,
            hmac_hash_module=hashlib.sha256
        )
    
    def encrypt_field(self, plaintext: str, field_name: str = "default") -> dict:
        """
        Encrypt a single field
        Returns: {v: ciphertext, i: iv, t: hmac, f: field, e: True}
        """
        if not plaintext:
            return {"value": "", "encrypted": False}
            
        try:
            # Derive field-specific key
            key = self.derive_key(field_name)
            
            # Generate random IV
            iv = secrets.token_bytes(16)  # 128 bits for CBC
            
            # Create cipher and encrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
            
            # Generate HMAC for authentication
            hmac_val = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()[:16]
            
            return {
                "v": base64.b64encode(ciphertext).decode('utf-8'),
                "i": base64.b64encode(iv).decode('utf-8'),
                "t": base64.b64encode(hmac_val).decode('utf-8'),
                "f": field_name,
                "e": True
            }
        except Exception as e:
            print(f"Encryption error for field {field_name}: {e}")
            return {"value": plaintext, "encrypted": False}
    
    def decrypt_field(self, encrypted_payload: dict) -> str:
        """Decrypt a single field"""
        if not encrypted_payload.get("e"):
            return encrypted_payload.get("value", "")
            
        try:
            key = self.derive_key(encrypted_payload["f"])
            ciphertext = base64.b64decode(encrypted_payload["v"])
            iv = base64.b64decode(encrypted_payload["i"])
            tag = base64.b64decode(encrypted_payload["t"])
            
            # Verify HMAC
            expected_hmac = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()[:16]
            if not hmac.compare_digest(expected_hmac, tag):
                raise ValueError("HMAC verification failed")
            
            # Decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return plaintext.decode('utf-8')
        except Exception as e:
            print(f"Decryption error: {e}")
            return "[decryption_failed]"
    
    def encrypt_response_data(self, data: dict, sensitive_fields: list = None) -> dict:
        """Encrypt specific fields in a response object"""
        if sensitive_fields is None:
            sensitive_fields = ['email', 'token', 'netflix_id', 'login_urls', 'cookie_data']
        
        if not isinstance(data, dict):
            return data
            
        encrypted_data = {}
        
        for key, value in data.items():
            if key in sensitive_fields and value:
                if key == 'login_urls' and isinstance(value, dict):
                    encrypted_urls = {}
                    for url_key, url_value in value.items():
                        if url_value:
                            encrypted_urls[url_key] = self.encrypt_field(str(url_value), f"login_url_{url_key}")
                        else:
                            encrypted_urls[url_key] = {"value": "", "encrypted": False}
                    encrypted_data[key] = encrypted_urls
                else:
                    encrypted_data[key] = self.encrypt_field(str(value), key)
            elif isinstance(value, dict):
                encrypted_data[key] = self.encrypt_response_data(value, sensitive_fields)
            elif isinstance(value, list):
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

# Global instance
crypto = DataEncryption()

def encrypt_api_response(data: dict, sensitive_fields: list = None) -> dict:
    return crypto.encrypt_response_data(data, sensitive_fields)

def create_encrypted_wrapper(data: dict, status: str = "success", message: str = None) -> dict:
    response = {
        "status": status,
        "encrypted": True,
        "version": "1.0",
        "data": encrypt_api_response(data) if data else {}
    }
    if message:
        response["message"] = message
    return response
