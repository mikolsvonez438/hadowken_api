# api/crypto_utils.py - Pure Python, no external dependencies
import os
import json
import base64
import hashlib
import hmac
import secrets

class PureEncryption:
    """
    Pure Python encryption using only standard library
    AES-256-CBC simulation using SHA-256 + XOR
    """
    
    def __init__(self):
        self.master_key = self._get_key()
        self.salt = os.environ.get('ENCRYPTION_SALT', 'netflix_checker_salt_v1')
    
    def _get_key(self):
        key = os.environ.get('API_ENCRYPTION_KEY')
        if not key:
            raise ValueError("API_ENCRYPTION_KEY required")
        # Add padding if needed
        padding_needed = 4 - len(key) % 4 if len(key) % 4 else 0
        key += '=' * padding_needed
        return base64.urlsafe_b64decode(key)
    
    def _derive_key(self, field_name: str) -> bytes:
        """HKDF-like key derivation"""
        info = f"{self.salt}:{field_name}".encode()
        prk = hmac.new(self.master_key, info, hashlib.sha256).digest()
        return hashlib.sha256(prk + info).digest()
    
    def _encrypt_block(self, key: bytes, block: bytes, counter: int) -> bytes:
        """Encrypt a single block using key derivation"""
        counter_bytes = counter.to_bytes(16, 'big')
        # Use SHA-256 to generate keystream
        keystream = hashlib.sha256(key + counter_bytes).digest()
        # XOR with plaintext (use only needed bytes)
        return bytes(b ^ keystream[i] for i, b in enumerate(block))
    
    def encrypt_field(self, plaintext: str, field_name: str = "default") -> dict:
        """Encrypt field using custom AES-like construction"""
        if not plaintext:
            return {"value": "", "encrypted": False}
        
        try:
            key = self._derive_key(field_name)
            iv = secrets.token_bytes(16)
            data = plaintext.encode('utf-8')
            
            # Pad to 16-byte boundary
            pad_len = 16 - (len(data) % 16) if len(data) % 16 else 0
            data += bytes([pad_len] * pad_len)
            
            # CTR mode encryption
            ciphertext = bytearray()
            for i in range(0, len(data), 16):
                block = data[i:i+16]
                encrypted_block = self._encrypt_block(key, block, i // 16)
                ciphertext.extend(encrypted_block)
            
            # HMAC for authentication
            tag = hmac.new(key, iv + bytes(ciphertext), hashlib.sha256).digest()[:16]
            
            return {
                "v": base64.b64encode(bytes(ciphertext)).decode('utf-8'),
                "i": base64.b64encode(iv).decode('utf-8'),
                "t": base64.b64encode(tag).decode('utf-8'),
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
