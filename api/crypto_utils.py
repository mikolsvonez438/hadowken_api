from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

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
