from flask import request, g, jsonify, Response
import json
from functools import wraps
from .crypto_utils import encrypt_api_response, create_encrypted_wrapper

class EncryptionMiddleware:
    """
    Middleware to automatically encrypt sensitive API responses
    """
    
    SENSITIVE_ENDPOINTS = [
        '/api/check',
        '/api/batch-check',
        '/api/accounts',
        '/api/accounts/',
        '/api/auth/me',
    ]
    
    @staticmethod
    def should_encrypt_response(path: str) -> bool:
        """Check if endpoint should have encrypted responses"""
        for endpoint in EncryptionMiddleware.SENSITIVE_ENDPOINTS:
            if path.startswith(endpoint):
                return True
        return False
    
    @staticmethod
    def encrypt_json_response(response_data: dict, endpoint: str) -> dict:
        """Encrypt sensitive fields in JSON response"""
        # Determine which fields to encrypt based on endpoint
        sensitive_fields = ['email', 'token', 'netflix_id', 'login_urls', 'cookie_data']
        
        if 'batch' in endpoint:
            # Handle batch results array
            if 'results' in response_data:
                encrypted_results = []
                for result in response_data['results']:
                    if isinstance(result, dict) and 'data' in result:
                        result['data'] = encrypt_api_response(result['data'], sensitive_fields)
                    elif isinstance(result, dict):
                        encrypted_results.append(encrypt_api_response(result, sensitive_fields))
                    else:
                        encrypted_results.append(result)
                if encrypted_results:
                    response_data['results'] = encrypted_results
            elif 'data' in response_data:
                response_data['data'] = encrypt_api_response(response_data['data'], sensitive_fields)
        else:
            # Standard single object encryption
            if 'data' in response_data:
                response_data['data'] = encrypt_api_response(response_data['data'], sensitive_fields)
            else:
                # Wrap entire response if no data key
                response_data = create_encrypted_wrapper(response_data)
                
        return response_data

def init_encryption_middleware(app):
    """Initialize encryption middleware on Flask app"""
    
    @app.after_request
    def encrypt_response(response):
        # Only process JSON responses
        if not response.is_json:
            return response
            
        path = request.path
        
        # Check if this endpoint should be encrypted
        if not EncryptionMiddleware.should_encrypt_response(path):
            return response
            
        try:
            # Get response data
            response_data = response.get_json()
            
            # Skip if already encrypted or error response
            if not response_data or response_data.get('encrypted') or response.status_code >= 400:
                return response
            
            # Encrypt the response data
            encrypted_data = EncryptionMiddleware.encrypt_json_response(response_data, path)
            
            # Create new response with encrypted data
            new_response = jsonify(encrypted_data)
            new_response.status_code = response.status_code
            
            # Copy headers
            for key, value in response.headers:
                if key.lower() not in ['content-type', 'content-length']:
                    new_response.headers[key] = value
            
            return new_response
            
        except Exception as e:
            print(f"Encryption middleware error: {e}")
            return response
    
    return app

def require_encryption(f):
    """Decorator to force encryption on specific routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Set flag to indicate encryption required
        g.require_encryption = True
        return f(*args, **kwargs)
    return decorated_function
