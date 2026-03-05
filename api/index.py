from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from functools import wraps
import os
import re
import json
import requests
import zipfile
import urllib.parse
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import logging
import tempfile
import shutil
import hashlib
from datetime import datetime
from supabase import create_client, Client
from gotrue.errors import AuthApiError
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or os.urandom(32)

# CORS - Allow your frontend
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5000",
    "http://localhost",
    "https://hakdowken.vercel.app",
]

CORS(app, 
    resources={
        r"/api/*": {
            "origins": ALLOWED_ORIGINS,
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization", "X-Requested-With", "Accept", "Origin"],
            "supports_credentials": True,
            "max_age": 86400
        }
    },
    supports_credentials=True
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TEMP_DIR = "/tmp"

# Supabase setup
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_SERVICE_KEY = os.environ.get('SUPABASE_SERVICE_KEY')

if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
    logger.warning("Supabase credentials not configured!")

try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY) if SUPABASE_URL and SUPABASE_SERVICE_KEY else None
except Exception as e:
    logger.error(f"Supabase init failed: {e}")
    supabase = None

# ============================================
# CORS Handlers
# ============================================

@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = make_response()
        origin = request.headers.get('Origin', '')
        if origin in ALLOWED_ORIGINS:
            response.headers.add("Access-Control-Allow-Origin", origin)
        else:
            response.headers.add("Access-Control-Allow-Origin", ALLOWED_ORIGINS[0])
        response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, Origin")
        response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        response.headers.add("Access-Control-Max-Age", "86400")
        return response, 204

@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    if origin and origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
    elif origin:
        response.headers['Access-Control-Allow-Origin'] = origin
    else:
        response.headers['Access-Control-Allow-Origin'] = ALLOWED_ORIGINS[0]
    
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Expose-Headers'] = 'Content-Type'
    return response

# ============================================
# Auth Helpers
# ============================================

def get_user_from_token(auth_header):
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    if not supabase:
        return None
    
    token = auth_header.split(' ')[1]
    try:
        user = supabase.auth.get_user(token)
        return user.user if user else None
    except:
        return None

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'OPTIONS':
            return make_response(), 204
            
        auth_header = request.headers.get('Authorization')
        user = get_user_from_token(auth_header)
        
        if not user:
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        
        return f(user, *args, **kwargs)
    return decorated_function

# ============================================
# Routes
# ============================================

@app.route('/')
def home():
    return jsonify({
        "status": "ok", 
        "message": "Netflix Cookie Checker API",
        "supabase_connected": supabase is not None
    })

@app.route('/api/health')
def health():
    return jsonify({
        "status": "ok",
        "supabase_connected": supabase is not None,
        "env_vars": {
            "SUPABASE_URL": bool(SUPABASE_URL),
            "SUPABASE_SERVICE_KEY": bool(SUPABASE_SERVICE_KEY),
            "FLASK_SECRET_KEY": bool(os.environ.get('FLASK_SECRET_KEY'))
        }
    })

@app.route('/api/test', methods=['GET', 'OPTIONS'])
def test():
    if request.method == 'OPTIONS':
        return '', 204
    return jsonify({"status": "ok", "message": "Test working", "auth_required": False})

@app.route('/api/auth/signup', methods=['POST', 'OPTIONS'])
def signup():
    if request.method == 'OPTIONS':
        return make_response(), 204
    
    if not supabase:
        return jsonify({'status': 'error', 'message': 'Database not configured'}), 500
    
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'status': 'error', 'message': 'Email and password required'}), 400
        
        auth_response = supabase.auth.sign_up({
            "email": email,
            "password": password
        })
        
        return jsonify({
            'status': 'success',
            'message': 'User created',
            'user': {
                'id': auth_response.user.id,
                'email': auth_response.user.email
            }
        })
    except AuthApiError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"Signup error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/auth/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return make_response(), 204
    
    if not supabase:
        return jsonify({'status': 'error', 'message': 'Database not configured'}), 500
    
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'status': 'error', 'message': 'Email and password required'}), 400
        
        auth_response = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password
        })
        
        # Get user profile
        try:
            profile = supabase.table('user_profiles').select('*').eq('id', auth_response.user.id).single().execute()
            is_premium = profile.data.get('is_premium', False) if profile.data else False
        except:
            is_premium = False
        
        # PLAIN TEXT RESPONSE (no encryption yet)
        return jsonify({
            'status': 'success',
            'session': {
                'access_token': auth_response.session.access_token,
                'refresh_token': auth_response.session.refresh_token,
                'expires_at': auth_response.session.expires_at
            },
            'user': {
                'id': auth_response.user.id,
                'email': auth_response.user.email,
                'is_premium': is_premium
            }
        })
        
    except AuthApiError as e:
        return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/auth/me', methods=['GET', 'OPTIONS'])
@require_auth
def get_current_user(user):
    if request.method == 'OPTIONS':
        return make_response(), 204
    
    try:
        profile = supabase.table('user_profiles').select('*').eq('id', user.id).single().execute()
        return jsonify({
            'status': 'success',
            'user': {
                'id': user.id,
                'email': user.email,
                'is_premium': profile.data.get('is_premium', False) if profile.data else False
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/auth/logout', methods=['POST', 'OPTIONS'])
@require_auth
def logout(user):
    if request.method == 'OPTIONS':
        return make_response(), 204
    
    try:
        supabase.auth.sign_out()
        return jsonify({'status': 'success', 'message': 'Logged out'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ============================================
# Netflix Check (Protected but no encryption)
# ============================================

@app.route('/api/check', methods=['POST', 'OPTIONS'])
@require_auth
def check_cookie(user):
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.get_json()
        content = data.get('content', '')
        mode = data.get('mode', 'check_only')
        
        if not content:
            return jsonify({'status': 'error', 'message': 'No content provided'}), 400
        
        # Simple mock check for now
        return jsonify({
            'status': 'success',
            'data': {
                'email': 'test@example.com',
                'country': 'US',
                'plan': 'Premium',
                'is_premium': True,
                'subscription_type': 'Premium',
                'mode': mode,
                'message': 'Cookie check working (mock data)'
            }
        })
        
    except Exception as e:
        logger.error(f"Check error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
