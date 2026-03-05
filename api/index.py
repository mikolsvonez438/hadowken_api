from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import os
import json
from datetime import datetime

app = Flask(__name__)

# Simple CORS - allow all for now to test
CORS(app, supports_credentials=True)

@app.route('/')
def home():
    return jsonify({"status": "ok", "message": "API is running"})

@app.route('/api/health')
def health():
    return jsonify({
        "status": "ok",
        "env_vars": {
            "SUPABASE_URL": bool(os.environ.get('SUPABASE_URL')),
            "FLASK_SECRET_KEY": bool(os.environ.get('FLASK_SECRET_KEY'))
        }
    })

@app.route('/api/test', methods=['GET', 'OPTIONS'])
def test():
    if request.method == 'OPTIONS':
        return '', 204
    return jsonify({"status": "ok", "message": "Test endpoint working"})

@app.route('/api/auth/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        return response, 204
    
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        # Mock response for testing - no encryption, no database
        return jsonify({
            'status': 'success',
            'message': 'Login working (test mode)',
            'data': {
                'email': email,
                'token': 'test-token-12345',
                'is_premium': False
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
