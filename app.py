import os
import random
import re
import threading
import requests
import io
import boto3
import json
import pandas as pd
import subprocess
import filetype  # 🚀 Security: 100% Pure Python Malware Signature Checker (No Windows DLL Issues!)
from PIL import Image
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response, make_response, send_from_directory, send_file, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func, text
from sqlalchemy.orm import load_only  
from sqlalchemy.exc import IntegrityError # 🚀 Phase 4: Duplicate Game Handling
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache  
from flask_compress import Compress 
from apscheduler.schedulers.background import BackgroundScheduler
from flask_babel import Babel, _  # 🚀 Phase 2: Multi-Language SEO (i18n)
from deep_translator import GoogleTranslator # 🚀 PHASE 1: Auto-Translation Engine

try:
    from pywebpush import webpush, WebPushException
except ImportError:
    print("⚠️ pywebpush not installed. Push notifications broadcast will require it.")
    webpush = None

load_dotenv()
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# 🚀 VAPID Configuration for Push Notifications
VAPID_PUBLIC_KEY = os.getenv('VAPID_PUBLIC_KEY')
VAPID_PRIVATE_KEY = os.getenv('VAPID_PRIVATE_KEY')
VAPID_CLAIMS = {"sub": os.getenv('VAPID_CLAIMS', "mailto:admin@KixoGames.com")}

app = Flask(__name__)
Compress(app)
app.secret_key = os.getenv('SECRET_KEY')
IS_PRODUCTION = os.environ.get('FLASK_ENV') == 'production'

app.config.update(
    SESSION_COOKIE_SECURE=IS_PRODUCTION,    
    SESSION_COOKIE_HTTPONLY=True,           
    SESSION_COOKIE_SAMESITE='Lax',          
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30) 
)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 🚀 Phase 4: Poki-Style Major Languages Dictionary (24 Languages with Native Names & Flag Codes)
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['LANGUAGES'] = {
    'en': {'name': 'English', 'native': 'English', 'flag': 'us'},
    'es': {'name': 'Spanish', 'native': 'Español', 'flag': 'es'},
    'pt': {'name': 'Portuguese', 'native': 'Português', 'flag': 'br'},
    'fr': {'name': 'French', 'native': 'Français', 'flag': 'fr'},
    'de': {'name': 'German', 'native': 'Deutsch', 'flag': 'de'},
    'it': {'name': 'Italian', 'native': 'Italiano', 'flag': 'it'},
    'nl': {'name': 'Dutch', 'native': 'Nederlands', 'flag': 'nl'},
    'pl': {'name': 'Polish', 'native': 'Polski', 'flag': 'pl'},
    'ru': {'name': 'Russian', 'native': 'Русский', 'flag': 'ru'},
    'tr': {'name': 'Turkish', 'native': 'Türkçe', 'flag': 'tr'},
    'uk': {'name': 'Ukrainian', 'native': 'Українська', 'flag': 'ua'},
    'ro': {'name': 'Romanian', 'native': 'Română', 'flag': 'ro'},
    'cs': {'name': 'Czech', 'native': 'Čeština', 'flag': 'cz'},
    'sv': {'name': 'Swedish', 'native': 'Svenska', 'flag': 'se'},
    'id': {'name': 'Indonesian', 'native': 'Bahasa Indonesia', 'flag': 'id'},
    'ms': {'name': 'Malay', 'native': 'Bahasa Melayu', 'flag': 'my'},
    'tl': {'name': 'Tagalog', 'native': 'Tagalog', 'flag': 'ph'},
    'vi': {'name': 'Vietnamese', 'native': 'Tiếng Việt', 'flag': 'vn'},
    'hi': {'name': 'Hindi', 'native': 'हिन्दी', 'flag': 'in'},
    'bn': {'name': 'Bengali', 'native': 'বাংলা', 'flag': 'bd'},
    'ar': {'name': 'Arabic', 'native': 'عربي', 'flag': 'sa'},
    'ja': {'name': 'Japanese', 'native': '日本語', 'flag': 'jp'},
    'ko': {'name': 'Korean', 'native': '한국어', 'flag': 'kr'},
    'zh-CN': {'name': 'Chinese', 'native': '中文', 'flag': 'cn'} # 🚀 FIX: Updated to zh-CN
}

def get_locale():
    # 🚀 PHASE 4: Check if language is forced via URL prefix (e.g., /es/game/...)
    if 'lang' in g:
        return g.lang
        
    # 🚀 PHASE 4: Check User Cookie for Persistent Language (So reloads keep the same lang)
    cookie_lang = request.cookies.get('lang')
    if cookie_lang and cookie_lang in app.config['LANGUAGES']:
        return cookie_lang
        
    # Fallback to browser preferences if no prefix or cookie is set
    return request.accept_languages.best_match(app.config['LANGUAGES'].keys())

babel = Babel(app, locale_selector=get_locale)

# 🚀 Security: Max upload size limited to 5MB to prevent memory exhaustion (Trojan payload)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# 🚀 Security: Strict CSP Tuning to prevent XSS attacks (FIXED: Added cdnjs for SVG flags)
CSP = {
    'default-src': ["'self'"],
    'img-src': ["*", "data:", "blob:"],
    'media-src': ["*", "data:", "blob:"],
    'frame-src': ["*"],
    'script-src': ["'self'", "https://cdn.tailwindcss.com", "https://cdn.jsdelivr.net", "'unsafe-inline'"],
    'style-src': ["'self'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com", "'unsafe-inline'"],
    'font-src': ["*", "data:"],
    'connect-src': ["'self'", "https:", "http:"]
}
Talisman(app, content_security_policy=CSP, force_https=IS_PRODUCTION) 
limiter = Limiter(get_remote_address, app=app, default_limits=["5000 per day", "500 per hour"], storage_uri="memory://") 

# 🚀 PHASE 2: BILLION-USER SCALING (Auto-Switching Redis Cache)
redis_url = os.getenv('REDIS_URL')
if redis_url:
    # Use Enterprise Redis in Production
    cache_config = {"DEBUG": False, "CACHE_TYPE": "RedisCache", "CACHE_REDIS_URL": redis_url, "CACHE_DEFAULT_TIMEOUT": 300}
    print("🚀 Enterprise Redis Caching Enabled!")
else:
    # Use SimpleCache for Local Development
    cache_config = {"DEBUG": True, "CACHE_TYPE": "SimpleCache", "CACHE_DEFAULT_TIMEOUT": 300}
    print("⚠️ Using Local SimpleCache. Set REDIS_URL for production scaling.")

app.config.from_mapping(cache_config)
cache = Cache(app)

# ==========================================
# 🚀 PHASE 2: CLOUDFLARE R2 INITIALIZATION
# ==========================================
R2_ACCESS_KEY_ID = os.getenv('R2_ACCESS_KEY_ID')
R2_SECRET_ACCESS_KEY = os.getenv('R2_SECRET_ACCESS_KEY')
R2_ENDPOINT_URL = os.getenv('R2_ENDPOINT_URL')
R2_PUBLIC_URL = os.getenv('R2_PUBLIC_URL')
BUCKET_NAME = 'KixoGames-assets'

s3_client = boto3.client(
    's3',
    endpoint_url=R2_ENDPOINT_URL,
    aws_access_key_id=R2_ACCESS_KEY_ID,
    aws_secret_access_key=R2_SECRET_ACCESS_KEY,
    region_name='auto'
)

def slugify_filter(text_str): return re.sub(r'[\W_]+', '-', text_str.lower()).strip('-')
app.jinja_env.filters['slugify'] = slugify_filter

def format_views(num):
    if num >= 1_000_000_000_000: return f"{num / 1_000_000_000_000:.1f}T".replace('.0T', 'T')
    elif num >= 1_000_000_000: return f"{num / 1_000_000_000:.1f}B".replace('.0B', 'B')
    elif num >= 1_000_000: return f"{num / 1_000_000:.1f}M".replace('.0M', 'M')
    elif num >= 1_000: return f"{num / 1_000:.1f}K".replace('.0K', 'K')
    return str(num)
app.jinja_env.filters['format_views'] = format_views

# 🚀 PHASE 5: CrazyGames Mixed Badge Logic (Time + Views)
def get_game_badge(game_views, game_created_at):
    now = datetime.utcnow()
    created = game_created_at or (now - timedelta(days=2)) # fallback
    
    if now - created < timedelta(days=1):  
        return 'new'
    elif game_views >= 150:                
        return 'top'
    elif now - created < timedelta(days=3) and game_views >= 50: 
        return 'hot'
    
    return None

# ==========================================
# 🚀 PHASE 1: DYNAMIC TRANSLATION ENGINE (MASKING & ASYNC PROCESS)
# ==========================================
def apply_masking(text, game_name):
    """Protects Game Names, URLs, Studio Names and Key Controls from being translated."""
    if not text: return text, {}
    mapping = {}
    count = [0]
    
    def repl(match):
        ph = f"NOTRANS{count[0]}X"
        mapping[ph] = match.group(0)
        count[0] += 1
        return ph

    # 1. Mask Original Game Name
    if game_name:
        text = re.sub(re.escape(game_name), repl, text, flags=re.IGNORECASE)

    # 2. Mask URLs
    text = re.sub(r'https?://\S+', repl, text)

    # 3. Mask Global Controls (W, A, S, D, SPACE, etc.)
    keys_pattern = r'\b(W|A|S|D|SPACE|UP|DOWN|LEFT|RIGHT|ENTER|CLICK|MOUSE|SHIFT|CTRL|ALT|TAB|ESC)\b'
    text = re.sub(keys_pattern, repl, text, flags=re.IGNORECASE)

    return text, mapping

def remove_masking(text, mapping):
    """Restores protected keywords to the text after translation."""
    if not text: return text
    for ph, original in mapping.items():
        text = text.replace(ph, original)
    return text

def async_translate_and_save(game_id, data_dict, game_name):
    """Background worker to translate game text using Batch Translation to prevent Ban."""
    import time
    with app.app_context():
        try:
            # We skip English because the default data in Game is already English
            target_langs = [code for code in app.config['LANGUAGES'].keys() if code != 'en']
            
            for lang in target_langs:
                translated_data = {}
                translator = GoogleTranslator(source='auto', target=lang)
                
                # 🚀 ANTI-BAN: Prepare arrays for Batch Translation
                fields_list = []
                texts_list = []
                mappings_list = []
                
                for field, text_content in data_dict.items():
                    if not text_content:
                        translated_data[field] = ""
                        continue
                    
                    # Apply SEO Masking Algorithm
                    masked_text, mapping = apply_masking(text_content, game_name)
                    
                    fields_list.append(field)
                    texts_list.append(masked_text[:4999]) # Character Limit Failsafe
                    mappings_list.append(mapping)
                
                if texts_list:
                    try:
                        # 🚀 ANTI-BAN: 1 Request per language instead of 4! (Reduces API calls by 75%)
                        translated_batch = translator.translate_batch(texts_list)
                        
                        # Unmask Keywords and map back to fields
                        for i, field in enumerate(fields_list):
                            # Safe fallback in case batch translation returns None
                            trans_text = translated_batch[i] if translated_batch and i < len(translated_batch) else texts_list[i]
                            final_text = remove_masking(trans_text, mappings_list[i])
                            translated_data[field] = final_text
                            
                        time.sleep(2) # 🚀 ANTI-BAN: 2 sec delay = 0.5 requests per second (Google allows 5/sec)
                    except Exception as e:
                        print(f"Translation API error for {lang}: {e}")
                        # Fallback to original text if API fails completely
                        for i, field in enumerate(fields_list):
                            translated_data[field] = remove_masking(texts_list[i], mappings_list[i])
                        time.sleep(4) # 🚀 ANTI-BAN: Wait longer if Google gives a warning
                    
                # Save to GameTranslation Table
                new_trans = GameTranslation(
                    game_id=game_id,
                    language_code=lang,
                    description=translated_data.get('description', ''),
                    how_to_play=translated_data.get('how_to_play', ''),
                    controls=translated_data.get('controls', ''),
                    faqs=translated_data.get('faqs', '')
                )
                
                # 🚀 ENTERPRISE UPGRADE: Commit per language so frontend updates instantly!
                try:
                    db.session.add(new_trans)
                    db.session.commit()
                except Exception as db_err:
                    db.session.rollback()
            
            print(f"✅ [Auto-Translate] Successfully translated Game ID {game_id} into {len(target_langs)} languages.")
        except Exception as e:
            print(f"❌ [Auto-Translate] Failed for Game ID {game_id}: {e}")

# ==========================================
# 🚀 PHASE 2: LOCALIZATION HELPER
# ==========================================
def get_localized_game_data(game_obj, lang_code):
    """Fetches localized text for a game if available, otherwise falls back to English."""
    data = {
        'description': game_obj.description,
        'how_to_play': getattr(game_obj, 'how_to_play', ''),
        'controls': getattr(game_obj, 'controls', ''),
        'faqs': getattr(game_obj, 'faqs', '')
    }
    
    if lang_code and lang_code != 'en':
        translation = GameTranslation.query.filter_by(game_id=game_obj.id, language_code=lang_code).first()
        if translation:
            if translation.description: data['description'] = translation.description
            if translation.how_to_play: data['how_to_play'] = translation.how_to_play
            if translation.controls: data['controls'] = translation.controls
            if translation.faqs: data['faqs'] = translation.faqs
            
    return data

# ==========================================
# 🚀 PHASE 2: CLOUDFLARE CORE LOGIC FUNCTIONS
# ==========================================
def delete_from_r2(file_url):
    """Zero Garbage System: Deletes file from R2 Cloud."""
    if not file_url or not file_url.startswith(R2_PUBLIC_URL): return
    try:
        filename = file_url.replace(f"{R2_PUBLIC_URL}/", "")
        s3_client.delete_object(Bucket=BUCKET_NAME, Key=filename)
    except Exception as e:
        print(f"R2 Delete Error: {e}")

# 🚀 NEW: Background Async Worker for Images
def async_image_process_and_upload(file_bytes, bucket, filename):
    """Background worker for Image Processing (Pillow) & R2 Upload."""
    try:
        img = Image.open(io.BytesIO(file_bytes))
        if img.mode != 'RGB': 
            img = img.convert('RGB')
        
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='WEBP', quality=85) # High quality, low size
        img_byte_arr.seek(0)
        
        s3_client.upload_fileobj(
            img_byte_arr, bucket, filename,
            ExtraArgs={'ContentType': 'image/webp'}
        )
        print(f"✅ Background Async Upload Complete (Image): {filename}")
    except Exception as e:
        print(f"❌ Background Image Process Error: {e}")

# 🚀 NEW: Background Async Worker for Video/GIFs
def async_s3_upload(file_bytes, bucket, filename, content_type):
    """Background worker for video/gif uploads."""
    try:
        s3_client.upload_fileobj(
            io.BytesIO(file_bytes), bucket, filename,
            ExtraArgs={'ContentType': content_type}
        )
        print(f"✅ Background Async Upload Complete (Video): {filename}")
    except Exception as e:
        print(f"❌ Background Video Upload Error: {e}")

def process_and_upload_image(file_storage, game_name):
    """Smart Renaming & WebP Auto-Conversion with Real Malware Check (filetype) + ASYNC."""
    if not file_storage or file_storage.filename == '': return None
    try:
        # 🚀 1. Safe Memory Buffering
        file_bytes = file_storage.read()

        # 🚀 2. Real Malware Protection (Pure Python MIME Signature Verification)
        kind = filetype.guess(file_bytes)
        if kind is None or not kind.mime.startswith('image/'):
            mime_found = kind.mime if kind else "Unknown"
            print(f"🚨 Security Alert: Blocked malware/invalid image payload (Real MIME: {mime_found})")
            return None
        
        # 🚀 3. Unique URL Pre-generation
        safe_name = slugify_filter(game_name)
        filename = f"play-{safe_name}-game-{int(datetime.utcnow().timestamp())}.webp"
        final_url = f"{R2_PUBLIC_URL}/{filename}"
        
        # 🚀 4. Background Threading (Zero-Hang Performance)
        threading.Thread(target=async_image_process_and_upload, args=(file_bytes, BUCKET_NAME, filename)).start()
        
        # Instantly return URL
        return final_url
    except Exception as e:
        print(f"Image Pre-process Error: {e}")
        return None

def process_and_upload_video(file_storage, game_name):
    """Uploads Hover Video/GIF to R2 with SEO Smart Naming, Malware Check (filetype) + ASYNC."""
    if not file_storage or file_storage.filename == '': return ""
    try:
        # 🚀 1. Safe Memory Buffering
        file_bytes = file_storage.read()

        # 🚀 2. Real Malware Protection (Pure Python MIME Signature Verification)
        kind = filetype.guess(file_bytes)
        mime_found = kind.mime if kind else "Unknown"
        valid_mimes = ['video/mp4', 'video/webm', 'image/gif']
        
        if kind is None or mime_found not in valid_mimes:
            print(f"🚨 Security Alert: Blocked malware/invalid video payload (Real MIME: {mime_found})")
            return ""

        # 🚀 3. Unique URL Pre-generation based on REAL MIME
        ext = 'mp4'
        if mime_found == 'video/webm': ext = 'webm'
        elif mime_found == 'image/gif': ext = 'gif'
        
        safe_name = slugify_filter(game_name)
        filename = f"{safe_name}-gameplay-preview-{int(datetime.utcnow().timestamp())}.{ext}"
        final_url = f"{R2_PUBLIC_URL}/{filename}"
        
        # 🚀 4. Background Threading (Zero-Hang Performance)
        threading.Thread(target=async_s3_upload, args=(file_bytes, BUCKET_NAME, filename, mime_found)).start()
        
        # Instantly return URL
        return final_url
    except Exception as e:
        print(f"Video Pre-process Error: {e}")
        return ""

# 🚀 PHASE 3: Advanced Auto-Sitemap & Google Ping System
def ping_google(sitemap_url):
    try: 
        requests.get(f"http://www.google.com/ping?sitemap={sitemap_url}", timeout=5)
        requests.get(f"https://www.bing.com/ping?sitemap={sitemap_url}", timeout=5)
        print(f"✅ SEO Ping Sent Successfully to Search Engines for: {sitemap_url}")
    except Exception as e: 
        print(f"❌ SEO Ping Failed: {e}")

# 🚀 PHASE 5: Telegram Auto-Poster Bot
def auto_post_to_social(game_name, category, image_url, full_game_url):
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    channel_id = os.getenv('TELEGRAM_CHANNEL_ID')
    if not bot_token or not channel_id or bot_token == 'your_telegram_bot_token_here': return
    
    tracked_url = f"{full_game_url}?utm_source=telegram_bot&utm_medium=social"
    caption = (
        f"🎮 *NEW GAME ALERT!* 🔥\n\n"
        f"Play *{game_name}* right now!\n"
        f"Dive into the ultimate gaming experience, now available on KixoGames.\n\n"
        f"👇 Click the link below to play for FREE instantly:\n"
        f"{tracked_url}\n\n"
        f"#KixoGames #FreeGames #{category.capitalize()}Games #PlayNow"
    )
    api_url = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
    payload = {'chat_id': channel_id, 'photo': image_url, 'caption': caption, 'parse_mode': 'Markdown'}
    try: requests.post(api_url, data=payload, timeout=10)
    except Exception: pass

# ==========================================
# DATABASE MODELS
# ==========================================
class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, index=True, nullable=False)
    url = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), index=True, nullable=False)
    image_url = db.Column(db.String(500), nullable=False)
    color = db.Column(db.String(20), nullable=False)
    views = db.Column(db.Integer, default=0, index=True)
    preview_url = db.Column(db.String(500), nullable=True) 
    is_active = db.Column(db.Boolean, default=True, index=True) # 🚀 AI Auto-Moderation Status
    created_at = db.Column(db.DateTime, default=datetime.utcnow) # 🚀 Added for 'New Badge logic
    
    # 🚀 ADVANCED SEO: Hyper-Niche Data Fields
    tags = db.Column(db.String(255), nullable=True) 
    how_to_play = db.Column(db.Text, nullable=True)
    controls = db.Column(db.String(255), nullable=True)
    faqs = db.Column(db.Text, nullable=True)

    # 🚀 Enterprise Cascade Deletion Setup
    reports = db.relationship('Report', backref='game_ref', cascade='all, delete-orphan', lazy=True)
    ratings = db.relationship('Rating', backref='game_ref', cascade='all, delete-orphan', lazy=True)
    favorites = db.relationship('Favorite', backref='game_ref', cascade='all, delete-orphan', lazy=True)
    play_histories = db.relationship('PlayHistory', backref='game_ref', cascade='all, delete-orphan', lazy=True)
    interaction_logs = db.relationship('InteractionLog', backref='game_ref', cascade='all, delete-orphan', lazy=True)
    translations = db.relationship('GameTranslation', backref='game_translation_ref', cascade='all, delete-orphan', lazy=True) # 🚀 Phase 1 Link

# 🚀 PHASE 1: HYBRID TRANSLATION DB MODEL
class GameTranslation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id', ondelete='CASCADE'), nullable=False, index=True)
    language_code = db.Column(db.String(10), nullable=False, index=True)
    
    description = db.Column(db.Text, nullable=True)
    how_to_play = db.Column(db.Text, nullable=True)
    controls = db.Column(db.String(255), nullable=True)
    faqs = db.Column(db.Text, nullable=True)
    seo_text = db.Column(db.Text, nullable=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    auth_provider = db.Column(db.String(50), default='google')
    xp = db.Column(db.Integer, default=0)

class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=False)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='moderator') 

class LegalPage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)

# 🚀 HYBRID SEO: Category Content Model with Dynamic Icon
class CategoryContent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category_name = db.Column(db.String(50), unique=True, index=True, nullable=False)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    icon = db.Column(db.String(20), default='🎮')  
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SiteSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    show_ads = db.Column(db.Boolean, default=False)
    head_script = db.Column(db.Text, default='') 
    top_banner = db.Column(db.Text, default='')  
    sidebar_1 = db.Column(db.Text, default='')   
    sidebar_2 = db.Column(db.Text, default='')   

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)

class PlayHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=False)
    last_played = db.Column(db.DateTime, default=datetime.utcnow)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=False)
    reason = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default='Pending')
    count = db.Column(db.Integer, default=1) # 🚀 Smart Aggregation Count
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# 🚀 AI RECOMMENDATION: Interaction Log Data Model
class InteractionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100), index=True, nullable=False)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    playtime_seconds = db.Column(db.Integer, default=0) # 🚀 PHASE 1: Added Playtime Tracking

# ==========================================
# 🚀 POKI-LIKE DEVELOPER ECOSYSTEM MODELS
# ==========================================
class DeveloperWhitelist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

class DeveloperSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dev_email = db.Column(db.String(150), index=True, nullable=False)
    game_name = db.Column(db.String(100), nullable=False)
    game_url = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=True)
    image_url = db.Column(db.String(500), nullable=True)
    preview_url = db.Column(db.String(500), nullable=True)
    color = db.Column(db.String(20), default='blue') 
    
    # 🚀 ADVANCED SEO: Hyper-Niche Data Fields
    tags = db.Column(db.String(255), nullable=True) 
    how_to_play = db.Column(db.Text, nullable=True)
    controls = db.Column(db.String(255), nullable=True)
    faqs = db.Column(db.Text, nullable=True)
    
    status = db.Column(db.String(20), default='Pending') # Pending, Approved, Rejected
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

class DeveloperNotification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dev_email = db.Column(db.String(150), index=True, nullable=False)
    game_name = db.Column(db.String(100), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# 🚀 PHASE 5: PUSH NOTIFICATION SUBSCRIPTION MODEL
class PushSubscriber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subscription_info = db.Column(db.Text, nullable=False) # Stores JSON str
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    try:
        check_col = db.session.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='interaction_log' AND column_name='interaction_type'"))
        if check_col.fetchone():
            db.session.execute(text("DROP TABLE interaction_log CASCADE"))
            db.session.commit()
            print("✅ Successfully removed corrupted old interaction_log table.")
    except Exception:
        db.session.rollback()

    db.create_all()
    
    # 🚀 PHASE 1 DB Migration: Ensure playtime_seconds exists without crashing
    try:
        db.session.execute(text("ALTER TABLE interaction_log ADD COLUMN IF NOT EXISTS playtime_seconds INTEGER DEFAULT 0"))
        db.session.commit()
    except Exception:
        db.session.rollback()

    # 🚀 ADVANCED SEO: DB Migrations for existing tables
    try:
        db.session.execute(text("ALTER TABLE game ADD COLUMN IF NOT EXISTS tags VARCHAR(255)"))
        db.session.execute(text("ALTER TABLE game ADD COLUMN IF NOT EXISTS how_to_play TEXT"))
        db.session.execute(text("ALTER TABLE game ADD COLUMN IF NOT EXISTS controls VARCHAR(255)"))
        db.session.execute(text("ALTER TABLE game ADD COLUMN IF NOT EXISTS faqs TEXT"))
        db.session.execute(text("ALTER TABLE developer_submission ADD COLUMN IF NOT EXISTS tags VARCHAR(255)"))
        db.session.execute(text("ALTER TABLE developer_submission ADD COLUMN IF NOT EXISTS how_to_play TEXT"))
        db.session.execute(text("ALTER TABLE developer_submission ADD COLUMN IF NOT EXISTS controls VARCHAR(255)"))
        db.session.execute(text("ALTER TABLE developer_submission ADD COLUMN IF NOT EXISTS faqs TEXT"))
        db.session.commit()
    except Exception:
        db.session.rollback()

    try:
        db.session.execute(text('ALTER TABLE interaction_log ALTER COLUMN user_id TYPE VARCHAR(100) USING user_id::VARCHAR'))
        db.session.execute(text('ALTER TABLE interaction_log ADD COLUMN IF NOT EXISTS timestamp TIMESTAMP'))
        db.session.commit()
    except Exception: 
        db.session.rollback()
        
    try:
        db.session.execute(text("ALTER TABLE category_content ADD COLUMN icon VARCHAR(20) DEFAULT '🎮'"))
        db.session.commit()
    except Exception: 
        db.session.rollback()
        
    try:
        db.session.execute(text("ALTER TABLE game ADD COLUMN is_active BOOLEAN DEFAULT TRUE"))
        db.session.commit()
    except Exception: 
        db.session.rollback()
        
    try:
        db.session.execute(text("ALTER TABLE report ADD COLUMN count INTEGER DEFAULT 1"))
        db.session.commit()
    except Exception: 
        db.session.rollback()

    # 🚀 Phase 5: DB Migration for 'created_at' field (Needed for 'New Badge logic)
    try:
        db.session.execute(text("ALTER TABLE game ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"))
        db.session.commit()
    except Exception: 
        db.session.rollback()
        
    # 🚀 Alter DeveloperSubmission to add new fields safely without dropping table
    try:
        db.session.execute(text("ALTER TABLE developer_submission ADD COLUMN IF NOT EXISTS description TEXT"))
        db.session.execute(text("ALTER TABLE developer_submission ADD COLUMN IF NOT EXISTS category VARCHAR(50)"))
        db.session.execute(text("ALTER TABLE developer_submission ADD COLUMN IF NOT EXISTS image_url VARCHAR(500)"))
        db.session.execute(text("ALTER TABLE developer_submission ADD COLUMN IF NOT EXISTS preview_url VARCHAR(500)"))
        db.session.execute(text("ALTER TABLE developer_submission ADD COLUMN IF NOT EXISTS color VARCHAR(20) DEFAULT 'blue'")) # 🚀 FIX: DB Migration for color
        db.session.commit()
    except Exception: 
        db.session.rollback()
    
    try:
        db.session.execute(text('CREATE EXTENSION IF NOT EXISTS pg_trgm;'))
        db.session.commit()
        db.session.execute(text('CREATE INDEX IF NOT EXISTS ix_game_name_trgm ON game USING gin (name gin_trgm_ops);'))
        db.session.commit()
    except Exception as e:
        print(f"Warning: pg_trgm optimization could not be applied: {e}")
        db.session.rollback()
        
    try:
        db.session.execute(text('ALTER TABLE game ADD COLUMN preview_url VARCHAR(500)'))
        db.session.commit()
    except Exception: db.session.rollback() 
    try:
        db.session.execute(text('CREATE INDEX IF NOT EXISTS ix_game_category ON game (category)'))
        db.session.execute(text('CREATE INDEX IF NOT EXISTS ix_game_views ON game (views)'))
        db.session.commit()
    except Exception: db.session.rollback()
    try:
        db.session.execute(text('ALTER TABLE "user" ADD COLUMN xp INTEGER DEFAULT 0'))
        db.session.commit()
    except Exception: db.session.rollback()
    if Admin.query.count() == 0:
        hashed_pw = generate_password_hash('superadmin123', method='pbkdf2:sha256')
        db.session.add(Admin(email='superadmin@KixoGames.com', password_hash=hashed_pw, role='superadmin'))
        db.session.commit()
    if LegalPage.query.count() == 0:
        db.session.add(LegalPage(title="Privacy Policy", content="Default Privacy Policy Content..."))
        db.session.add(LegalPage(title="Terms of Service", content="Default Terms of Service Content..."))
        db.session.add(LegalPage(title="About Us", content="Welcome to KixoGames! Your ultimate gaming portal."))
        db.session.commit()
    if SiteSettings.query.count() == 0:
        db.session.add(SiteSettings(show_ads=False))
        db.session.commit()

# ==========================================
# 🚀 AI RECOMMENDATION: Background Model Training (MLOps)
# ==========================================
def train_ai_model():
    """Trains the Recommendation Model using Playtime Weight and Cleans DB silently."""
    with app.app_context():
        try:
            logs = InteractionLog.query.all()
            if len(logs) < 50: 
                print("⚠️ Not enough data to train AI model yet.")
                return 
            
            # 🚀 PHASE 1: Filter out clickbait (sessions < 15s) unless data is very sparse
            valid_logs = [log for log in logs if getattr(log, 'playtime_seconds', 0) >= 15]
            if len(valid_logs) < 20: 
                valid_logs = logs # Fallback to all logs if filtering removes too much
                
            # 1. Prepare Dataset with Playtime Weight
            data = [{'user_id': log.user_id, 'game_id': log.game_id, 'weight': getattr(log, 'playtime_seconds', 0) or 1} for log in valid_logs]
            df = pd.DataFrame(data)
            
            # 2. Create Co-occurrence Matrix (Playtime Weighted)
            user_item_matrix = df.pivot_table(index='user_id', columns='game_id', values='weight', aggfunc='sum', fill_value=0)
            item_similarity = user_item_matrix.corr()
            
            # 3. Generate Recommendations
            recommendations = {}
            for game_id in item_similarity.columns:
                sim_scores = item_similarity[game_id].drop(game_id, errors='ignore').sort_values(ascending=False)
                top_games = sim_scores[sim_scores > 0].head(6).index.tolist()
                recommendations[str(game_id)] = [int(x) for x in top_games]
                
            # 4. Save to Last Known Good Model Cache
            cache_path = os.path.join(app.root_path, 'ai_model_cache.json')
            with open(cache_path, 'w') as f:
                json.dump(recommendations, f)
                
            # 5. Database Cleanup (30-Day Rolling Window)
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            InteractionLog.query.filter(InteractionLog.timestamp < thirty_days_ago).delete()
            db.session.commit()
            
            print("✅ Phase 1: AI Model Trained Successfully with Playtime Weights!")
        except Exception as e:
            print(f"❌ AI Training Failed: {e}")

# ==========================================
# 🚀 SECURITY: Automated DB Backup System
# ==========================================
def backup_database():
    """Takes a PostgreSQL DB dump and securely uploads it to Cloudflare R2 Cloud."""
    with app.app_context():
        try:
            db_url = os.getenv('DATABASE_URL')
            if not db_url: return
            
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"db_backup_{timestamp}.sql"
            filepath = os.path.join('/tmp', filename)
            
            # Run background pg_dump process
            subprocess.run(['pg_dump', db_url, '-f', filepath], check=True)
            
            # Stream directly to Cloudflare R2
            with open(filepath, 'rb') as f:
                s3_client.upload_fileobj(
                    f, BUCKET_NAME, f"database_backups/{filename}",
                    ExtraArgs={'ContentType': 'application/sql'}
                )
            
            # Clean up local temp file securely
            os.remove(filepath)
            print(f"✅ Secure DB Backup Successful & Uploaded to R2: {filename}")
        except Exception as e:
            print(f"❌ DB Backup Failed: {e}")

# ==========================================
# 🚀 DEVELOPER ECOSYSTEM: Notification Cleanup
# ==========================================
def clean_developer_notifications():
    """Auto-deletes rejected game notifications older than 7 days to save DB space."""
    with app.app_context():
        try:
            seven_days_ago = datetime.utcnow() - timedelta(days=7)
            DeveloperNotification.query.filter(DeveloperNotification.created_at < seven_days_ago).delete()
            db.session.commit()
            print("✅ Cleaned up expired developer notifications.")
        except Exception as e:
            print(f"❌ Notification cleanup failed: {e}")

@app.context_processor
def inject_global_settings():
    settings = SiteSettings.query.first()
    
    # 🚀 Phase 4: Inject available languages for UI Dropdown globally
    available_languages = app.config.get('LANGUAGES', {'en': {'name': 'English', 'native': 'English', 'flag': 'us'}})
    current_language = get_locale()
    
    return dict(
        site_settings=settings, 
        available_languages=available_languages, 
        current_language=current_language
    )

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),   
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'), 
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

@app.errorhandler(404)
def page_not_found(e): return render_template('404.html'), 404

# Catch entity too large for files > 5MB
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'status': 'error', 'message': 'File exceeds maximum limit of 5MB.'}), 413

@app.route('/robots.txt')
def robots():
    lines = [
        "User-agent: *",
        "Allow: /",
        "Disallow: /gamesecurityadmin/",
        "Disallow: /gamesecurity/",
        "Disallow: /profile",
        "Disallow: /signup",
        f"Sitemap: {request.host_url}sitemap.xml"
    ]
    return Response("\n".join(lines), mimetype="text/plain")

@app.route('/sitemap.xml')
def sitemap():
    games = Game.query.filter(Game.is_active == True).all()
    pages = LegalPage.query.all()
    categories = [c[0] for c in Game.query.with_entities(Game.category).filter(Game.is_active == True).distinct().all()]
    
    # 🚀 Advanced SEO: Generate Unique Tags for Sitemap
    unique_tags = set()
    for g in games:
        if getattr(g, 'tags', None):
            for t in g.tags.split(','):
                clean_tag = slugify_filter(t)
                if clean_tag:
                    unique_tags.add(clean_tag)
                    
    # 🚀 Phase 2 i18n SEO: Pass configured languages to sitemap
    available_langs = app.config.get('LANGUAGES', {'en': {}}).keys()
                    
    sitemap_xml = render_template(
        'sitemap.xml', 
        games=games, 
        pages=pages, 
        categories=categories, 
        unique_tags=list(unique_tags), 
        base_url=request.host_url[:-1],
        available_langs=available_langs
    )
    response = make_response(sitemap_xml)
    response.headers["Content-Type"] = "application/xml"
    return response

# ==========================================
# 🚀 PHASE 2: i18n DYNAMIC ROUTING WRAPPER
# ==========================================
# We wrap main frontend routes with an optional <lang_code> prefix.
# Example: /es/game/... or just /game/... (defaults to 'en')

def set_lang_and_continue(lang_code):
    """Helper to validate and set the language context before executing route logic."""
    if lang_code is not None:
        if lang_code not in app.config['LANGUAGES']:
            return render_template('404.html'), 404
        g.lang = lang_code
    else:
        # 🚀 BUG FIX: Prevent hard-resetting to English. Respect the cookie!
        cookie_lang = request.cookies.get('lang')
        if cookie_lang and cookie_lang in app.config['LANGUAGES']:
            g.lang = cookie_lang
        else:
            g.lang = 'en'
    return None

# 🚀 PROGRAMMATIC SEO ROUTE (Hyper-Niche Pages)
@app.route('/tag/<string:tag_slug>')
@app.route('/<lang_code>/tag/<string:tag_slug>')
def tag_page(tag_slug, lang_code=None):
    err = set_lang_and_continue(lang_code)
    if err: return err

    page = request.args.get('page', 1, type=int)
    search_term = tag_slug.replace('-', ' ')
    
    # 🚀 FIX: Search for both hyphenated and spaced versions of the tag
    fuzzy_term_space = f"%{search_term}%"
    fuzzy_term_hyphen = f"%{tag_slug}%"
    
    query = Game.query.filter(
        Game.is_active == True, 
        (Game.tags.ilike(fuzzy_term_space)) | (Game.tags.ilike(fuzzy_term_hyphen))
    ).order_by(Game.views.desc())
    
    pagination = query.paginate(page=page, per_page=60, error_out=False) 
    categories = [c[0] for c in Game.query.with_entities(Game.category).filter(Game.is_active == True).distinct().all()]
    user_favorites = [f.game_id for f in Favorite.query.filter_by(user_id=session['user_id']).all()] if session.get('user_logged_in') else []
    footer_pages = LegalPage.query.all()
    
    cat_seo_records = CategoryContent.query.all()
    dynamic_icons = {c.category_name: c.icon for c in cat_seo_records if c.icon}
    
    games_dict = {}
    for g_item in pagination.items:
        ratings = Rating.query.filter_by(game_id=g_item.id).all()
        avg_rating = sum(r.score for r in ratings) / len(ratings) if ratings else 0.0
        
        # 🚀 PHASE 2: Fetch Localized Content
        local_data = get_localized_game_data(g_item, g.lang)
        
        games_dict[g_item.name] = {
            'id': g_item.id, 'url': g_item.url, 
            'description': local_data['description'], # 🚀 Localized
            'category': g_item.category, 'image_url': g_item.image_url, 
            'preview_url': g_item.preview_url, 
            'color': g_item.color, 'views': g_item.views, 'rating': round(avg_rating, 1),
            'badge': get_game_badge(g_item.views, getattr(g_item, 'created_at', None))
        }
    
    # Passing current_tag so the frontend can dynamically adapt the H1 title
    return render_template('index.html', games=games_dict, trending_games=[], category_sliders=[], pagination=pagination, search_query='', current_category='all', categories=categories, user_favorites=user_favorites, footer_pages=footer_pages, recently_played=[], category_seo=None, dynamic_icons=dynamic_icons, current_tag=search_term.title())

# 🚀 OLD PROGRAMMATIC SEO ROUTE REDIRECT (e.g. /games/best-action-games)
@app.route('/games/best-<string:category>-games')
def programmatic_seo_category(category):
    return redirect(url_for('home', category=category.lower()), code=301)

@app.route('/')
@app.route('/<lang_code>/')
def home(lang_code=None):
    err = set_lang_and_continue(lang_code)
    if err: return err

    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('q', '').strip()
    category_filter = request.args.get('category', '').strip()
    
    query = Game.query.filter(Game.is_active == True)
    if search_query:
        similarity = func.similarity(Game.name, search_query)
        fuzzy_term = f"%{search_query.replace(' ', '%')}%"
        query = query.filter((Game.name.ilike(fuzzy_term)) | (similarity > 0.2))
        query = query.order_by(similarity.desc(), Game.views.desc())
        category_filter = 'all' 
    elif category_filter and category_filter != 'all':
        # 🚀 Phase 5: Shuffle/Newest logic for All Free Games
        query = query.filter(Game.category == category_filter).order_by(Game.created_at.desc(), Game.id.desc())
    else:
        # 🚀 Phase 5: Shuffle/Newest logic for All Free Games
        query = query.order_by(Game.created_at.desc(), Game.id.desc())
        
    pagination = query.paginate(page=page, per_page=60, error_out=False) 
    categories = [c[0] for c in Game.query.with_entities(Game.category).filter(Game.is_active == True).distinct().all()]
    user_favorites = [f.game_id for f in Favorite.query.filter_by(user_id=session['user_id']).all()] if session.get('user_logged_in') else []
    footer_pages = LegalPage.query.all()
    
    category_seo = None
    if category_filter and category_filter != 'all' and not search_query:
        category_seo = CategoryContent.query.filter_by(category_name=category_filter).first()
        # 🚀 PHASE 2: (Optional) Localize Category SEO Content here if translation logic is applied to CategoryContent later
        
    cat_seo_records = CategoryContent.query.all()
    dynamic_icons = {c.category_name: c.icon for c in cat_seo_records if c.icon}
    
    recently_played = []
    if session.get('user_logged_in'):
        history_records = PlayHistory.query.filter_by(user_id=session['user_id']).order_by(PlayHistory.last_played.desc()).limit(6).all()
        for h in history_records:
            g_item = Game.query.get(h.game_id)
            if g_item and g_item.is_active:
                ratings = Rating.query.filter_by(game_id=g_item.id).all()
                avg = sum(r.score for r in ratings) / len(ratings) if ratings else 0.0
                recently_played.append({
                    'id': g_item.id, 'name': g_item.name, 'category': g_item.category, 
                    'image_url': g_item.image_url, 'preview_url': g_item.preview_url, 
                    'color': g_item.color, 'views': g_item.views, 'rating': round(avg, 1)
                })

    # 🚀 Phase 5: Separate Top 12 list for Trending Now
    trending_games = []
    if not search_query and (not category_filter or category_filter == 'all'):
        trend_query = Game.query.filter(Game.is_active == True).order_by(Game.views.desc()).limit(12).all()
        for g_item in trend_query:
            ratings = Rating.query.filter_by(game_id=g_item.id).all()
            avg = sum(r.score for r in ratings) / len(ratings) if ratings else 0.0
            trending_games.append({
                'id': g_item.id, 'name': g_item.name, 'category': g_item.category, 
                'image_url': g_item.image_url, 'preview_url': g_item.preview_url, 
                'color': g_item.color, 'views': g_item.views, 'rating': round(avg, 1),
                'slug': slugify_filter(g_item.name)
            })
            
    # 🚀 CRAZYGAMES UI: Dynamic Category Sliders Logic
    category_sliders = []
    if not search_query and (not category_filter or category_filter == 'all'):
        for cat in categories:
            cat_games = Game.query.filter_by(category=cat, is_active=True).order_by(Game.views.desc()).limit(12).all()
            if cat_games:
                slider_games_list = []
                for g_item in cat_games:
                    ratings = Rating.query.filter_by(game_id=g_item.id).all()
                    avg = sum(r.score for r in ratings) / len(ratings) if ratings else 0.0
                    slider_games_list.append({
                        'id': g_item.id, 'name': g_item.name, 'category': g_item.category, 
                        'image_url': g_item.image_url, 'preview_url': g_item.preview_url, 
                        'color': g_item.color, 'views': g_item.views, 'rating': round(avg, 1),
                        'slug': slugify_filter(g_item.name),
                        'badge': get_game_badge(g_item.views, getattr(g_item, 'created_at', None))
                    })
                category_sliders.append({
                    'category_name': cat,
                    'games': slider_games_list
                })

    games_dict = {}
    for g_item in pagination.items:
        ratings = Rating.query.filter_by(game_id=g_item.id).all()
        avg_rating = sum(r.score for r in ratings) / len(ratings) if ratings else 0.0
        
        # 🚀 PHASE 2: Fetch Localized Content
        local_data = get_localized_game_data(g_item, g.lang)
        
        games_dict[g_item.name] = {
            'id': g_item.id, 'url': g_item.url, 
            'description': local_data['description'], # 🚀 Localized
            'category': g_item.category, 'image_url': g_item.image_url, 
            'preview_url': g_item.preview_url, 
            'color': g_item.color, 'views': g_item.views, 'rating': round(avg_rating, 1),
            'badge': get_game_badge(g_item.views, getattr(g_item, 'created_at', None)) # 🚀 Dynamic Badge added!
        }
    
    return render_template('index.html', games=games_dict, trending_games=trending_games, category_sliders=category_sliders, pagination=pagination, search_query=search_query, current_category=category_filter, categories=categories, user_favorites=user_favorites, footer_pages=footer_pages, recently_played=recently_played, category_seo=category_seo, dynamic_icons=dynamic_icons)

@app.route('/api/search')
@limiter.limit("60 per minute") 
def api_search():
    query_str = request.args.get('q', '').strip()
    query = Game.query.options(load_only(Game.id, Game.name, Game.category, Game.image_url, Game.preview_url, Game.color, Game.views, Game.created_at)).filter(Game.is_active == True)
    
    if query_str: 
        similarity = func.similarity(Game.name, query_str)
        fuzzy_term = f"%{query_str.replace(' ', '%')}%"
        query = query.filter((Game.name.ilike(fuzzy_term)) | (similarity > 0.2))
        query = query.order_by(similarity.desc(), Game.views.desc())
    else:
        query = query.order_by(Game.views.desc())
        
    games = query.limit(20).all() 
    user_favorites = [f.game_id for f in Favorite.query.filter_by(user_id=session['user_id']).all()] if session.get('user_logged_in') else []
    
    # 🚀 PHASE 2: Apply language from cookie for API
    lang_code = request.cookies.get('lang', 'en')
    if lang_code not in app.config['LANGUAGES']: lang_code = 'en'
    
    results = []
    for g_item in games:
        ratings = Rating.query.filter_by(game_id=g_item.id).all()
        avg = sum(r.score for r in ratings) / len(ratings) if ratings else 0.0
        results.append({
            'id': g_item.id, 'name': g_item.name, 'category': g_item.category, 
            'image_url': g_item.image_url, 'preview_url': g_item.preview_url, 'color': g_item.color, 'views': g_item.views, 
            'is_favorite': g_item.id in user_favorites, 'rating': round(avg, 1),
            'badge': get_game_badge(g_item.views, getattr(g_item, 'created_at', None)) # 🚀 Dynamic Badge added!
        })
    return jsonify(results)

@app.route('/api/games')
@limiter.limit("120 per minute") 
def api_games():
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('q', '').strip()
    category_filter = request.args.get('category', 'all').strip()
    query = Game.query.options(load_only(Game.id, Game.name, Game.category, Game.image_url, Game.preview_url, Game.color, Game.views, Game.created_at)).filter(Game.is_active == True)
    
    if search_query: 
        similarity = func.similarity(Game.name, search_query)
        fuzzy_term = f"%{search_query.replace(' ', '%')}%"
        query = query.filter((Game.name.ilike(fuzzy_term)) | (similarity > 0.2))
        query = query.order_by(similarity.desc(), Game.views.desc())
    elif category_filter and category_filter != 'all': 
        # 🚀 Phase 5: Shuffle/Newest logic for Infinite Scroll
        query = query.filter(Game.category == category_filter).order_by(Game.created_at.desc(), Game.id.desc())
    else:
        # 🚀 Phase 5: Shuffle/Newest logic for Infinite Scroll
        query = query.order_by(Game.created_at.desc(), Game.id.desc())
        
    pagination = query.paginate(page=page, per_page=60, error_out=False)
    user_favorites = [f.game_id for f in Favorite.query.filter_by(user_id=session['user_id']).all()] if session.get('user_logged_in') else []
    
    # 🚀 PHASE 2: Apply language from cookie for API
    lang_code = request.cookies.get('lang', 'en')
    if lang_code not in app.config['LANGUAGES']: lang_code = 'en'
    
    results = []
    for g_item in pagination.items:
        ratings = Rating.query.filter_by(game_id=g_item.id).all()
        avg = sum(r.score for r in ratings) / len(ratings) if ratings else 0.0
        results.append({
            'id': g_item.id, 'name': g_item.name, 'category': g_item.category, 
            'image_url': g_item.image_url, 'preview_url': g_item.preview_url, 'color': g_item.color, 'views': g_item.views, 
            'is_favorite': g_item.id in user_favorites, 'rating': round(avg, 1),
            'badge': get_game_badge(g_item.views, getattr(g_item, 'created_at', None)) # 🚀 Dynamic Badge added!
        })
    return jsonify({'games': results, 'has_next': pagination.has_next})

@app.route('/game/<string:category>/<int:game_id>/<string:slug>')
@app.route('/<lang_code>/game/<string:category>/<int:game_id>/<string:slug>')
def game(category, game_id, slug, lang_code=None):
    err = set_lang_and_continue(lang_code)
    if err: return err

    game_obj = Game.query.get_or_404(game_id)
    
    # 🚀 ENTERPRISE ANTI-SPAM: View Count & DB Flood Protection (1 Hour Cooldown)
    client_ip = get_remote_address() 
    view_key = f"view_cooldown_{client_ip}_{game_id}"
    
    if not cache.get(view_key):
        game_obj.views += 1
        cache.set(view_key, True, timeout=3600) # 3600 seconds = 1 Hour cooldown
        
        # Record Interaction Log ONLY once per hour to save DB from flooding
        uid = str(session.get('user_id')) if session.get('user_logged_in') else client_ip
        db.session.add(InteractionLog(user_id=uid, game_id=game_id))
        
    if session.get('user_logged_in'):
        user_id = session['user_id']
        history = PlayHistory.query.filter_by(user_id=user_id, game_id=game_id).first()
        current_user = User.query.get(user_id)
        if current_user:
            if not history or (datetime.utcnow() - history.last_played) > timedelta(hours=1):
                current_user.xp = (current_user.xp or 0) + 5
        if history: history.last_played = datetime.utcnow()
        else: db.session.add(PlayHistory(user_id=user_id, game_id=game_id))
    db.session.commit()
    
    recommended_games = []
    cache_path = os.path.join(app.root_path, 'ai_model_cache.json')
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'r') as f:
                ai_cache = json.load(f)
            rec_ids = ai_cache.get(str(game_id), [])
            if rec_ids:
                rec_query = Game.query.options(load_only(Game.id, Game.name, Game.category, Game.image_url, Game.preview_url, Game.color)).filter(Game.id.in_(rec_ids), Game.is_active == True).all()
                rec_dict = {g.id: g for g in rec_query}
                recommended_games = [rec_dict[rid] for rid in rec_ids if rid in rec_dict]
        except Exception as e:
            print(f"Error loading AI Cache: {e}")
            
    pool = Game.query.options(load_only(Game.id, Game.name, Game.category, Game.image_url, Game.preview_url, Game.color)).filter(Game.category == category, Game.id != game_id, Game.is_active == True).order_by(Game.views.desc()).limit(20).all()
    related_games = random.sample(pool, min(len(pool), 12))
    
    # 🚀 NEW: Unique Random Sidebar Games Logic (2-Column Grid Source)
    exclude_ids = [g.id for g in recommended_games] + [g.id for g in related_games] + [game_id]
    sidebar_pool = Game.query.options(load_only(Game.id, Game.name, Game.category, Game.image_url, Game.preview_url, Game.color)).filter(Game.category == category, Game.is_active == True, ~Game.id.in_(exclude_ids)).order_by(Game.views.desc()).limit(40).all()
    sidebar_games = random.sample(sidebar_pool, min(len(sidebar_pool), 16))
    
    ratings = Rating.query.filter_by(game_id=game_id).all()
    avg_rating = sum(r.score for r in ratings) / len(ratings) if ratings else 0.0
    user_rating = 0
    if session.get('user_logged_in'):
        ur = Rating.query.filter_by(game_id=game_id, user_id=session['user_id']).first()
        if ur: user_rating = ur.score
        
    cat_seo_records = CategoryContent.query.all()
    dynamic_icons = {c.category_name: c.icon for c in cat_seo_records if c.icon}

    # 🚀 PHASE 2: Fetch Localized Content
    local_data = get_localized_game_data(game_obj, g.lang)

    # 🚀 Passing Advanced SEO & Localized data to frontend
    return render_template(
        'game.html', 
        name=game_obj.name, 
        info={
            'id': game_obj.id, 'category': game_obj.category, 'url': game_obj.url, 
            'views': game_obj.views, 'image_url': game_obj.image_url, 'preview_url': game_obj.preview_url, 
            'color': game_obj.color, 'tags': getattr(game_obj, 'tags', ''), 
            'description': local_data['description'],       # 🚀 Localized
            'how_to_play': local_data['how_to_play'],       # 🚀 Localized
            'controls': local_data['controls'],             # 🚀 Localized
            'faqs': local_data['faqs']                      # 🚀 Localized
        }, 
        related_games=related_games, recommended_games=recommended_games, sidebar_games=sidebar_games, 
        avg_rating=round(avg_rating, 1), total_ratings=len(ratings), user_rating=user_rating, 
        footer_pages=LegalPage.query.all(), dynamic_icons=dynamic_icons
    )

@app.route('/game.html')
def old_game_route():
    game_name = request.args.get('game')
    if game_name:
        game_obj = Game.query.filter_by(name=game_name).first()
        if game_obj and game_obj.is_active: return redirect(url_for('game', category=game_obj.category, game_id=game_obj.id, slug=slugify_filter(game_obj.name)), code=301)
    return redirect(url_for('home'))

# 🚀 PHASE 1: AI Playtime Tracking API
@app.route('/api/track_playtime', methods=['POST'])
def track_playtime():
    try:
        # Supports FormData from navigator.sendBeacon
        game_id = request.form.get('game_id')
        playtime = int(request.form.get('playtime', 0))
        
        if not game_id or playtime <= 0:
            return jsonify({'status': 'ignored'}), 200

        uid = str(session.get('user_id')) if session.get('user_logged_in') else request.remote_addr
        
        # Get the most recent interaction for this user and game
        log = InteractionLog.query.filter_by(user_id=uid, game_id=game_id).order_by(InteractionLog.timestamp.desc()).first()
        if log:
            log.playtime_seconds = (log.playtime_seconds or 0) + playtime
            db.session.commit()
            
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        print(f"Playtime Tracking Error: {e}")
        return jsonify({'status': 'error'}), 500

@app.route('/api/rate_game/<int:game_id>', methods=['POST'])
def rate_game(game_id):
    if not session.get('user_logged_in'): return jsonify({'status': 'unauthorized'}), 401
    score = request.get_json().get('score', 0)
    if not (1 <= score <= 5): return jsonify({'status': 'error'}), 400
    rating = Rating.query.filter_by(game_id=game_id, user_id=session['user_id']).first()
    if rating: rating.score = score
    else: 
        db.session.add(Rating(game_id=game_id, user_id=session['user_id'], score=score))
        current_user = User.query.get(session['user_id'])
        if current_user: current_user.xp = (current_user.xp or 0) + 10
    db.session.commit()
    return jsonify({'status': 'success'})

@app.route('/api/report_game/<int:game_id>', methods=['POST'])
@limiter.limit("5 per day")
def report_game(game_id):
    reason = request.get_json().get('reason', 'Other')
    
    # 🚀 Enterprise Feature: Smart Data Aggregation
    existing_report = Report.query.filter_by(game_id=game_id, reason=reason).first()
    if existing_report:
        existing_report.count += 1
        current_report = existing_report
    else:
        current_report = Report(game_id=game_id, reason=reason, count=1)
        db.session.add(current_report)
        
    # 🚀 Enterprise Feature: AI Auto-Moderation (Hide game if >= 100 flags)
    if current_report.count >= 100:
        game = Game.query.get(game_id)
        if game and game.is_active:
            game.is_active = False

    db.session.commit()
    return jsonify({'status': 'success'})

# 🚀 PHASE 5: PUSH NOTIFICATIONS API
@app.route('/api/push/subscribe', methods=['POST'])
def push_subscribe():
    sub_info = request.get_json()
    if sub_info:
        sub_str = json.dumps(sub_info)
        if not PushSubscriber.query.filter_by(subscription_info=sub_str).first():
            db.session.add(PushSubscriber(subscription_info=sub_str))
            db.session.commit()
    return jsonify({'status': 'success'})

@app.route('/signup')
@app.route('/<lang_code>/signup')
def signup(lang_code=None):
    err = set_lang_and_continue(lang_code)
    if err: return err

    if session.get('user_logged_in'): return redirect(url_for('home'))
    return render_template('signup.html')

# 🚀 Phase 3: Developer Portal Special Login Hook
@app.route('/dev_login')
def dev_login():
    session['next_url'] = url_for('developer_portal')
    return google.authorize_redirect(url_for('google_auth', _external=True))

@app.route('/login/google')
def google_login(): return google.authorize_redirect(url_for('google_auth', _external=True))

@app.route('/auth/callback')
def google_auth():
    token = google.authorize_access_token()
    user_info = token.get('userinfo')
    if user_info:
        user = User.query.filter_by(email=user_info['email']).first()
        if not user:
            user = User(username=user_info['email'].split('@')[0]+str(random.randint(10,999)), email=user_info['email'], auth_provider='google', xp=0)
            db.session.add(user)
            db.session.commit()
        # 🚀 ADDED 'user_email' for future whitelist checking logic
        session.update({'user_logged_in': True, 'user_id': user.id, 'username': user.username, 'user_email': user.email})
    
    # Route back to developer portal if requested
    next_url = session.pop('next_url', url_for('home'))
    return redirect(next_url)

@app.route('/user_logout')
def user_logout():
    session.pop('user_logged_in', None)
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('user_email', None)
    return redirect(url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
@app.route('/<lang_code>/profile', methods=['GET', 'POST'])
def profile(lang_code=None):
    err = set_lang_and_continue(lang_code)
    if err: return err

    if not session.get('user_logged_in'): 
        if request.is_json: return jsonify({'status': 'unauthorized'}), 401
        return redirect(url_for('signup'))
        
    user = User.query.get_or_404(session['user_id'])
    
    if request.method == 'POST':
        if request.is_json:
            new_username = request.get_json().get('username', '').strip()
            if new_username:
                user.username = new_username
                db.session.commit()
                session['username'] = new_username
                return jsonify({'status': 'success', 'message': 'Username updated successfully!', 'username': new_username})
            return jsonify({'status': 'error', 'message': 'Invalid username'}), 400
            
        new_username = request.form.get('username').strip()
        if new_username:
            user.username = new_username
            db.session.commit()
            session['username'] = new_username
            flash('Username updated successfully!', 'success')
            return redirect(url_for('profile'))
            
    pagination = Game.query.join(Favorite).filter(Favorite.user_id == user.id, Game.is_active == True).order_by(Favorite.id.desc()).paginate(page=request.args.get('page', 1, type=int), per_page=15, error_out=False)
    
    # 🚀 PHASE 1: Dynamic Data Routing for Favorite Games
    games_list = []
    for g_item in pagination.items:
        local_data = get_localized_game_data(g_item, g.lang)
        games_list.append({
            'id': g_item.id,
            'name': g_item.name,
            'category': g_item.category,
            'image_url': g_item.image_url,
            'preview_url': g_item.preview_url,
            'color': g_item.color,
            'description': local_data['description']
        })
        
    history_records = PlayHistory.query.filter_by(user_id=user.id).order_by(PlayHistory.last_played.desc()).limit(10).all()
    
    # 🚀 PHASE 1: Dynamic Data Routing for Recently Played
    recently_played_list = []
    for h in history_records:
        g_item = Game.query.get(h.game_id)
        if g_item and g_item.is_active:
            local_data = get_localized_game_data(g_item, g.lang)
            recently_played_list.append({
                'id': g_item.id,
                'name': g_item.name,
                'category': g_item.category,
                'image_url': g_item.image_url,
                'preview_url': g_item.preview_url,
                'color': g_item.color,
                'description': local_data['description']
            })

    return render_template('profile.html', user=user, games=games_list, pagination=pagination, recently_played=recently_played_list, footer_pages=LegalPage.query.all())

@app.route('/toggle_favorite/<int:game_id>', methods=['POST'])
def toggle_favorite(game_id):
    if not session.get('user_logged_in'): return jsonify({'status': 'unauthorized'}), 401
    fav = Favorite.query.filter_by(user_id=session['user_id'], game_id=game_id).first()
    if fav: db.session.delete(fav)
    else: db.session.add(Favorite(user_id=session['user_id'], game_id=game_id))
    db.session.commit()
    return jsonify({'status': 'removed' if fav else 'added'})

# ==========================================
# 🚀 PHASE 3: DEVELOPER PORTAL (Strict Access)
# ==========================================
@app.route('/developers', methods=['GET', 'POST'])
def developer_portal():
    # 1. State: Gateway - Not logged in
    if not session.get('user_logged_in'):
        return render_template('developer.html', auth_state='unauthenticated')
        
    dev_email = session.get('user_email')
    is_whitelisted = DeveloperWhitelist.query.filter_by(email=dev_email).first()
    
    # 2. State: Denied - Logged in but NOT in Admin Whitelist
    if not is_whitelisted:
        return render_template('developer.html', auth_state='denied', email=dev_email)
        
    # 3. State: Authorized & Submitting a game
    if request.method == 'POST':
        game_name = request.form.get('name', '').strip()
        game_url = request.form.get('url', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '').lower().strip()
        color_theme = request.form.get('color_theme', 'blue').strip() # 🚀 FIX: Capture dev's color
        
        # 🚀 ADVANCED SEO: Fetch new text fields
        tags = request.form.get('tags', '').strip()
        how_to_play = request.form.get('how_to_play', '').strip()
        controls = request.form.get('controls', '').strip()
        faqs = request.form.get('faqs', '').strip()
        
        image_file = request.files.get('image_file')
        preview_file = request.files.get('preview_file')
        
        # Upload straight to Cloudflare R2
        image_url = process_and_upload_image(image_file, game_name) if image_file else "https://via.placeholder.com/400x400?text=No+Image"
        preview_url = process_and_upload_video(preview_file, game_name) if preview_file else ""
        
        new_sub = DeveloperSubmission(
            dev_email=dev_email,
            game_name=game_name,
            game_url=game_url,
            description=description,
            category=category,
            color=color_theme, 
            image_url=image_url,
            preview_url=preview_url,
            tags=tags,
            how_to_play=how_to_play,
            controls=controls,
            faqs=faqs,
            status='Pending'
        )
        db.session.add(new_sub)
        db.session.commit()
        return redirect(url_for('developer_portal'))
        
    # 4. State: Dashboard Render with Pagination (10 per page)
    page = request.args.get('page', 1, type=int)
    submissions_pagination = DeveloperSubmission.query.filter_by(dev_email=dev_email).order_by(DeveloperSubmission.submitted_at.desc()).paginate(page=page, per_page=10, error_out=False)
    
    notifications = DeveloperNotification.query.filter_by(dev_email=dev_email).order_by(DeveloperNotification.created_at.desc()).all()
    
    # Only fetch existing categories from Game db for dropdown. Devs cannot create new ones.
    categories = [c[0] for c in Game.query.with_entities(Game.category).distinct().all()]
    
    return render_template('developer.html', auth_state='authorized', submissions_pagination=submissions_pagination, notifications=notifications, categories=categories, email=dev_email)

@app.route('/developers/dismiss/<int:notif_id>')
def dismiss_notification(notif_id):
    """Allows a developer to clear a rejection notification manually."""
    if not session.get('user_logged_in'): return redirect(url_for('developer_portal'))
    notif = DeveloperNotification.query.get_or_404(notif_id)
    
    # Security check: Make sure they only delete their own notifications
    if notif.dev_email == session.get('user_email'):
        db.session.delete(notif)
        db.session.commit()
    return redirect(url_for('developer_portal'))

# ==========================================
# 🛡️ 100% SECURE & HIDDEN ADMIN ROUTES
# ==========================================
@app.route('/gamesecurity/logout')
def admin_logout():
    session.pop('logged_in', None)
    session.pop('admin_email', None)
    session.pop('role', None)
    return redirect(url_for('home'))

# 🚀 DB BACKUP SYSTEM (One-Click Download for SQLite & PostgreSQL)
@app.route('/gamesecurity/backup')
def download_backup():
    if not session.get('logged_in') or session.get('role') != 'superadmin':
        return redirect(url_for('admin_dashboard'))
    
    try:
        db_uri = os.getenv('DATABASE_URL', '')
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        
        # Handle SQLite
        if db_uri.startswith('sqlite:///'):
            db_path = db_uri.replace('sqlite:///', '')
            if os.path.exists(db_path): target_path = db_path
            elif os.path.exists(os.path.join(app.instance_path, db_path)): target_path = os.path.join(app.instance_path, db_path)
            elif os.path.exists(os.path.join(app.root_path, db_path)): target_path = os.path.join(app.root_path, db_path)
            else: target_path = 'KixoGames.db'
            return send_file(target_path, as_attachment=True, download_name=f"database_backup_{timestamp}.sqlite")
            
        # Handle PostgreSQL
        elif db_uri.startswith('postgres'):
            filename = f"db_backup_{timestamp}.sql"
            filepath = os.path.join(app.root_path, filename)
            
            # Execute pg_dump
            subprocess.run(['pg_dump', db_uri, '-f', filepath], check=True)
            
            # Read file into memory and delete from server
            with open(filepath, 'rb') as f:
                return_data = io.BytesIO(f.read())
            os.remove(filepath)
            
            return send_file(return_data, as_attachment=True, download_name=filename, mimetype='application/sql')
            
        else:
            return "Unsupported database type. Only SQLite and PostgreSQL are supported.", 400
    except Exception as e:
        print(f"Database Download Error: {e}")
        return f"Backup Failed. Please ensure 'pg_dump' is installed on your system. Error: {e}", 500

@app.route('/gamesecurityadmin', methods=['GET', 'POST'])
@limiter.limit("60 per minute")
def admin_dashboard():
    # 🚀 Security: Admin Account Lockout Protection (Brute-Force Guard)
    ip_addr = get_remote_address()
    lockout_key = f"admin_lockout_{ip_addr}"
    attempts_key = f"admin_attempts_{ip_addr}"
    
    if cache.get(lockout_key):
        error = "Account locked due to too many failed attempts. Please try again after 30 minutes."
        return render_template('login.html', error=error), 403

    if not session.get('logged_in'):
        error = None
        if request.method == 'POST':
            if 'email' in request.form and 'password' in request.form:
                admin_user = Admin.query.filter_by(email=request.form['email']).first()
                if admin_user and check_password_hash(admin_user.password_hash, request.form['password']):
                    # Login Success: Reset attempts
                    cache.delete(attempts_key)
                    session.update({'logged_in': True, 'admin_email': admin_user.email, 'role': admin_user.role})
                    return redirect(url_for('admin_dashboard'))
                
                # Login Failed: Track attempts
                attempts = cache.get(attempts_key) or 0
                attempts += 1
                if attempts >= 5:
                    cache.set(lockout_key, True, timeout=1800) # 30 mins block
                    cache.delete(attempts_key)
                    error = "Account locked due to too many failed attempts. Please try again after 30 minutes."
                    return render_template('login.html', error=error), 403
                else:
                    cache.set(attempts_key, attempts, timeout=3600)
                    error = f'Invalid Email or Password! ({5 - attempts} attempts remaining)'
        return render_template('login.html', error=error)
    
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        if form_type == 'add_game':
            image_file = request.files.get('image_file')
            preview_file = request.files.get('preview_file')
            
            cat_name = request.form['category'].lower().strip()
            cat_icon = request.form.get('category_icon', '').strip()
            
            # 🚀 ADVANCED SEO: Fetch new text fields
            tags = request.form.get('tags', '').strip()
            how_to_play = request.form.get('how_to_play', '').strip()
            controls = request.form.get('controls', '').strip()
            faqs = request.form.get('faqs', '').strip()
            
            if cat_icon:
                existing_cat = CategoryContent.query.filter_by(category_name=cat_name).first()
                if existing_cat:
                    existing_cat.icon = cat_icon
                else:
                    db.session.add(CategoryContent(
                        category_name=cat_name, 
                        title=f"Play Best {cat_name.capitalize()} Games", 
                        content=f"<p>Discover the best free online <b>{cat_name.capitalize()}</b> games on KixoGames! Play directly in your browser with no downloads.</p>",
                        icon=cat_icon
                    ))
            
            image_url = process_and_upload_image(image_file, request.form['name']) if image_file else "https://via.placeholder.com/400x400?text=No+Image"
            if not image_url: image_url = "https://via.placeholder.com/400x400?text=No+Image"
            preview_url = process_and_upload_video(preview_file, request.form['name']) if preview_file else ""
            
            new_game = Game(
                name=request.form['name'], 
                url=request.form['url'], 
                description=request.form['description'], 
                category=cat_name, 
                image_url=image_url, 
                preview_url=preview_url, 
                color=request.form['color'],
                tags=tags,
                how_to_play=how_to_play,
                controls=controls,
                faqs=faqs
            )
            db.session.add(new_game)
            db.session.commit()
            
            # 🚀 FIX: Trigger Auto-Translation for Direct Admin Uploads
            data_to_translate = {
                'description': new_game.description,
                'how_to_play': new_game.how_to_play,
                'controls': new_game.controls,
                'faqs': new_game.faqs
            }
            threading.Thread(target=async_translate_and_save, args=(new_game.id, data_to_translate, new_game.name)).start()
            
            sitemap_url = request.host_url + 'sitemap.xml'
            threading.Thread(target=ping_google, args=(sitemap_url,)).start()
            
            full_game_url = f"{request.host_url.rstrip('/')}/game/{new_game.category}/{new_game.id}/{slugify_filter(new_game.name)}"
            threading.Thread(target=auto_post_to_social, args=(new_game.name, new_game.category, new_game.image_url, full_game_url)).start()
            
        elif form_type == 'add_page':
            db.session.add(LegalPage(title=request.form['page_title'], content=request.form['page_content']))
            db.session.commit()
            threading.Thread(target=ping_google, args=(request.host_url + 'sitemap.xml',)).start() # 🚀 Phase 3 Ping
            
        elif form_type == 'update_category_seo':
            cat_name = request.form['category_name'].lower().strip()
            existing = CategoryContent.query.filter_by(category_name=cat_name).first()
            if existing:
                existing.title = request.form['seo_title']
                existing.content = request.form['seo_content']
            else:
                db.session.add(CategoryContent(category_name=cat_name, title=request.form['seo_title'], content=request.form['seo_content']))
            db.session.commit()
            
            sitemap_url = request.host_url + 'sitemap.xml'
            threading.Thread(target=ping_google, args=(sitemap_url,)).start() # 🚀 Phase 3 Ping
            
        elif form_type == 'update_ads':
            settings = SiteSettings.query.first()
            settings.show_ads = request.form.get('show_ads') == 'true'
            settings.head_script = request.form.get('head_script', '')
            settings.top_banner = request.form.get('top_banner', '')
            settings.sidebar_1 = request.form.get('sidebar_1', '')
            settings.sidebar_2 = request.form.get('sidebar_2', '')
            db.session.commit()
        return redirect(url_for('admin_dashboard'))
        
    user_search = request.args.get('user_email', '').strip()
    game_search = request.args.get('game_search', '').strip()
    game_page = request.args.get('game_page', 1, type=int)
    
    # 🚀 Update: Pagination parameters for other sections
    mod_page = request.args.get('mod_page', 1, type=int)
    dev_page = request.args.get('dev_page', 1, type=int)
    seo_page = request.args.get('seo_page', 1, type=int)
    
    total_users = User.query.count()
    total_games = Game.query.count()
    total_views = db.session.query(func.sum(Game.views)).scalar() or 0
    top_games = Game.query.order_by(Game.views.desc()).limit(5).all()
    chart_labels = [g.name for g in top_games]
    chart_data = [g.views for g in top_games]
    raw_reports = Report.query.order_by(Report.created_at.desc()).all()
    reports = [{'id': r.id, 'game_name': Game.query.get(r.game_id).name if Game.query.get(r.game_id) else 'Unknown', 'reason': r.reason, 'count': r.count, 'date': r.created_at.strftime('%Y-%m-%d')} for r in raw_reports]

    # In Admin panel we show ALL games (including inactive ones)
    game_query = Game.query
    if game_search: 
        similarity = func.similarity(Game.name, game_search)
        fuzzy_term = f"%{game_search.replace(' ', '%')}%"
        game_query = game_query.filter((Game.name.ilike(fuzzy_term)) | (similarity > 0.2))
        game_query = game_query.order_by(similarity.desc(), Game.id.desc())
    else:
        game_query = game_query.order_by(Game.id.desc())
        
    games_pagination = game_query.paginate(page=game_page, per_page=10, error_out=False)
    
    # 🚀 Update: Paginated Category SEO
    category_seo_pagination = CategoryContent.query.order_by(CategoryContent.category_name).paginate(page=seo_page, per_page=10, error_out=False)
    dynamic_icons = {c.category_name: c.icon for c in CategoryContent.query.all() if c.icon}
    
    # 🚀 Update: Paginated Moderators (Only for superadmin)
    moderators_pagination = None
    if session.get('role') == 'superadmin':
        moderators_pagination = Admin.query.filter_by(role='moderator').order_by(Admin.id.desc()).paginate(page=mod_page, per_page=10, error_out=False)
    
    # 🚀 Update: Paginated Developer Whitelist
    developer_whitelist_pagination = DeveloperWhitelist.query.order_by(DeveloperWhitelist.added_at.desc()).paginate(page=dev_page, per_page=10, error_out=False)
    
    # 🚀 PHASE 4: Fetch Pending Developer Submissions
    pending_submissions = DeveloperSubmission.query.filter_by(status='Pending').order_by(DeveloperSubmission.submitted_at.desc()).all()
    
    # 🚀 PHASE 4.1: Fetch List of Games for Translation UI Dropdown
    all_active_games = Game.query.filter_by(is_active=True).order_by(Game.name).all()
            
    return render_template('admin.html', 
                           games_pagination=games_pagination, 
                           users=User.query.filter(User.email.ilike(f'%{user_search}%')).all() if user_search else [], 
                           admin_email=session.get('admin_email'), 
                           role=session.get('role'), 
                           categories=[c[0] for c in Game.query.with_entities(Game.category).distinct().all()], 
                           moderators_pagination=moderators_pagination, 
                           all_pages=LegalPage.query.all(), 
                           total_users=total_users, 
                           total_views=total_views, 
                           total_games=total_games, 
                           chart_labels=chart_labels, 
                           chart_data=chart_data, 
                           reports=reports, 
                           category_seo_pagination=category_seo_pagination, 
                           dynamic_icons=dynamic_icons, 
                           developer_whitelist_pagination=developer_whitelist_pagination, 
                           pending_submissions=pending_submissions,
                           all_active_games=all_active_games) # 🚀 Pass games for translation UI

# ==========================================
# 🚀 PHASE 4.1: ADMIN MANUAL OVERRIDE APIs
# ==========================================
@app.route('/gamesecurity/fetch_translation/<int:game_id>/<string:lang_code>', methods=['GET'])
def fetch_translation(game_id, lang_code):
    """Fetches the translated content for a specific game and language."""
    if not session.get('logged_in'): 
        return jsonify({'status': 'unauthorized'}), 403
        
    translation = GameTranslation.query.filter_by(game_id=game_id, language_code=lang_code).first()
    
    if translation:
        return jsonify({
            'status': 'success',
            'data': {
                'description': translation.description or '',
                'how_to_play': translation.how_to_play or '',
                'controls': translation.controls or '',
                'faqs': translation.faqs or ''
            }
        })
    else:
        # If no translation exists yet, return empty fields to let the admin write from scratch
        return jsonify({
            'status': 'not_found',
            'data': {
                'description': '', 'how_to_play': '', 'controls': '', 'faqs': ''
            }
        })

@app.route('/gamesecurity/update_translation', methods=['POST'])
def update_translation():
    """Updates or Creates a specific translation manually from the Admin panel."""
    if not session.get('logged_in'): 
        return jsonify({'status': 'unauthorized'}), 403
        
    data = request.get_json()
    game_id = data.get('game_id')
    lang_code = data.get('language_code')
    
    if not game_id or not lang_code:
        return jsonify({'status': 'error', 'message': 'Missing game_id or language_code'}), 400
        
    translation = GameTranslation.query.filter_by(game_id=game_id, language_code=lang_code).first()
    
    if translation:
        # 🚀 ZERO STORAGE BLOAT: Update existing record directly
        translation.description = data.get('description', '')
        translation.how_to_play = data.get('how_to_play', '')
        translation.controls = data.get('controls', '')
        translation.faqs = data.get('faqs', '')
    else:
        # Insert new if it somehow doesn't exist
        new_trans = GameTranslation(
            game_id=game_id,
            language_code=lang_code,
            description=data.get('description', ''),
            how_to_play=data.get('how_to_play', ''),
            controls=data.get('controls', ''),
            faqs=data.get('faqs', '')
        )
        db.session.add(new_trans)
        
    try:
        db.session.commit()
        # 🚀 Clear cache if you use Redis for the frontend game routes later
        return jsonify({'status': 'success', 'message': f'Translation for {lang_code.upper()} updated perfectly!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ==========================================
# 🚀 PHASE 4: ADMIN QA SYSTEM (Approve / Reject)
# ==========================================
@app.route('/gamesecurity/approve_submission/<int:sub_id>')
def approve_submission(sub_id):
    if not session.get('logged_in'): return redirect(url_for('admin_dashboard'))
    sub = DeveloperSubmission.query.get_or_404(sub_id)
    if sub.status != 'Pending': return redirect(url_for('admin_dashboard'))
    
    game_color = sub.color if sub.color else 'blue'
    
    new_game = Game(
        name=sub.game_name,
        url=sub.game_url,
        description=sub.description,
        category=sub.category,
        image_url=sub.image_url,
        preview_url=sub.preview_url,
        color=game_color,
        tags=getattr(sub, 'tags', ''),
        how_to_play=getattr(sub, 'how_to_play', ''),
        controls=getattr(sub, 'controls', ''),
        faqs=getattr(sub, 'faqs', ''),
        is_active=True
    )
    
    # Duplicate Protection
    try:
        db.session.add(new_game)
        sub.status = 'Approved'
        db.session.commit()
        
        # 🚀 PHASE 2: TRIGGER ASYNC TRANSLATION HERE
        data_to_translate = {
            'description': new_game.description,
            'how_to_play': new_game.how_to_play,
            'controls': new_game.controls,
            'faqs': new_game.faqs
        }
        threading.Thread(target=async_translate_and_save, args=(new_game.id, data_to_translate, new_game.name)).start()

    except IntegrityError:
        db.session.rollback()
        new_game.name = f"{sub.game_name} {random.randint(100, 999)}"
        db.session.add(new_game)
        sub.status = 'Approved'
        db.session.commit()
        
        # 🚀 PHASE 2: TRIGGER ASYNC TRANSLATION HERE (For Duplicates)
        data_to_translate = {
            'description': new_game.description,
            'how_to_play': new_game.how_to_play,
            'controls': new_game.controls,
            'faqs': new_game.faqs
        }
        threading.Thread(target=async_translate_and_save, args=(new_game.id, data_to_translate, new_game.name)).start()
        
    threading.Thread(target=ping_google, args=(request.host_url + 'sitemap.xml',)).start() # 🚀 Phase 3 Ping
    threading.Thread(target=auto_post_to_social, args=(new_game.name, new_game.category, new_game.image_url, f"{request.host_url.rstrip('/')}/game/{new_game.category}/{new_game.id}/{slugify_filter(new_game.name)}")).start()
    
    return redirect(url_for('admin_dashboard'))

@app.route('/gamesecurity/reject_submission/<int:sub_id>', methods=['POST'])
def reject_submission(sub_id):
    if not session.get('logged_in'): return redirect(url_for('admin_dashboard'))
    sub = DeveloperSubmission.query.get_or_404(sub_id)
    
    reason = request.form.get('reason', 'Game did not meet our quality guidelines.')
    db.session.add(DeveloperNotification(dev_email=sub.dev_email, game_name=sub.game_name, reason=reason))
    
    # 🧹 Clean Cloud Storage! Zero Garbage!
    delete_from_r2(sub.image_url)
    if sub.preview_url: delete_from_r2(sub.preview_url)
        
    db.session.delete(sub)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

# ==========================================
# 🚀 PHASE 2: DEVELOPER WHITELIST API ROUTES
# ==========================================
@app.route('/gamesecurity/add_developer', methods=['POST'])
def add_developer():
    if not session.get('logged_in'): return redirect(url_for('admin_dashboard'))
    email = request.form.get('email', '').strip().lower()
    if email and not DeveloperWhitelist.query.filter_by(email=email).first():
        db.session.add(DeveloperWhitelist(email=email))
        db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/gamesecurity/delete_developer/<int:id>')
def delete_developer(id):
    if not session.get('logged_in'): return redirect(url_for('admin_dashboard'))
    db.session.delete(DeveloperWhitelist.query.get_or_404(id))
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/gamesecurity/generate_fake_logs')
def generate_fake_logs():
    if not session.get('logged_in') or session.get('role') != 'superadmin': 
        return redirect(url_for('admin_dashboard'))
    
    games = Game.query.with_entities(Game.id).all()
    if not games: 
        return jsonify({'status': 'error', 'message': 'Upload some games first!'})
    
    game_ids = [g.id for g in games]
    dummy_users = [f"fake_user_test_bot_{i}" for i in range(1, 501)] 
    
    new_logs = []
    now = datetime.utcnow()
    
    for _ in range(5000):
        uid = random.choice(dummy_users)
        gid = random.choice(game_ids)
        random_days = random.randint(0, 29)
        random_seconds = random.randint(0, 86400)
        ts = now - timedelta(days=random_days, seconds=random_seconds)
        new_logs.append(InteractionLog(user_id=uid, game_id=gid, timestamp=ts))
        
    db.session.bulk_save_objects(new_logs)
    db.session.commit()
    
    threading.Thread(target=train_ai_model).start()
    
    return jsonify({'status': 'success', 'message': '5000 fake logs generated & AI Training started in background!'})

@app.route('/gamesecurity/resolve_report/<int:report_id>')
def resolve_report(report_id):
    if not session.get('logged_in'): return redirect(url_for('admin_dashboard'))
    # 🚀 Enterprise Feature: Hard Delete of resolving specific report to save storage
    db.session.delete(Report.query.get_or_404(report_id))
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

# 🚀 Enterprise Feature: Toggle Active Status of Game
@app.route('/gamesecurity/toggle_game/<int:id>')
def toggle_game(id):
    if not session.get('logged_in'): return redirect(url_for('admin_dashboard'))
    game = Game.query.get_or_404(id)
    game.is_active = not game.is_active
    db.session.commit()
    threading.Thread(target=ping_google, args=(request.host_url + 'sitemap.xml',)).start() # 🚀 Phase 3 Ping
    return redirect(url_for('admin_dashboard'))

@app.route('/gamesecurity/delete_game/<int:id>')
def delete_game(id):
    if not session.get('logged_in'): return redirect(url_for('admin_dashboard'))
    game = Game.query.get_or_404(id)
    
    delete_from_r2(game.image_url)
    if game.preview_url:
        delete_from_r2(game.preview_url)
        
    # 🚀 Enterprise Feature: Cascade delete orphan automatically manages all child records
    db.session.delete(game)
    db.session.commit()
    threading.Thread(target=ping_google, args=(request.host_url + 'sitemap.xml',)).start() # 🚀 Phase 3 Ping
    return redirect(url_for('admin_dashboard'))

@app.route('/gamesecurity/edit_game/<int:id>', methods=['GET', 'POST'])
def edit_game(id):
    if not session.get('logged_in'): return redirect(url_for('admin_dashboard'))
    game = Game.query.get_or_404(id)
    if request.method == 'POST':
        game.name = request.form['name']
        game.url = request.form['url']
        game.description = request.form['description']
        game.category = request.form['category'].lower()
        game.color = request.form['color']
        
        # 🚀 ADVANCED SEO: Update text fields
        game.tags = request.form.get('tags', '').strip()
        game.how_to_play = request.form.get('how_to_play', '').strip()
        game.controls = request.form.get('controls', '').strip()
        game.faqs = request.form.get('faqs', '').strip()
        
        image_file = request.files.get('image_file')
        if image_file and image_file.filename != '':
            delete_from_r2(game.image_url)
            new_image_url = process_and_upload_image(image_file, game.name)
            if new_image_url: game.image_url = new_image_url
            
        preview_file = request.files.get('preview_file')
        if preview_file and preview_file.filename != '':
            if game.preview_url: delete_from_r2(game.preview_url)
            new_preview_url = process_and_upload_video(preview_file, game.name)
            if new_preview_url: game.preview_url = new_preview_url
            
        db.session.commit()
        threading.Thread(target=ping_google, args=(request.host_url + 'sitemap.xml',)).start() # 🚀 Phase 3 Ping
        return redirect(url_for('admin_dashboard'))
    return render_template('edit.html', game=game, categories=[c[0] for c in Game.query.with_entities(Game.category).distinct().all()])

@app.route('/gamesecurity/edit_page/<int:page_id>', methods=['GET', 'POST'])
def edit_page(page_id):
    if not session.get('logged_in'): return redirect(url_for('admin_dashboard'))
    page = LegalPage.query.get_or_404(page_id)
    if request.method == 'POST':
        page.title, page.content = request.form['page_title'], request.form['page_content']
        db.session.commit()
        threading.Thread(target=ping_google, args=(request.host_url + 'sitemap.xml',)).start() # 🚀 Phase 3 Ping
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_page.html', page=page)

@app.route('/gamesecurity/delete_page/<int:page_id>')
def delete_page(page_id):
    if not session.get('logged_in'): return redirect(url_for('admin_dashboard'))
    db.session.delete(LegalPage.query.get_or_404(page_id))
    db.session.commit()
    threading.Thread(target=ping_google, args=(request.host_url + 'sitemap.xml',)).start() # 🚀 Phase 3 Ping
    return redirect(url_for('admin_dashboard'))

@app.route('/gamesecurity/delete_category_seo/<int:seo_id>')
def delete_category_seo(seo_id):
    if not session.get('logged_in'): return redirect(url_for('admin_dashboard'))
    db.session.delete(CategoryContent.query.get_or_404(seo_id))
    db.session.commit()
    threading.Thread(target=ping_google, args=(request.host_url + 'sitemap.xml',)).start() # 🚀 Phase 3 Ping
    return redirect(url_for('admin_dashboard'))

@app.route('/gamesecurity/add_moderator', methods=['POST'])
def add_moderator():
    if session.get('role') != 'superadmin': return "Access Denied", 403
    db.session.add(Admin(email=request.form['email'], password_hash=generate_password_hash(request.form['password'], method='pbkdf2:sha256'), role='moderator'))
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/gamesecurity/delete_moderator/<int:id>')
def delete_moderator(id):
    if session.get('role') != 'superadmin': return "Access Denied", 403
    db.session.delete(Admin.query.get_or_404(id))
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/gamesecurity/delete_user/<int:user_id>')
def delete_user(user_id):
    if not session.get('logged_in'): return redirect(url_for('admin_dashboard'))
    Favorite.query.filter_by(user_id=user_id).delete()
    PlayHistory.query.filter_by(user_id=user_id).delete()
    Rating.query.filter_by(user_id=user_id).delete()
    db.session.delete(User.query.get_or_404(user_id))
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/gamesecurity/user_favorites/<int:user_id>')
def admin_user_favorites(user_id):
    if not session.get('logged_in'): return redirect(url_for('admin_dashboard'))
    return render_template('user_favorites_admin.html', user=User.query.get_or_404(user_id), games=Game.query.join(Favorite).filter(Favorite.user_id == user_id).all())

@app.route('/gamesecurity/remove_favorite/<int:fav_id>/<int:user_id>')
def admin_remove_fav(fav_id, user_id):
    if not session.get('logged_in'): return redirect(url_for('admin_dashboard'))
    Favorite.query.filter_by(user_id=user_id, game_id=fav_id).delete()
    db.session.commit()
    return redirect(url_for('admin_user_favorites', user_id=user_id))

# ==========================================
# 🚀 PUSH NOTIFICATION BROADCAST ROUTE
# ==========================================
@app.route('/gamesecurity/broadcast_push', methods=['POST'])
def broadcast_push():
    if not session.get('logged_in') or session.get('role') != 'superadmin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403

    if not webpush:
        flash('pywebpush not installed. Cannot send push notifications.', 'error')
        return redirect(url_for('admin_dashboard'))

    title = request.form.get('title', 'KixoGames Update')
    message = request.form.get('message', '')
    target_url = request.form.get('target_url', '/')
    image_url = request.form.get('image_url', '').strip()

    payload = {
        "title": title,
        "body": message,
        "icon": "/static/icon-192.png",
        "url": target_url
    }
    if image_url:
        payload["image"] = image_url

    subscribers = PushSubscriber.query.all()
    success_count = 0
    fail_count = 0

    for sub in subscribers:
        try:
            sub_info = json.loads(sub.subscription_info)
            webpush(
                subscription_info=sub_info,
                data=json.dumps(payload),
                vapid_private_key=VAPID_PRIVATE_KEY,
                vapid_claims=VAPID_CLAIMS
            )
            success_count += 1
        except WebPushException as ex:
            if ex.response and ex.response.status_code in [404, 410]:
                # Subscription expired or user unsubscribed, remove from DB
                db.session.delete(sub)
            fail_count += 1
        except Exception as e:
            fail_count += 1

    db.session.commit()
    flash(f'Broadcast sent! Success: {success_count}, Failed/Removed: {fail_count}', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/page/<string:title_slug>')
@app.route('/<lang_code>/page/<string:title_slug>')
def legal_page(title_slug, lang_code=None):
    err = set_lang_and_continue(lang_code)
    if err: return err

    search_title = title_slug.replace('-', ' ')
    page_data = LegalPage.query.filter(LegalPage.title.ilike(search_title)).first_or_404()
    return render_template('page.html', data=page_data, footer_pages=LegalPage.query.all())

@app.route('/manifest.json')
def serve_manifest(): return send_from_directory('static', 'manifest.json', mimetype='application/manifest+json')

@app.route('/sw.js')
def serve_sw(): return send_from_directory('static', 'sw.js', mimetype='application/javascript')

# 🚀 AI RECOMMENDATION & SECURITY: Scheduler Initialization
scheduler = BackgroundScheduler()
scheduler.add_job(func=train_ai_model, trigger="cron", day_of_week='sun', hour=8, minute=0)
scheduler.add_job(func=backup_database, trigger="cron", day_of_week='sun', hour=2, minute=0) # 🚀 Auto DB Backup Trigger
scheduler.add_job(func=clean_developer_notifications, trigger="cron", hour=3, minute=0) # 🚀 Auto-clean dev notifications
scheduler.start()

if __name__ == '__main__':
    app.run(debug=True)