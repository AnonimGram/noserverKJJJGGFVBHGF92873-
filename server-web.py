import asyncio
import websockets
import json
import sqlite3
import logging
import uuid
import random
import string
import base64
import os
import tempfile
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Set, List
import sys
import traceback
import time
from collections import defaultdict
import aiohttp

# --- НАСТРОЙКИ ---
HOST = '0.0.0.0'
PORT = 8080
DATABASE = 'anonimgram.db'

# --- ЗАЩИТА ОТ DDOS ---
RATE_LIMIT = {
    'window': 60,
    'max_requests': 100,
    'ban_time': 300
}

request_counts = defaultdict(list)
banned_ips = {}

# --- ЛОГИРОВАНИЕ ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ---
active_connections: Dict[int, websockets.WebSocketServerProtocol] = {}
online_users: Set[int] = set()
typing_status: Dict[str, Set[int]] = {}
hidden_online_users: Set[int] = set()
hidden_last_seen_users: Set[int] = set()
friend_requests: Dict[int, List[Dict]] = {}
premium_users: Dict[int, Dict] = {}

# --- ХЭШИРОВАНИЕ ПАРОЛЕЙ ---
def hash_password(password: str, salt: str = None) -> tuple:
    if salt is None:
        salt = secrets.token_hex(16)
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt, hash_obj.hex()

def verify_password(password: str, salt: str, hash_hex: str) -> bool:
    _, new_hash = hash_password(password, salt)
    return new_hash == hash_hex

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
def is_banned(ip: str) -> bool:
    if ip in banned_ips:
        if time.time() < banned_ips[ip]:
            return True
        else:
            del banned_ips[ip]
    return False

def check_rate_limit(ip: str) -> bool:
    now = time.time()
    request_counts[ip] = [t for t in request_counts[ip] if now - t < RATE_LIMIT['window']]
    if len(request_counts[ip]) >= RATE_LIMIT['max_requests']:
        banned_ips[ip] = now + RATE_LIMIT['ban_time']
        logger.warning(f"🚫 IP {ip} забанен на {RATE_LIMIT['ban_time']}с")
        return False
    request_counts[ip].append(now)
    return True

def generate_channel_id() -> str:
    return 'channel_' + ''.join(random.choices(string.digits, k=18))

def generate_group_id() -> str:
    return 'group_' + ''.join(random.choices(string.digits, k=10))

def generate_private_chat_id(user1: int, user2: int) -> str:
    return f"private_{min(user1, user2)}_{max(user1, user2)}"

def random_color() -> str:
    colors = ['2196F3', '4CAF50', 'F44336', '9C27B0', 'FF9800', '795548', '607D8B']
    return random.choice(colors)

def format_last_seen(timestamp: str, hide_last_seen: bool = False) -> str:
    if hide_last_seen:
        return "скрыто"
    if not timestamp:
        return "никогда"
    try:
        last = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        now = datetime.now()
        delta = now - last
        if delta.days > 7:
            return last.strftime('%d.%m.%Y')
        elif delta.days > 0:
            return f"{delta.days} дн. назад"
        elif delta.seconds > 3600:
            return f"{delta.seconds // 3600} ч. назад"
        elif delta.seconds > 60:
            return f"{delta.seconds // 60} мин. назад"
        else:
            return "только что"
    except:
        return "неизвестно"

# --- PREMIUM ФУНКЦИИ ---
def activate_premium(user_id: int, plan: str) -> bool:
    expiry_date = calculate_expiry_date(plan)
    premium_users[user_id] = {
        'plan': plan,
        'expiry': expiry_date.isoformat() if expiry_date else None,
        'activated_at': datetime.now().isoformat()
    }
    logger.info(f"⭐ Premium активирован для пользователя {user_id}: {plan}")
    return True

def is_premium(user_id: int) -> bool:
    if user_id not in premium_users:
        return False
    info = premium_users[user_id]
    if info['plan'] == 'forever':
        return True
    if info['expiry']:
        expiry = datetime.fromisoformat(info['expiry'])
        if expiry > datetime.now():
            return True
        else:
            del premium_users[user_id]
            return False
    return False

def calculate_expiry_date(plan: str) -> Optional[datetime]:
    now = datetime.now()
    if plan == '1day':
        return now + timedelta(days=1)
    elif plan == '1week':
        return now + timedelta(weeks=1)
    elif plan == '1month':
        return now + timedelta(days=30)
    elif plan == '1year':
        return now + timedelta(days=365)
    elif plan == 'forever':
        return None
    return now

def has_used_free_trial(user_id: int) -> bool:
    if user_id in premium_users:
        return premium_users[user_id]['plan'] == '1day'
    return False

# --- ЗАПРОСЫ НА ДРУЖБУ ---
def send_friend_request(from_user_id: int, to_user_id: int) -> bool:
    if to_user_id not in friend_requests:
        friend_requests[to_user_id] = []
    for req in friend_requests[to_user_id]:
        if req['from_id'] == from_user_id:
            return False
    from_user = get_user_by_id(from_user_id)
    if not from_user:
        return False
    friend_requests[to_user_id].append({
        'from_id': from_user_id,
        'from_login': from_user['login'],
        'from_nickname': from_user['nickname'],
        'timestamp': datetime.now().isoformat()
    })
    logger.info(f"📨 Запрос на дружбу от {from_user_id} к {to_user_id}")
    if to_user_id in active_connections:
        try:
            asyncio.create_task(active_connections[to_user_id].send(json.dumps({
                "cmd": "NEW_FRIEND_REQUEST",
                "from_user_id": from_user_id,
                "from_login": from_user['login'],
                "from_nickname": from_user['nickname']
            })))
        except:
            pass
    return True

def get_friend_requests(user_id: int) -> list:
    return friend_requests.get(user_id, [])

def accept_friend_request(user_id: int, from_user_id: int) -> bool:
    requests = friend_requests.get(user_id, [])
    request = None
    for req in requests:
        if req['from_id'] == from_user_id:
            request = req
            break
    if not request:
        return False
    friend_requests[user_id] = [r for r in requests if r['from_id'] != from_user_id]
    chat_id = generate_private_chat_id(user_id, from_user_id)
    target_name = request['from_nickname'] or request['from_login']
    create_chat(chat_id, target_name, "private", user_id)
    add_chat_member(chat_id, user_id, 'member')
    add_chat_member(chat_id, from_user_id, 'member')
    logger.info(f"✅ Запрос принят: {from_user_id} и {user_id} теперь друзья, чат {chat_id}")
    for uid in [user_id, from_user_id]:
        if uid in active_connections:
            try:
                asyncio.create_task(active_connections[uid].send(json.dumps({
                    "status": "FRIEND_REQUEST_ACCEPTED",
                    "chat_id": chat_id,
                    "from_id": from_user_id,
                    "from_nickname": request['from_nickname'],
                    "to_id": user_id
                })))
            except:
                pass
    return True

def reject_friend_request(user_id: int, from_user_id: int) -> bool:
    requests = friend_requests.get(user_id, [])
    friend_requests[user_id] = [r for r in requests if r['from_id'] != from_user_id]
    logger.info(f"❌ Запрос отклонён: от {from_user_id} к {user_id}")
    if from_user_id in active_connections:
        try:
            asyncio.create_task(active_connections[from_user_id].send(json.dumps({
                "status": "FRIEND_REQUEST_REJECTED",
                "from_id": user_id
            })))
        except:
            pass
    return True

async def check_expired_premium():
    while True:
        await asyncio.sleep(3600)
        expired = []
        for user_id, info in premium_users.items():
            if info['plan'] != 'forever' and info.get('expiry'):
                expiry = datetime.fromisoformat(info['expiry'])
                if expiry <= datetime.now():
                    expired.append(user_id)
        for user_id in expired:
            del premium_users[user_id]
            logger.info(f"⌛ Premium истек для пользователя {user_id}")

# ========== АВТОМАТИЧЕСКИЙ ПИНГ ДЛЯ RENDER ==========
async def auto_ping():
    while True:
        await asyncio.sleep(60)
        try:
            public_url = os.environ.get('RENDER_EXTERNAL_URL', f'http://localhost:{PORT}')
            async with aiohttp.ClientSession() as session:
                async with session.get(f'{public_url}/') as resp:
                    logger.info(f"🔄 Auto-ping: статус {resp.status}")
        except Exception as e:
            logger.warning(f"⚠️ Auto-ping ошибка: {e}")

# --- ПРОКСИ ДЛЯ CRYPTOBOT ---
async def proxy_cryptobot_request(endpoint: str, data: dict, token: str):
    """Прокси для запросов к CryptoBot API"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f'https://pay.crypt.bot/api/{endpoint}',
                json=data,
                headers={
                    'Content-Type': 'application/json',
                    'Crypto-Pay-API-Token': token
                }
            ) as response:
                result = await response.json()
                logger.info(f"CryptoBot API response: {result}")
                return result
    except Exception as e:
        logger.error(f"CryptoBot API error: {e}")
        return {"ok": False, "error": str(e)}

# --- РАБОТА С БАЗОЙ ДАННЫХ ---
def init_database():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        login TEXT UNIQUE NOT NULL,
        nickname TEXT DEFAULT '',
        password_salt TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_online BOOLEAN DEFAULT 0,
        hide_online BOOLEAN DEFAULT 0,
        hide_last_seen BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        deleted_at TIMESTAMP NULL
    )''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS chats (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT CHECK(type IN ('private', 'group', 'channel', 'system')) NOT NULL,
        description TEXT DEFAULT '',
        avatar_path TEXT DEFAULT '',
        owner_id INTEGER,
        is_public BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        deleted_at TIMESTAMP NULL,
        FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE SET NULL
    )''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS chat_members (
        chat_id TEXT,
        user_id INTEGER,
        role TEXT CHECK(role IN ('member', 'admin', 'owner', 'subscriber')) DEFAULT 'member',
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        left_at TIMESTAMP NULL,
        PRIMARY KEY (chat_id, user_id),
        FOREIGN KEY (chat_id) REFERENCES chats (id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS channel_subscribers (
        channel_id TEXT,
        user_id INTEGER,
        subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        unsubscribed_at TIMESTAMP NULL,
        PRIMARY KEY (channel_id, user_id),
        FOREIGN KEY (channel_id) REFERENCES chats (id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS group_invites (
        group_id TEXT,
        invite_code TEXT UNIQUE,
        created_by INTEGER,
        expires_at TIMESTAMP,
        uses_left INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (group_id, invite_code),
        FOREIGN KEY (group_id) REFERENCES chats (id) ON DELETE CASCADE,
        FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL
    )''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER,
        device TEXT,
        browser TEXT,
        ip TEXT DEFAULT 'скрыт',
        last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )''')
    conn.commit()
    conn.close()
    logger.info("✅ База данных инициализирована (IP скрыты для анонимности)")

def get_user_by_login(login: str) -> Optional[Dict]:
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, login, nickname, password_salt, password_hash, last_seen, is_online, hide_online, hide_last_seen FROM users WHERE login = ? AND deleted_at IS NULL", (login,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def get_user_by_id(user_id: int) -> Optional[Dict]:
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, login, nickname, last_seen, is_online, hide_online, hide_last_seen FROM users WHERE id = ? AND deleted_at IS NULL", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def create_user(login: str, nickname: str, password: str) -> int:
    salt, hash_hex = hash_password(password)
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (login, nickname, password_salt, password_hash, last_seen, is_online) 
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, 1)
    """, (login, nickname, salt, hash_hex))
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return user_id

def search_users(query: str, current_user_id: int) -> list:
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, login, nickname, is_online, hide_online, hide_last_seen, last_seen 
        FROM users 
        WHERE (login LIKE ? OR nickname LIKE ?) AND id != ? AND deleted_at IS NULL
        ORDER BY 
            CASE WHEN is_online = 1 AND hide_online = 0 THEN 0 ELSE 1 END,
            nickname
        LIMIT 20
    ''', (f'%{query}%', f'%{query}%', current_user_id))
    users = cursor.fetchall()
    conn.close()
    result = []
    for user in users:
        user_dict = dict(user)
        if user_dict['hide_online']:
            user_dict['is_online'] = False
        user_dict['is_premium'] = is_premium(user_dict['id'])
        result.append(user_dict)
    return result

def update_user_status(user_id: int, is_online: bool):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_online = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ? AND deleted_at IS NULL", (1 if is_online else 0, user_id))
    conn.commit()
    conn.close()

def update_user_privacy(user_id: int, hide_online: bool = None, hide_last_seen: bool = None):
    updates, params = [], []
    if hide_online is not None:
        updates.append("hide_online = ?")
        params.append(1 if hide_online else 0)
        if hide_online:
            hidden_online_users.add(user_id)
        elif user_id in hidden_online_users:
            hidden_online_users.remove(user_id)
    if hide_last_seen is not None:
        updates.append("hide_last_seen = ?")
        params.append(1 if hide_last_seen else 0)
        if hide_last_seen:
            hidden_last_seen_users.add(user_id)
        elif user_id in hidden_last_seen_users:
            hidden_last_seen_users.remove(user_id)
    if not updates:
        return True
    params.append(user_id)
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ? AND deleted_at IS NULL", params)
    conn.commit()
    conn.close()
    return True

def delete_user_account(user_id: int) -> bool:
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET deleted_at = CURRENT_TIMESTAMP, is_online = 0 WHERE id = ?", (user_id,))
        cursor.execute("UPDATE chat_members SET left_at = CURRENT_TIMESTAMP WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        if user_id in active_connections:
            del active_connections[user_id]
        if user_id in online_users:
            online_users.remove(user_id)
        if user_id in hidden_online_users:
            hidden_online_users.remove(user_id)
        if user_id in hidden_last_seen_users:
            hidden_last_seen_users.remove(user_id)
        if user_id in premium_users:
            del premium_users[user_id]
        if user_id in friend_requests:
            del friend_requests[user_id]
        logger.info(f"✅ Аккаунт пользователя {user_id} удален")
        return True
    except Exception as e:
        logger.error(f"❌ Ошибка удаления аккаунта: {e}")
        return False

def create_chat(chat_id: str, name: str, chat_type: str, owner_id: int, description: str = "", is_public: bool = False) -> bool:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO chats (id, name, type, owner_id, description, is_public, avatar_path) VALUES (?, ?, ?, ?, ?, ?, ?)", (chat_id, name, chat_type, owner_id, description, 1 if is_public else 0, f"GENERATE:{name}:#{random_color()}"))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"❌ Ошибка создания чата: {e}")
        return False
    finally:
        conn.close()

def add_chat_member(chat_id: str, user_id: int, role: str = 'member'):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO chat_members (chat_id, user_id, role) VALUES (?, ?, ?)", (chat_id, user_id, role))
    conn.commit()
    conn.close()

def add_channel_subscriber(channel_id: str, user_id: int):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO channel_subscribers (channel_id, user_id) VALUES (?, ?)", (channel_id, user_id))
    cursor.execute("INSERT OR IGNORE INTO chat_members (chat_id, user_id, role) VALUES (?, ?, ?)", (channel_id, user_id, 'subscriber'))
    conn.commit()
    conn.close()

def remove_channel_subscriber(channel_id: str, user_id: int):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("UPDATE channel_subscribers SET unsubscribed_at = CURRENT_TIMESTAMP WHERE channel_id = ? AND user_id = ?", (channel_id, user_id))
    cursor.execute("UPDATE chat_members SET left_at = CURRENT_TIMESTAMP WHERE chat_id = ? AND user_id = ?", (channel_id, user_id))
    conn.commit()
    conn.close()

def is_chat_member(chat_id: str, user_id: int) -> bool:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ? AND left_at IS NULL", (chat_id, user_id))
    result = cursor.fetchone() is not None
    conn.close()
    return result

def get_user_chats(user_id: int) -> list:
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT c.id, c.name, c.type, c.description, c.avatar_path, c.is_public,
               cm.role,
               (SELECT COUNT(*) FROM chat_members WHERE chat_id = c.id AND left_at IS NULL) as members_count
        FROM chats c
        JOIN chat_members cm ON c.id = cm.chat_id
        WHERE cm.user_id = ? AND cm.left_at IS NULL AND c.deleted_at IS NULL
        ORDER BY 
            CASE c.type 
                WHEN 'system' THEN 1
                WHEN 'private' THEN 2
                WHEN 'group' THEN 3
                WHEN 'channel' THEN 4
            END,
            c.created_at DESC
    ''', (user_id,))
    chats = cursor.fetchall()
    conn.close()
    result = []
    for chat in chats:
        chat_dict = dict(chat)
        chat_dict['time'] = ''
        chat_dict['last_message'] = ''
        result.append(chat_dict)
    return result

def get_chat_members(chat_id: str) -> list:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM chat_members WHERE chat_id = ? AND left_at IS NULL", (chat_id,))
    members = cursor.fetchall()
    conn.close()
    return [member[0] for member in members]

def get_chat_info(chat_id: str, user_id: int) -> Optional[Dict]:
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM chat_members WHERE chat_id = ? AND user_id = ? AND left_at IS NULL", (chat_id, user_id))
    membership = cursor.fetchone()
    cursor.execute('''
        SELECT c.*, u.nickname as owner_nickname,
               (SELECT COUNT(*) FROM chat_members WHERE chat_id = c.id AND left_at IS NULL) as members_count
        FROM chats c
        LEFT JOIN users u ON c.owner_id = u.id
        WHERE c.id = ? AND c.deleted_at IS NULL
    ''', (chat_id,))
    chat = cursor.fetchone()
    if not chat:
        conn.close()
        return None
    result = dict(chat)
    result['is_member'] = membership is not None
    result['user_role'] = membership['role'] if membership else None
    if result['type'] == 'channel':
        cursor.execute("SELECT COUNT(*) FROM channel_subscribers WHERE channel_id = ? AND unsubscribed_at IS NULL", (chat_id,))
        result['subscribers_count'] = cursor.fetchone()[0]
    conn.close()
    return result

def generate_invite_code(group_id: str, created_by: int, expires_in_days: int = 7, uses: int = 1) -> str:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    invite_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    expires_at = (datetime.now() + timedelta(days=expires_in_days)).isoformat()
    cursor.execute("INSERT INTO group_invites (group_id, invite_code, created_by, expires_at, uses_left) VALUES (?, ?, ?, ?, ?)", (group_id, invite_code, created_by, expires_at, uses))
    conn.commit()
    conn.close()
    return invite_code

def use_invite_code(invite_code: str, user_id: int) -> Optional[str]:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT group_id, expires_at, uses_left FROM group_invites WHERE invite_code = ?", (invite_code,))
    invite = cursor.fetchone()
    if not invite:
        conn.close()
        return None
    group_id, expires_at, uses_left = invite
    if datetime.fromisoformat(expires_at) < datetime.now():
        conn.close()
        return None
    if uses_left <= 0:
        conn.close()
        return None
    cursor.execute("INSERT OR IGNORE INTO chat_members (chat_id, user_id, role) VALUES (?, ?, ?)", (group_id, user_id, 'member'))
    cursor.execute("UPDATE group_invites SET uses_left = uses_left - 1 WHERE invite_code = ?", (invite_code,))
    conn.commit()
    conn.close()
    return group_id

# --- УПРАВЛЕНИЕ СЕССИЯМИ (БЕЗ IP) ---
def save_user_session(session_id: str, user_id: int, device: str, browser: str, ip: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # IP всегда сохраняем как 'скрыт' для анонимности
    cursor.execute("INSERT OR REPLACE INTO user_sessions (id, user_id, device, browser, ip, last_active) VALUES (?, ?, ?, ?, 'скрыт', CURRENT_TIMESTAMP)", (session_id, user_id, device, browser))
    conn.commit()
    conn.close()
    logger.info(f"💾 Сессия сохранена: {device} / {browser} (IP скрыт)")

def get_user_sessions(user_id: int) -> list:
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, device, browser, last_active FROM user_sessions WHERE user_id = ? ORDER BY last_active DESC", (user_id,))
    sessions = cursor.fetchall()
    conn.close()
    # Возвращаем без IP
    return [{"id": s["id"], "device": s["device"], "browser": s["browser"], "last_active": s["last_active"]} for s in sessions]

def remove_user_session(session_id: str):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM user_sessions WHERE id = ?", (session_id,))
    conn.commit()
    conn.close()
    logger.info(f"🗑️ Сессия удалена: {session_id}")

async def notify_contacts_status_change(user_id: int, is_online: bool):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT DISTINCT cm2.user_id 
        FROM chat_members cm1
        JOIN chat_members cm2 ON cm1.chat_id = cm2.chat_id
        WHERE cm1.user_id = ? AND cm2.user_id != ? AND cm2.left_at IS NULL
    ''', (user_id, user_id))
    contacts = cursor.fetchall()
    conn.close()
    for (contact_id,) in contacts:
        if contact_id in active_connections:
            try:
                await active_connections[contact_id].send(json.dumps({
                    "cmd": "USER_STATUS_CHANGED",
                    "user_id": user_id,
                    "is_online": is_online
                }))
            except:
                pass

async def handle_http_request(path, request_headers):
    if path == "/" or path == "/health":
        headers = [("Content-Type", "text/plain"), ("Content-Length", "2"), ("Connection", "close")]
        return (200, headers, b"OK")
    return None

async def ws_handler(websocket):
    client_ip = websocket.remote_address[0]
    if is_banned(client_ip):
        logger.warning(f"🚫 Заблокирован запрос от забаненного IP: {client_ip}")
        await websocket.close()
        return
    session_id = str(uuid.uuid4())[:8]
    logger.info(f"🔌 Новое подключение (сессия: {session_id})")
    user_id = None

    try:
        async for message in websocket:
            if not check_rate_limit(client_ip):
                logger.warning(f"🚫 IP {client_ip} превысил лимит запросов")
                await websocket.send(json.dumps({"error": "Слишком много запросов"}))
                await websocket.close()
                return
            try:
                data = json.loads(message)
                command = data.get("cmd")
                logger.info(f"📨 Команда: {command} (сессия: {session_id})")

                requires_auth = command in [
                    "GET_CHATS", "GET_MESSAGES", "SEND_MESSAGE", "UPDATE_PROFILE",
                    "GET_USER_INFO", "CREATE_CHAT", "PING", "SEARCH_USERS",
                    "CREATE_GROUP", "CREATE_CHANNEL", "JOIN_CHANNEL", "LEAVE_CHANNEL",
                    "GET_INVITE_LINK", "JOIN_WITH_INVITE", "ACTIVATE_PREMIUM",
                    "CHECK_PREMIUM", "GET_PREMIUM_INFO",
                    "SEND_FRIEND_REQUEST", "GET_FRIEND_REQUESTS", 
                    "ACCEPT_FRIEND_REQUEST", "REJECT_FRIEND_REQUEST", "JOIN_PRIVATE_CHAT",
                    "SEND_FILE", "UPDATE_NICKNAME",
                    "SEND_STICKER", "SEND_VOICE", "SET_REACTION",
                    "CALL_REQUEST", "CALL_ACCEPT", "CALL_REJECT", "CALL_END",
                    "DELETE_CHAT", "GET_SESSIONS", "TERMINATE_SESSION",
                    "CREATE_INVOICE", "CHECK_INVOICE", "ICE_CANDIDATE"
                ]

                if requires_auth and user_id is None:
                    await websocket.send(json.dumps({"error": "Пользователь не авторизован"}))
                    continue

                # --- РЕГИСТРАЦИЯ ---
                if command == "REGISTER":
                    login = data.get("login")
                    password = data.get("password")
                    if not login or not password:
                        await websocket.send(json.dumps({"error": "Логин и пароль обязательны"}))
                        continue
                    if len(login) < 3:
                        await websocket.send(json.dumps({"error": "Логин минимум 3 символа"}))
                        continue
                    if len(password) < 6:
                        await websocket.send(json.dumps({"error": "Пароль минимум 6 символов"}))
                        continue
                    existing = get_user_by_login(login)
                    if existing:
                        await websocket.send(json.dumps({"error": "Пользователь существует"}))
                        continue
                    user_id = create_user(login, login, password)
                    anonimgram_chat_id = f"system_{user_id}"
                    create_chat(anonimgram_chat_id, "AnonimGram", "system", user_id)
                    add_chat_member(anonimgram_chat_id, user_id, 'member')
                    active_connections[user_id] = websocket
                    online_users.add(user_id)
                    await websocket.send(json.dumps({
                        "status": "REGISTERED",
                        "user_id": user_id,
                        "message": "Регистрация успешна"
                    }))
                    logger.info(f"✅ Пользователь зарегистрирован: ID {user_id}")

                # --- ВХОД ---
                elif command == "LOGIN":
                    login = data.get("login")
                    password = data.get("password")
                    device = data.get("device", "Unknown")
                    browser = data.get("browser", "Unknown")
                    
                    if not login or not password:
                        await websocket.send(json.dumps({"error": "Логин и пароль обязательны"}))
                        continue
                    
                    user = get_user_by_login(login)
                    if not user:
                        user_id = create_user(login, login, password)
                        anonimgram_chat_id = f"system_{user_id}"
                        create_chat(anonimgram_chat_id, "AnonimGram", "system", user_id)
                        add_chat_member(anonimgram_chat_id, user_id, 'member')
                        logger.info(f"✅ Автоматическая регистрация: ID {user_id}")
                    else:
                        if not verify_password(password, user['password_salt'], user['password_hash']):
                            await websocket.send(json.dumps({"error": "Неверный пароль"}))
                            continue
                        user_id = user['id']
                    
                    # Сохраняем сессию (IP скрыт)
                    save_user_session(session_id, user_id, device, browser, client_ip)
                    
                    if user_id in active_connections:
                        try:
                            await active_connections[user_id].close()
                        except:
                            pass
                    active_connections[user_id] = websocket
                    online_users.add(user_id)
                    update_user_status(user_id, True)
                    user = get_user_by_id(user_id)
                    user_info = dict(user) if user else {'id': user_id, 'login': login}
                    user_info['is_premium'] = is_premium(user_id)
                    user_info['premium_plan'] = premium_users.get(user_id, {}).get('plan') if is_premium(user_id) else None
                    await websocket.send(json.dumps({
                        "status": "LOGGED_IN",
                        "user_id": user_id,
                        "user_info": user_info,
                        "session_id": session_id
                    }))
                    logger.info(f"✅ Вход выполнен: ID {user_id}")

                # --- СОЗДАНИЕ СЧЕТА CRYPTOBOT ---
                elif command == "CREATE_INVOICE":
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    
                    token = data.get("token")
                    asset = data.get("asset", "USDT")
                    amount = data.get("amount")
                    description = data.get("description", "")
                    
                    if not token or not amount:
                        await websocket.send(json.dumps({"error": "Недостаточно данных"}))
                        continue
                    
                    result = await proxy_cryptobot_request("createInvoice", {
                        "asset": asset,
                        "amount": amount,
                        "description": description
                    }, token)
                    
                    await websocket.send(json.dumps({
                        "cmd": "INVOICE_CREATED",
                        "result": result
                    }))
                
                # --- ПРОВЕРКА СЧЕТА CRYPTOBOT ---
                elif command == "CHECK_INVOICE":
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    
                    token = data.get("token")
                    invoice_ids = data.get("invoice_ids", [])
                    
                    if not token or not invoice_ids:
                        await websocket.send(json.dumps({"error": "Недостаточно данных"}))
                        continue
                    
                    result = await proxy_cryptobot_request("getInvoices", {
                        "invoice_ids": invoice_ids
                    }, token)
                    
                    await websocket.send(json.dumps({
                        "cmd": "INVOICE_CHECKED",
                        "result": result
                    }))

                # --- ПОЛУЧЕНИЕ СПИСКА ЧАТОВ ---
                elif command == "GET_CHATS":
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    chats = get_user_chats(user_id)
                    for chat in chats:
                        if chat["type"] == "private":
                            if chat["id"].startswith("private_"):
                                parts = chat["id"].split('_')
                                if len(parts) == 3:
                                    other_id = int(parts[2]) if int(parts[2]) != user_id else int(parts[1])
                                    other = get_user_by_id(other_id)
                                    if other:
                                        is_online = other["is_online"] and other_id not in hidden_online_users
                                        last_seen = format_last_seen(other["last_seen"], other_id in hidden_last_seen_users)
                                        chat["other_user"] = {
                                            "id": other["id"],
                                            "nickname": other["nickname"],
                                            "is_online": is_online,
                                            "last_seen": last_seen,
                                            "is_premium": is_premium(other_id)
                                        }
                                        chat["name"] = other["nickname"]
                    await websocket.send(json.dumps({
                        "cmd": "CHATS_LIST",
                        "chats": chats
                    }))

                # --- ОТПРАВКА СООБЩЕНИЯ ---
                elif command == "SEND_MESSAGE":
                    chat_id = data.get("chat_id")
                    text = data.get("text")
                    sender_has_premium = data.get("sender_has_premium", False) or is_premium(user_id)
                    
                    if not chat_id or not text:
                        await websocket.send(json.dumps({"error": "Недостаточно данных"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    if not is_chat_member(chat_id, user_id):
                        await websocket.send(json.dumps({"error": "Нет доступа к чату"}))
                        continue
                    
                    members = get_chat_members(chat_id)
                    message_id = f"msg_{uuid.uuid4().hex[:16]}"
                    sent_time = datetime.now().strftime('%H:%M')
                    
                    for member_id in members:
                        if member_id != user_id and member_id in active_connections:
                            try:
                                await active_connections[member_id].send(json.dumps({
                                    "cmd": "NEW_MESSAGE",
                                    "message": {
                                        "id": message_id,
                                        "chat_id": chat_id,
                                        "sender_id": user_id,
                                        "text": text,
                                        "time": sent_time,
                                        "sender_has_premium": sender_has_premium
                                    }
                                }))
                            except:
                                pass
                    
                    await websocket.send(json.dumps({"status": "MESSAGE_SENT", "message_id": message_id}))

                # --- ОТПРАВКА СТИКЕРА ---
                elif command == "SEND_STICKER":
                    chat_id = data.get("chat_id")
                    sticker_data = data.get("sticker_data")
                    if not chat_id or not sticker_data:
                        await websocket.send(json.dumps({"error": "Недостаточно данных"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    if not is_chat_member(chat_id, user_id):
                        await websocket.send(json.dumps({"error": "Нет доступа к чату"}))
                        continue
                    
                    members = get_chat_members(chat_id)
                    sent_time = datetime.now().strftime('%H:%M')
                    for member_id in members:
                        if member_id != user_id and member_id in active_connections:
                            try:
                                await active_connections[member_id].send(json.dumps({
                                    "cmd": "NEW_STICKER",
                                    "sticker": {
                                        "chat_id": chat_id,
                                        "sender_id": user_id,
                                        "sticker_data": sticker_data,
                                        "time": sent_time
                                    }
                                }))
                            except:
                                pass
                    await websocket.send(json.dumps({"status": "STICKER_SENT"}))

                # --- ОТПРАВКА ГОЛОСОВОГО ---
                elif command == "SEND_VOICE":
                    chat_id = data.get("chat_id")
                    voice_data = data.get("voice_data")
                    duration = data.get("duration", 0)
                    
                    logger.info(f"🎤 Получено голосовое: chat={chat_id}, duration={duration}")
                    
                    if not chat_id or not voice_data:
                        await websocket.send(json.dumps({"error": "Недостаточно данных"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    if not is_chat_member(chat_id, user_id):
                        await websocket.send(json.dumps({"error": "Нет доступа к чату"}))
                        continue
                    
                    members = get_chat_members(chat_id)
                    sent_time = datetime.now().strftime('%H:%M')
                    
                    for member_id in members:
                        if member_id != user_id and member_id in active_connections:
                            try:
                                await active_connections[member_id].send(json.dumps({
                                    "cmd": "NEW_VOICE",
                                    "voice": {
                                        "chat_id": chat_id,
                                        "sender_id": user_id,
                                        "voice_data": voice_data,
                                        "duration": duration,
                                        "time": sent_time
                                    }
                                }))
                                logger.info(f"🎤 Голосовое отправлено участнику {member_id}")
                            except Exception as e:
                                logger.error(f"❌ Ошибка отправки голосового: {e}")
                    
                    await websocket.send(json.dumps({"status": "VOICE_SENT"}))

                # --- ОТПРАВКА ФАЙЛА ---
                elif command == "SEND_FILE":
                    chat_id = data.get("chat_id")
                    file_name = data.get("fileName")
                    file_size = data.get("fileSize")
                    file_data = data.get("fileData")
                    
                    if not chat_id or not file_name or not file_data:
                        await websocket.send(json.dumps({"error": "Недостаточно данных"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    if not is_chat_member(chat_id, user_id):
                        await websocket.send(json.dumps({"error": "Нет доступа к чату"}))
                        continue
                    
                    members = get_chat_members(chat_id)
                    message_id = f"msg_{uuid.uuid4().hex[:16]}"
                    sent_time = datetime.now().strftime('%H:%M')
                    
                    for member_id in members:
                        if member_id != user_id and member_id in active_connections:
                            try:
                                await active_connections[member_id].send(json.dumps({
                                    "cmd": "NEW_MESSAGE",
                                    "message": {
                                        "id": message_id,
                                        "chat_id": chat_id,
                                        "sender_id": user_id,
                                        "text": f"📎 {file_name}",
                                        "time": sent_time,
                                        "isFile": True,
                                        "fileName": file_name,
                                        "fileSize": file_size,
                                        "fileData": file_data
                                    }
                                }))
                            except:
                                pass
                    
                    await websocket.send(json.dumps({
                        "status": "FILE_SENT",
                        "chat_id": chat_id,
                        "fileName": file_name,
                        "message": "Файл отправлен"
                    }))

                # --- ЗВОНОК: ЗАПРОС ---
                elif command == "CALL_REQUEST":
                    target_user_id = data.get("target_user_id")
                    is_video = data.get("is_video", False)
                    caller_name = data.get("caller_name")
                    sdp = data.get("sdp")
                    
                    if not target_user_id:
                        await websocket.send(json.dumps({"error": "ID пользователя не указан"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    
                    target_user_id = int(target_user_id)
                    user = get_user_by_id(user_id)
                    caller_name = caller_name or (user.get("nickname", f"User {user_id}") if user else f"User {user_id}")
                    
                    if target_user_id in active_connections:
                        try:
                            await active_connections[target_user_id].send(json.dumps({
                                "cmd": "CALL_REQUEST",
                                "from_id": user_id,
                                "from_name": caller_name,
                                "is_video": is_video,
                                "sdp": sdp
                            }))
                            await websocket.send(json.dumps({"status": "CALL_REQUEST_SENT"}))
                        except:
                            await websocket.send(json.dumps({"error": "Не удалось отправить запрос"}))
                    else:
                        await websocket.send(json.dumps({"error": "Пользователь не в сети"}))

                # --- ЗВОНОК: ПРИНЯТИЕ ---
                elif command == "CALL_ACCEPT":
                    target_user_id = data.get("target_user_id")
                    sdp = data.get("sdp")
                    
                    if not target_user_id:
                        await websocket.send(json.dumps({"error": "ID пользователя не указан"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    
                    target_user_id = int(target_user_id)
                    if target_user_id in active_connections:
                        try:
                            await active_connections[target_user_id].send(json.dumps({
                                "cmd": "CALL_ACCEPT",
                                "from_id": user_id,
                                "sdp": sdp
                            }))
                            await websocket.send(json.dumps({"status": "CALL_ACCEPTED"}))
                        except:
                            await websocket.send(json.dumps({"error": "Не удалось отправить подтверждение"}))
                    else:
                        await websocket.send(json.dumps({"error": "Пользователь не в сети"}))

                # --- ЗВОНОК: ОТКЛОНЕНИЕ ---
                elif command == "CALL_REJECT":
                    target_user_id = data.get("target_user_id")
                    if not target_user_id:
                        await websocket.send(json.dumps({"error": "ID пользователя не указан"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    
                    target_user_id = int(target_user_id)
                    if target_user_id in active_connections:
                        try:
                            await active_connections[target_user_id].send(json.dumps({
                                "cmd": "CALL_REJECT",
                                "from_id": user_id
                            }))
                            await websocket.send(json.dumps({"status": "CALL_REJECTED"}))
                        except:
                            await websocket.send(json.dumps({"error": "Не удалось отправить отклонение"}))
                    else:
                        await websocket.send(json.dumps({"error": "Пользователь не в сети"}))

                # --- ЗВОНОК: ЗАВЕРШЕНИЕ ---
                elif command == "CALL_END":
                    target_user_id = data.get("target_user_id")
                    if not target_user_id:
                        await websocket.send(json.dumps({"error": "ID пользователя не указан"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    
                    target_user_id = int(target_user_id)
                    if target_user_id in active_connections:
                        try:
                            await active_connections[target_user_id].send(json.dumps({
                                "cmd": "CALL_END",
                                "from_id": user_id
                            }))
                        except:
                            pass
                    await websocket.send(json.dumps({"status": "CALL_ENDED"}))

                # --- ICE CANDIDATE ---
                elif command == "ICE_CANDIDATE":
                    target_user_id = data.get("target_user_id")
                    candidate = data.get("candidate")
                    
                    if not target_user_id or not candidate:
                        await websocket.send(json.dumps({"error": "Недостаточно данных"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    
                    target_user_id = int(target_user_id)
                    if target_user_id in active_connections:
                        try:
                            await active_connections[target_user_id].send(json.dumps({
                                "cmd": "ICE_CANDIDATE",
                                "from_id": user_id,
                                "candidate": candidate
                            }))
                        except:
                            pass

                # --- УПРАВЛЕНИЕ СЕССИЯМИ ---
                elif command == "GET_SESSIONS":
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    sessions = get_user_sessions(user_id)
                    await websocket.send(json.dumps({
                        "cmd": "SESSIONS_LIST",
                        "sessions": sessions
                    }))

                elif command == "TERMINATE_SESSION":
                    session_to_remove = data.get("session_id")
                    if not session_to_remove:
                        await websocket.send(json.dumps({"error": "ID сессии не указан"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    
                    if session_to_remove == session_id:
                        await websocket.send(json.dumps({"error": "Нельзя удалить текущую сессию"}))
                        continue
                    
                    remove_user_session(session_to_remove)
                    await websocket.send(json.dumps({
                        "status": "SESSION_TERMINATED",
                        "session_id": session_to_remove
                    }))

                # --- ОСТАЛЬНЫЕ КОМАНДЫ ---
                elif command == "UPDATE_PRIVACY":
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    hide_online = data.get("hide_online")
                    hide_last_seen = data.get("hide_last_seen")
                    if update_user_privacy(user_id, hide_online, hide_last_seen):
                        await websocket.send(json.dumps({
                            "status": "PRIVACY_UPDATED",
                            "message": "Настройки приватности обновлены"
                        }))
                    else:
                        await websocket.send(json.dumps({"error": "Ошибка обновления"}))

                elif command == "ACTIVATE_PREMIUM":
                    plan = data.get("plan")
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    if plan == "1day" and has_used_free_trial(user_id):
                        await websocket.send(json.dumps({"error": "Бесплатный день уже использован"}))
                        continue
                    if activate_premium(user_id, plan):
                        await websocket.send(json.dumps({
                            "status": "PREMIUM_ACTIVATED",
                            "plan": plan,
                            "message": f"Premium {plan} активирован!"
                        }))
                    else:
                        await websocket.send(json.dumps({"error": "Ошибка активации"}))

                elif command == "SEND_FRIEND_REQUEST":
                    target_user_id = data.get("target_user_id")
                    if not target_user_id:
                        await websocket.send(json.dumps({"error": "ID пользователя не указан"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    target_user_id = int(target_user_id)
                    target = get_user_by_id(target_user_id)
                    if not target:
                        await websocket.send(json.dumps({"error": "Пользователь не найден"}))
                        continue
                    if send_friend_request(user_id, target_user_id):
                        await websocket.send(json.dumps({
                            "status": "FRIEND_REQUEST_SENT",
                            "target_user_id": target_user_id,
                            "message": "Запрос отправлен"
                        }))
                    else:
                        await websocket.send(json.dumps({"error": "Запрос уже отправлен"}))

                elif command == "GET_FRIEND_REQUESTS":
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    requests = get_friend_requests(user_id)
                    await websocket.send(json.dumps({
                        "cmd": "FRIEND_REQUESTS_LIST",
                        "requests": requests
                    }))

                elif command == "ACCEPT_FRIEND_REQUEST":
                    from_user_id = data.get("from_user_id")
                    if not from_user_id:
                        await websocket.send(json.dumps({"error": "ID отправителя не указан"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    from_user_id = int(from_user_id)
                    if accept_friend_request(user_id, from_user_id):
                        await websocket.send(json.dumps({
                            "status": "FRIEND_REQUEST_ACCEPTED",
                            "chat_id": generate_private_chat_id(user_id, from_user_id)
                        }))
                    else:
                        await websocket.send(json.dumps({"error": "Запрос не найден"}))

                elif command == "REJECT_FRIEND_REQUEST":
                    from_user_id = data.get("from_user_id")
                    if not from_user_id:
                        await websocket.send(json.dumps({"error": "ID отправителя не указан"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    from_user_id = int(from_user_id)
                    if reject_friend_request(user_id, from_user_id):
                        await websocket.send(json.dumps({
                            "status": "FRIEND_REQUEST_REJECTED"
                        }))
                    else:
                        await websocket.send(json.dumps({"error": "Запрос не найден"}))

                elif command == "SEARCH_USERS":
                    query = data.get("query", "")
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    users = search_users(query, user_id)
                    for user in users:
                        user_id_to_check = user["id"]
                        user["is_online"] = user["is_online"] and user_id_to_check not in hidden_online_users
                        user["last_seen_display"] = format_last_seen(user["last_seen"], user_id_to_check in hidden_last_seen_users)
                    await websocket.send(json.dumps({
                        "cmd": "SEARCH_RESULTS",
                        "users": users
                    }))

                elif command == "GET_USER_INFO":
                    target_id = data.get("user_id")
                    if not target_id:
                        await websocket.send(json.dumps({"error": "ID не указан"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    target_id = int(target_id)
                    user = get_user_by_id(target_id)
                    if user:
                        user["is_online"] = user["is_online"] and target_id not in hidden_online_users
                        user["last_seen_display"] = format_last_seen(user["last_seen"], target_id in hidden_last_seen_users)
                        user["is_premium"] = is_premium(target_id)
                        chat_id = generate_private_chat_id(user_id, target_id)
                        user["existing_chat_id"] = chat_id if is_chat_member(chat_id, user_id) else None
                        await websocket.send(json.dumps({
                            "cmd": "USER_INFO",
                            "user_info": user
                        }))
                    else:
                        await websocket.send(json.dumps({"error": "Пользователь не найден"}))

                elif command == "CREATE_GROUP":
                    name = data.get("name")
                    description = data.get("description", "")
                    if not name:
                        await websocket.send(json.dumps({"error": "Название группы не указано"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    chat_id = generate_group_id()
                    create_chat(chat_id, name, "group", user_id, description, is_public=False)
                    add_chat_member(chat_id, user_id, 'owner')
                    invite_code = generate_invite_code(chat_id, user_id)
                    await websocket.send(json.dumps({
                        "status": "GROUP_CREATED",
                        "chat_id": chat_id,
                        "invite_code": invite_code
                    }))

                elif command == "CREATE_CHANNEL":
                    name = data.get("name")
                    description = data.get("description", "")
                    is_public = data.get("is_public", False)
                    if not name:
                        await websocket.send(json.dumps({"error": "Название канала не указано"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    chat_id = generate_channel_id()
                    create_chat(chat_id, name, "channel", user_id, description, is_public)
                    add_chat_member(chat_id, user_id, 'owner')
                    await websocket.send(json.dumps({
                        "status": "CHANNEL_CREATED",
                        "chat_id": chat_id
                    }))

                elif command == "GET_CHAT_INFO":
                    chat_id = data.get("chat_id")
                    if not chat_id:
                        await websocket.send(json.dumps({"error": "ID чата не указан"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    chat_info = get_chat_info(chat_id, user_id)
                    if chat_info:
                        if chat_info["type"] == "private" and chat_id.startswith("private_"):
                            parts = chat_id.split('_')
                            if len(parts) == 3:
                                other_id = int(parts[2]) if int(parts[2]) != user_id else int(parts[1])
                                other = get_user_by_id(other_id)
                                if other:
                                    is_online = other["is_online"] and other_id not in hidden_online_users
                                    chat_info["other_user_status"] = "в сети" if is_online else "не в сети"
                                    chat_info["other_user_nickname"] = other["nickname"]
                                    chat_info["other_user_is_premium"] = is_premium(other_id)
                        await websocket.send(json.dumps({
                            "cmd": "CHAT_INFO",
                            "chat_info": chat_info
                        }))
                    else:
                        await websocket.send(json.dumps({"error": "Чат не найден"}))

                elif command == "DELETE_CHAT":
                    chat_id = data.get("chat_id")
                    if not chat_id:
                        await websocket.send(json.dumps({"error": "ID чата не указан"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    
                    if chat_id.startswith("private_"):
                        conn = sqlite3.connect(DATABASE)
                        cursor = conn.cursor()
                        cursor.execute("UPDATE chat_members SET left_at = CURRENT_TIMESTAMP WHERE chat_id = ? AND user_id = ?", (chat_id, user_id))
                        conn.commit()
                        conn.close()
                        await websocket.send(json.dumps({"status": "CHAT_DELETED", "message": "Чат удалён"}))
                    else:
                        await websocket.send(json.dumps({"error": "Нельзя удалить этот тип чата"}))

                elif command == "UPDATE_NICKNAME":
                    nickname = data.get("nickname")
                    if not nickname:
                        await websocket.send(json.dumps({"error": "Никнейм не указан"}))
                        continue
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    conn = sqlite3.connect(DATABASE)
                    cursor = conn.cursor()
                    cursor.execute("UPDATE users SET nickname = ? WHERE id = ?", (nickname, user_id))
                    conn.commit()
                    conn.close()
                    await websocket.send(json.dumps({
                        "status": "NICKNAME_UPDATED",
                        "nickname": nickname
                    }))

                elif command == "PING":
                    if user_id:
                        await websocket.send(json.dumps({
                            "status": "PONG",
                            "time": datetime.now().strftime('%H:%M:%S')
                        }))

                else:
                    logger.warning(f"❓ Неизвестная команда: {command}")
                    await websocket.send(json.dumps({"error": f"Неизвестная команда: {command}"}))

            except json.JSONDecodeError as e:
                logger.error(f"❌ Невалидный JSON: {e}")
                await websocket.send(json.dumps({"error": "Невалидный JSON"}))
            except Exception as e:
                logger.error(f"❌ Ошибка обработки: {e}")
                logger.error(traceback.format_exc())
                await websocket.send(json.dumps({"error": f"Внутренняя ошибка: {str(e)}"}))

    except websockets.exceptions.ConnectionClosed as e:
        logger.info(f"🔌 Соединение закрыто: {e}")
    except Exception as e:
        logger.error(f"💥 Ошибка: {e}")
    finally:
        if user_id:
            if user_id in active_connections:
                del active_connections[user_id]
            if user_id in online_users:
                online_users.remove(user_id)
            update_user_status(user_id, False)
            if user_id not in hidden_online_users:
                await notify_contacts_status_change(user_id, False)
            logger.info(f"👋 Пользователь {user_id} отключился")

async def main():
    try:
        init_database()
        asyncio.create_task(check_expired_premium())
        asyncio.create_task(auto_ping())
        async with websockets.serve(
            ws_handler,
            HOST,
            PORT,
            process_request=handle_http_request,
            ping_interval=20,
            ping_timeout=60,
            max_size=50 * 1024 * 1024
        ) as server:
            logger.info(f"✅ Сервер AnonimGram запущен на ws://{HOST}:{PORT}")
            logger.info(f"📊 База данных: {DATABASE}")
            logger.info(f"🔐 Анонимность: IP-адреса скрыты")
            logger.info(f"📱 Сессии: только устройства и браузеры")
            logger.info("⏳ Сервер готов...")
            await asyncio.Future()
    except Exception as e:
        logger.error(f"❌ Ошибка запуска: {e}")
        raise

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("👋 Сервер остановлен")