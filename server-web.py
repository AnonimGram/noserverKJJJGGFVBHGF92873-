import asyncio
import websockets
import json
import hashlib
import logging
import uuid
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Set
import sys
import traceback
from pathlib import Path

# --- НАСТРОЙКИ ---
HOST = '0.0.0.0'
PORT = 8080
DATABASE = 'anonimgram.db'

# --- ЛОГИРОВАНИЕ ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ---
active_connections: Dict[int, websockets.WebSocketServerProtocol] = {}  # user_id -> websocket
online_users: Set[int] = set()  # множество онлайн пользователей
typing_status: Dict[str, Set[int]] = {}  # chat_id -> кто печатает
hidden_online_users: Set[int] = set()  # пользователи, скрывшие онлайн-статус
hidden_last_seen_users: Set[int] = set()  # пользователи, скрывшие последний визит

# --- РАБОТА С БАЗОЙ ДАННЫХ ---
def init_database():
    """Инициализация базы данных"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Таблица пользователей с настройками приватности
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        login TEXT UNIQUE NOT NULL,
        nickname TEXT DEFAULT '',
        password_hash TEXT DEFAULT '',
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_online BOOLEAN DEFAULT 0,
        hide_online BOOLEAN DEFAULT 0,
        hide_last_seen BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        deleted_at TIMESTAMP NULL
    )''')
    
    # Таблица чатов
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS chats (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT CHECK(type IN ('private', 'group', 'system')) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        deleted_at TIMESTAMP NULL
    )''')
    
    # Таблица участников чатов
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS chat_members (
        chat_id TEXT,
        user_id INTEGER,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        left_at TIMESTAMP NULL,
        PRIMARY KEY (chat_id, user_id)
    )''')
    
    conn.commit()
    conn.close()
    logger.info("✅ База данных инициализирована")

def get_user_by_login(login: str) -> Optional[Dict]:
    """Получение пользователя по логину (только неудаленные)"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, login, nickname, last_seen, is_online, hide_online, hide_last_seen FROM users WHERE login = ? AND deleted_at IS NULL", 
        (login,)
    )
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def get_user_by_id(user_id: int) -> Optional[Dict]:
    """Получение пользователя по ID (только неудаленные)"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, login, nickname, last_seen, is_online, hide_online, hide_last_seen FROM users WHERE id = ? AND deleted_at IS NULL", 
        (user_id,)
    )
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def search_users(query: str, current_user_id: int) -> list:
    """Поиск пользователей (только неудаленные)"""
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
        # Не показываем онлайн-статус если пользователь скрыл его
        if user_dict['hide_online']:
            user_dict['is_online'] = False
        result.append(user_dict)
    
    return result

def create_user(login: str, nickname: str) -> int:
    """Создание нового пользователя"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (login, nickname, last_seen, is_online) VALUES (?, ?, CURRENT_TIMESTAMP, 1)",
        (login, nickname)
    )
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return user_id

def update_user_status(user_id: int, is_online: bool):
    """Обновление статуса пользователя"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET is_online = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ? AND deleted_at IS NULL",
        (1 if is_online else 0, user_id)
    )
    conn.commit()
    conn.close()

def update_user_privacy(user_id: int, hide_online: bool = None, hide_last_seen: bool = None):
    """Обновление настроек приватности пользователя"""
    updates = []
    params = []
    
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
    cursor.execute(
        f"UPDATE users SET {', '.join(updates)} WHERE id = ? AND deleted_at IS NULL",
        params
    )
    conn.commit()
    conn.close()
    return True

def delete_user_account(user_id: int) -> bool:
    """Полное удаление аккаунта пользователя"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Помечаем пользователя как удаленного
        cursor.execute(
            "UPDATE users SET deleted_at = CURRENT_TIMESTAMP, is_online = 0 WHERE id = ?",
            (user_id,)
        )
        
        # Помечаем чаты как удаленные (опционально)
        cursor.execute(
            "UPDATE chat_members SET left_at = CURRENT_TIMESTAMP WHERE user_id = ?",
            (user_id,)
        )
        
        conn.commit()
        conn.close()
        
        # Удаляем из глобальных переменных
        if user_id in active_connections:
            del active_connections[user_id]
        if user_id in online_users:
            online_users.remove(user_id)
        if user_id in hidden_online_users:
            hidden_online_users.remove(user_id)
        if user_id in hidden_last_seen_users:
            hidden_last_seen_users.remove(user_id)
        
        logger.info(f"✅ Аккаунт пользователя {user_id} удален")
        return True
    except Exception as e:
        logger.error(f"❌ Ошибка удаления аккаунта: {e}")
        return False

def get_or_create_chat(chat_id: str, name: str, chat_type: str) -> bool:
    """Получение или создание чата"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT OR IGNORE INTO chats (id, name, type) VALUES (?, ?, ?)",
            (chat_id, name, chat_type)
        )
        conn.commit()
        return True
    except:
        return False
    finally:
        conn.close()

def add_chat_member(chat_id: str, user_id: int):
    """Добавление участника в чат"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO chat_members (chat_id, user_id) VALUES (?, ?)",
        (chat_id, user_id)
    )
    conn.commit()
    conn.close()

def remove_chat_member(chat_id: str, user_id: int):
    """Удаление участника из чата (при удалении аккаунта)"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE chat_members SET left_at = CURRENT_TIMESTAMP WHERE chat_id = ? AND user_id = ?",
        (chat_id, user_id)
    )
    conn.commit()
    conn.close()

def get_user_chats(user_id: int) -> list:
    """Получение списка чатов пользователя (только активные)"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT c.id, c.name, c.type
        FROM chats c
        JOIN chat_members cm ON c.id = cm.chat_id
        WHERE cm.user_id = ? AND cm.left_at IS NULL AND c.deleted_at IS NULL
        ORDER BY c.created_at DESC
    ''', (user_id,))
    chats = cursor.fetchall()
    conn.close()
    return [dict(chat) for chat in chats]

def is_chat_member(chat_id: str, user_id: int) -> bool:
    """Проверка, является ли пользователь участником чата"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ? AND left_at IS NULL",
        (chat_id, user_id)
    )
    result = cursor.fetchone() is not None
    conn.close()
    return result

def cleanup_deleted_accounts(days: int = 30):
    """Очистка полностью удаленных аккаунтов старше N дней"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM users WHERE deleted_at IS NOT NULL AND deleted_at < datetime('now', ?)",
        (f'-{days} days',)
    )
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    if deleted > 0:
        logger.info(f"🧹 Очищено {deleted} старых удаленных аккаунтов")

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
def generate_chat_id() -> str:
    """Генерирует ID для группового чата"""
    return f"group_{uuid.uuid4().hex[:12]}"

def generate_temp_id() -> str:
    """Генерирует временный ID для сообщения"""
    return f"msg_{uuid.uuid4().hex[:16]}"

def get_current_time() -> str:
    return datetime.now().strftime('%H:%M')

def get_current_timestamp() -> str:
    return datetime.now().isoformat()

def format_last_seen(timestamp: str, hide_last_seen: bool = False) -> str:
    """Форматирование времени последнего визита с учетом приватности"""
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

async def notify_contacts_status_change(user_id: int, is_online: bool):
    """Уведомление контактов об изменении статуса"""
    # Получаем все чаты пользователя
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
    
    # Уведомляем контакты
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

# --- ОСНОВНОЙ ОБРАБОТЧИК WEBSOCKET ---
async def ws_handler(websocket):
    """Обработчик WebSocket соединений"""
    session_id = str(uuid.uuid4())[:8]
    logger.info(f"🔌 Новое подключение (сессия: {session_id})")
    user_id = None

    try:
        async for message in websocket:
            try:
                data = json.loads(message)
                command = data.get("cmd")
                logger.info(f"📨 Команда: {command} (сессия: {session_id})")

                # --- РЕГИСТРАЦИЯ ---
                if command == "REGISTER":
                    login = data.get("login")
                    if not login:
                        await websocket.send(json.dumps({"error": "Логин не указан"}))
                        continue

                    existing = get_user_by_login(login)
                    if existing:
                        await websocket.send(json.dumps({"error": "Пользователь существует"}))
                        continue

                    user_id = create_user(login, login)
                    
                    anonimgram_chat_id = f"anonimgram_{user_id}"
                    get_or_create_chat(anonimgram_chat_id, "AnonimGram", "system")
                    add_chat_member(anonimgram_chat_id, user_id)

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
                    
                    user = get_user_by_login(login)
                    
                    if not user:
                        # Автоматическая регистрация
                        user_id = create_user(login, login)
                        anonimgram_chat_id = f"anonimgram_{user_id}"
                        get_or_create_chat(anonimgram_chat_id, "AnonimGram", "system")
                        add_chat_member(anonimgram_chat_id, user_id)
                        logger.info(f"✅ Автоматическая регистрация: ID {user_id}")
                    else:
                        user_id = user["id"]
                        
                        # Проверяем настройки приватности
                        if user.get("hide_online"):
                            hidden_online_users.add(user_id)
                        if user.get("hide_last_seen"):
                            hidden_last_seen_users.add(user_id)

                    # Если пользователь уже онлайн, отключаем старое соединение
                    if user_id in active_connections:
                        try:
                            await active_connections[user_id].close()
                        except:
                            pass

                    active_connections[user_id] = websocket
                    online_users.add(user_id)
                    update_user_status(user_id, True)
                    
                    # Уведомляем контакты о входе (только если не скрыто)
                    if user_id not in hidden_online_users:
                        await notify_contacts_status_change(user_id, True)

                    user = get_user_by_id(user_id)

                    await websocket.send(json.dumps({
                        "status": "LOGGED_IN",
                        "user_id": user_id,
                        "user_info": user
                    }))
                    logger.info(f"✅ Вход выполнен: ID {user_id}")

                # --- ОБНОВЛЕНИЕ НАСТРОЕК ПРИВАТНОСТИ ---
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
                        
                        # Если изменился онлайн-статус, уведомляем контакты
                        if hide_online is not None:
                            if hide_online:
                                # Стали невидимыми - уведомляем что офлайн
                                await notify_contacts_status_change(user_id, False)
                            else:
                                # Стали видимыми - показываем реальный статус
                                if user_id in online_users:
                                    await notify_contacts_status_change(user_id, True)
                    else:
                        await websocket.send(json.dumps({"error": "Ошибка обновления"}))

                # --- УДАЛЕНИЕ АККАУНТА ---
                elif command == "DELETE_ACCOUNT":
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue
                    
                    confirm = data.get("confirm", False)
                    if not confirm:
                        await websocket.send(json.dumps({
                            "error": "Требуется подтверждение",
                            "need_confirm": True
                        }))
                        continue
                    
                    # Уведомляем контакты об уходе
                    await notify_contacts_status_change(user_id, False)
                    
                    # Удаляем аккаунт
                    if delete_user_account(user_id):
                        await websocket.send(json.dumps({
                            "status": "ACCOUNT_DELETED",
                            "message": "Аккаунт успешно удален"
                        }))
                        
                        # Закрываем соединение
                        await websocket.close()
                    else:
                        await websocket.send(json.dumps({"error": "Ошибка удаления аккаунта"}))

                # --- ПОЛУЧЕНИЕ СПИСКА ЧАТОВ ---
                elif command == "GET_CHATS":
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue

                    chats = get_user_chats(user_id)
                    
                    # Добавляем информацию о собеседниках
                    for chat in chats:
                        if chat["type"] == "private" and not chat["id"].startswith("anonimgram_"):
                            parts = chat["id"].split('_')
                            if len(parts) == 3:
                                other_id = int(parts[2]) if int(parts[2]) != user_id else int(parts[1])
                                other = get_user_by_id(other_id)
                                if other:
                                    # Применяем настройки приватности
                                    is_online = other["is_online"] and other_id not in hidden_online_users
                                    last_seen = format_last_seen(
                                        other["last_seen"], 
                                        other_id in hidden_last_seen_users
                                    )
                                    
                                    chat["other_user"] = {
                                        "id": other["id"],
                                        "nickname": other["nickname"],
                                        "is_online": is_online,
                                        "last_seen": last_seen
                                    }
                                    chat["name"] = other["nickname"]

                    await websocket.send(json.dumps({
                        "cmd": "CHATS_LIST",
                        "chats": chats
                    }))

                # --- ПОЛУЧЕНИЕ СООБЩЕНИЙ ---
                elif command == "GET_MESSAGES":
                    chat_id = data.get("chat_id")
                    
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue

                    if not is_chat_member(chat_id, user_id):
                        await websocket.send(json.dumps({"error": "Нет доступа к чату"}))
                        continue

                    messages = []
                    
                    if chat_id == f"anonimgram_{user_id}":
                        messages.append({
                            "id": generate_temp_id(),
                            "text": "🔐 Анонимный чат. Сообщения не сохраняются.",
                            "time": get_current_time(),
                            "sender_id": 0,
                            "is_system": True
                        })

                    await websocket.send(json.dumps({
                        "cmd": "MESSAGES",
                        "messages": messages,
                        "chat_id": chat_id
                    }))

                # --- ОТПРАВКА СООБЩЕНИЯ ---
                elif command == "SEND_MESSAGE":
                    chat_id = data.get("chat_id")
                    text = data.get("text")
                    
                    if not chat_id or not text:
                        await websocket.send(json.dumps({"error": "Недостаточно данных"}))
                        continue

                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue

                    if not is_chat_member(chat_id, user_id):
                        await websocket.send(json.dumps({"error": "Нет доступа к чату"}))
                        continue

                    # Получаем всех участников чата
                    conn = sqlite3.connect(DATABASE)
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT user_id FROM chat_members WHERE chat_id = ? AND left_at IS NULL", 
                        (chat_id,)
                    )
                    members = cursor.fetchall()
                    conn.close()

                    message_id = generate_temp_id()
                    sent_time = get_current_time()

                    # Отправляем всем участникам
                    for (member_id,) in members:
                        if member_id in active_connections:
                            try:
                                await active_connections[member_id].send(json.dumps({
                                    "cmd": "NEW_MESSAGE",
                                    "message": {
                                        "id": message_id,
                                        "chat_id": chat_id,
                                        "sender_id": user_id,
                                        "text": text,
                                        "time": sent_time,
                                        "is_my": member_id == user_id
                                    }
                                }))
                            except:
                                pass

                # --- ПОИСК ПОЛЬЗОВАТЕЛЕЙ ---
                elif command == "SEARCH_USERS":
                    query = data.get("query", "")
                    
                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue

                    users = search_users(query, user_id)
                    
                    # Форматируем last_seen с учетом приватности
                    for user in users:
                        user_id_to_check = user["id"]
                        user["is_online"] = user["is_online"] and user_id_to_check not in hidden_online_users
                        user["last_seen_display"] = format_last_seen(
                            user["last_seen"],
                            user_id_to_check in hidden_last_seen_users
                        )

                    await websocket.send(json.dumps({
                        "cmd": "SEARCH_RESULTS",
                        "users": users
                    }))

                # --- ПОЛУЧЕНИЕ ИНФОРМАЦИИ О ПОЛЬЗОВАТЕЛЕ ---
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
                        # Применяем настройки приватности
                        user["is_online"] = user["is_online"] and target_id not in hidden_online_users
                        user["last_seen_display"] = format_last_seen(
                            user["last_seen"],
                            target_id in hidden_last_seen_users
                        )
                        
                        # Проверяем существующий чат
                        chat_id = f"private_{min(user_id, target_id)}_{max(user_id, target_id)}"
                        user["existing_chat_id"] = chat_id if is_chat_member(chat_id, user_id) else None
                        
                        await websocket.send(json.dumps({
                            "cmd": "USER_INFO",
                            "user_info": user
                        }))
                    else:
                        await websocket.send(json.dumps({"error": "Пользователь не найден"}))

                # --- СОЗДАНИЕ ПРИВАТНОГО ЧАТА ---
                elif command == "CREATE_PRIVATE_CHAT":
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

                    chat_id = f"private_{min(user_id, target_user_id)}_{max(user_id, target_user_id)}"
                    
                    target_name = target.get("nickname", f"User {target_user_id}")
                    get_or_create_chat(chat_id, target_name, "private")
                    
                    add_chat_member(chat_id, user_id)
                    add_chat_member(chat_id, target_user_id)

                    # Уведомляем второго пользователя
                    if target_user_id in active_connections:
                        current_user = get_user_by_id(user_id)
                        await active_connections[target_user_id].send(json.dumps({
                            "cmd": "NEW_CHAT",
                            "chat": {
                                "id": chat_id,
                                "name": current_user.get("nickname", f"User {user_id}"),
                                "type": "private"
                            }
                        }))

                    await websocket.send(json.dumps({
                        "status": "CHAT_CREATED",
                        "chat_id": chat_id
                    }))

                # --- СОЗДАНИЕ ГРУППЫ ---
                elif command == "CREATE_GROUP":
                    name = data.get("name")
                    members = data.get("members", [])
                    
                    if not name:
                        await websocket.send(json.dumps({"error": "Название группы не указано"}))
                        continue

                    if user_id is None:
                        await websocket.send(json.dumps({"error": "Не авторизован"}))
                        continue

                    chat_id = generate_chat_id()
                    get_or_create_chat(chat_id, name, "group")
                    
                    # Добавляем создателя
                    add_chat_member(chat_id, user_id)
                    
                    # Добавляем остальных участников
                    all_members = {user_id}
                    for member_id in members:
                        add_chat_member(chat_id, member_id)
                        all_members.add(member_id)

                    # Уведомляем всех участников
                    for member_id in all_members:
                        if member_id in active_connections and member_id != user_id:
                            try:
                                await active_connections[member_id].send(json.dumps({
                                    "cmd": "NEW_CHAT",
                                    "chat": {
                                        "id": chat_id,
                                        "name": name,
                                        "type": "group"
                                    }
                                }))
                            except:
                                pass

                    await websocket.send(json.dumps({
                        "status": "GROUP_CREATED",
                        "chat_id": chat_id
                    }))

                # --- СТАТУС НАБОРА ТЕКСТА ---
                elif command == "TYPING":
                    chat_id = data.get("chat_id")
                    is_typing = data.get("is_typing", True)
                    
                    if not chat_id or user_id is None:
                        continue

                    # Получаем участников чата
                    conn = sqlite3.connect(DATABASE)
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT user_id FROM chat_members WHERE chat_id = ? AND left_at IS NULL",
                        (chat_id,)
                    )
                    members = cursor.fetchall()
                    conn.close()

                    for (member_id,) in members:
                        if member_id != user_id and member_id in active_connections:
                            try:
                                await active_connections[member_id].send(json.dumps({
                                    "cmd": "USER_TYPING",
                                    "chat_id": chat_id,
                                    "user_id": user_id,
                                    "is_typing": is_typing
                                }))
                            except:
                                pass

                # --- PING ---
                elif command == "PING":
                    if user_id:
                        await websocket.send(json.dumps({
                            "status": "PONG",
                            "time": get_current_time()
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
            
            # Уведомляем контакты об уходе (только если не скрыто)
            if user_id not in hidden_online_users:
                await notify_contacts_status_change(user_id, False)
            
            logger.info(f"👋 Пользователь {user_id} отключился")

# --- ОБРАБОТКА HTTP (HEALTH CHECK) ---
async def handle_http_request(path, request_headers):
    """Обрабатывает HTTP-запросы для health check"""
    if path == "/" or path == "/health":
        headers = [
            ("Content-Type", "text/plain"),
            ("Content-Length", "2"),
            ("Connection", "close")
        ]
        return (200, headers, b"OK")
    return None

# --- ПЕРИОДИЧЕСКАЯ ОЧИСТКА ---
async def periodic_cleanup():
    """Периодическая очистка старых удаленных аккаунтов"""
    while True:
        await asyncio.sleep(86400)  # Раз в день
        cleanup_deleted_accounts(30)  # Удаляем аккаунты старше 30 дней

# --- ЗАПУСК СЕРВЕРА ---
async def main():
    try:
        init_database()
        
        # Запускаем периодическую очистку
        asyncio.create_task(periodic_cleanup())
        
        async with websockets.serve(
            ws_handler,
            HOST,
            PORT,
            process_request=handle_http_request,
            ping_interval=20,
            ping_timeout=60
        ) as server:
            logger.info(f"✅ Анонимный сервер AnonimGram запущен на ws://{HOST}:{PORT}")
            logger.info(f"📊 База данных: {DATABASE}")
            logger.info(f"👤 Онлайн-статус: можно скрыть")
            logger.info(f"🗑️ Удаление аккаунтов: поддерживается")
            logger.info(f"📢 Сообщения НЕ сохраняются!")
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
