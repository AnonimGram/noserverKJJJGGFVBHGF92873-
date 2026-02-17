# server_ws.py
import asyncio
import websockets
import json
import aiosqlite
import hashlib
import logging
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, Set

# --- НАСТРОЙКИ ---
HOST = '0.0.0.0'
PORT = 8080
DATABASE = 'anonimgram_server.db'

# --- ЛОГИРОВАНИЕ ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ---
clients: Dict[int, websockets.WebSocketServerProtocol] = {}
user_sessions: Dict[websockets.WebSocketServerProtocol, int] = {}
active_chats: Dict[str, Dict] = {}
online_users: Set[int] = set()

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
def hash_password(password: str) -> str:
    """Хеширование пароля"""
    return hashlib.sha256(password.encode()).hexdigest()

# --- РАБОТА С БАЗОЙ ДАННЫХ ---
async def init_database():
    """Инициализация базы данных"""
    async with aiosqlite.connect(DATABASE) as db:
        # Таблица пользователей
        await db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            login TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            nickname TEXT DEFAULT '',
            username TEXT DEFAULT '',
            avatar_path TEXT DEFAULT '',
            hide_last_seen BOOLEAN DEFAULT 0,
            hide_online BOOLEAN DEFAULT 0,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_online BOOLEAN DEFAULT 0
        )''')

        # Проверяем наличие колонки is_online
        cursor = await db.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in await cursor.fetchall()]
        if 'is_online' not in columns:
            logger.info("Добавляем столбец is_online в таблицу users...")
            await db.execute('ALTER TABLE users ADD COLUMN is_online BOOLEAN DEFAULT 0')

        # Таблица чатов
        await db.execute('''
        CREATE TABLE IF NOT EXISTS chats (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            type TEXT CHECK(type IN ('user', 'group', 'channel')) NOT NULL,
            owner_id INTEGER,
            FOREIGN KEY (owner_id) REFERENCES users (id)
        )''')

        # Таблица участников чатов
        await db.execute('''
        CREATE TABLE IF NOT EXISTS chat_members (
            chat_id TEXT,
            user_id INTEGER,
            role TEXT CHECK(role IN ('member', 'admin', 'owner')),
            PRIMARY KEY (chat_id, user_id),
            FOREIGN KEY (chat_id) REFERENCES chats (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        
        await db.commit()
    logger.info("База данных инициализирована")

async def get_user_by_login(login: str) -> Optional[Dict[str, Any]]:
    """Получение пользователя по логину"""
    async with aiosqlite.connect(DATABASE) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT id, login, password_hash, nickname, username, avatar_path, hide_last_seen, hide_online, last_seen, is_online FROM users WHERE login = ?",
            (login,)
        )
        user = await cursor.fetchone()
        return dict(user) if user else None

async def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Получение пользователя по ID"""
    async with aiosqlite.connect(DATABASE) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT id, login, nickname, username, avatar_path, hide_last_seen, hide_online, last_seen, is_online FROM users WHERE id = ?",
            (user_id,)
        )
        user = await cursor.fetchone()
        return dict(user) if user else None

async def update_user_online_status(user_id: int, is_online: bool):
    """Обновление онлайн статуса пользователя"""
    async with aiosqlite.connect(DATABASE) as db:
        await db.execute(
            "UPDATE users SET is_online = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?",
            (1 if is_online else 0, user_id)
        )
        await db.commit()
    
    if is_online:
        online_users.add(user_id)
    elif user_id in online_users:
        online_users.remove(user_id)

async def get_or_create_direct_chat_id(user1_id: int, user2_id: int) -> str:
    """Создание или получение ID личного чата"""
    sorted_ids = sorted([user1_id, user2_id])
    chat_id = f"direct_{sorted_ids[0]}_{sorted_ids[1]}"
    
    async with aiosqlite.connect(DATABASE) as db:
        await db.execute("INSERT OR IGNORE INTO chats (id, name, type) VALUES (?, ?, ?)",
                        (chat_id, f"Direct between {user1_id} and {user2_id}", 'user'))
        await db.execute("INSERT OR IGNORE INTO chat_members (chat_id, user_id, role) VALUES (?, ?, ?)",
                        (chat_id, user1_id, 'member'))
        await db.execute("INSERT OR IGNORE INTO chat_members (chat_id, user_id, role) VALUES (?, ?, ?)",
                        (chat_id, user2_id, 'member'))
        await db.commit()
    
    if chat_id not in active_chats:
        active_chats[chat_id] = {'members': [user1_id, user2_id], 'type': 'user'}
    
    return chat_id

# --- ОБРАБОТКА HEALTH CHECK ---
async def health_check_handler(path: str, request_headers) -> Optional[tuple]:
    """
    Обработчик health check запросов от Render
    Возвращает HTTP ответ для GET/HEAD запросов на /
    """
    logger.debug(f"Health check request: {path}")
    
    # Render отправляет GET/HEAD запросы на корневой путь для проверки здоровья
    if path == "/" or path == "/health" or path == "/healthz":
        # Возвращаем успешный HTTP ответ
        headers = [
            ("Content-Type", "text/plain"),
            ("Content-Length", "2"),
            ("Connection", "close")
        ]
        return (200, headers, b"OK")
    
    # Для всех остальных путей продолжаем как WebSocket
    return None

# --- ОСНОВНОЙ ОБРАБОТЧИК WEBSOCKET ---
async def handle_client(websocket: websockets.WebSocketServerProtocol, path: str):
    """Обработчик WebSocket соединений"""
    session_id = str(uuid.uuid4())[:8]
    logger.info(f"Новое WebSocket-подключение (сессия: {session_id}, путь: {path})")
    user_id = None

    try:
        async for message in websocket:
            try:
                data = json.loads(message)
                command = data.get("cmd")
                logger.debug(f"Получена команда от сессии {session_id}: {command}")

                # Проверка авторизации для команд, требующих аутентификации
                requires_auth = command in [
                    "GET_CHATS", "GET_MESSAGES", "SEND_MESSAGE", "UPDATE_PROFILE",
                    "GET_USER_INFO", "CREATE_CHAT", "GET_USER_DETAILED_INFO", "PING"
                ]
                
                if requires_auth and user_id is None:
                    await websocket.send(json.dumps({"error": "Пользователь не авторизован"}))
                    continue

                # --- РЕГИСТРАЦИЯ ---
                if command == "REGISTER":
                    login = data.get("login")
                    if not login:
                        await websocket.send(json.dumps({"error": "Логин не указан"}))
                        continue

                    existing_user = await get_user_by_login(login)
                    if existing_user:
                        await websocket.send(json.dumps({"error": "Пользователь существует"}))
                        continue

                    password_hash = hash_password("default_password")
                    async with aiosqlite.connect(DATABASE) as db:
                        cursor = await db.execute(
                            "INSERT INTO users (login, password_hash, nickname) VALUES (?, ?, ?)",
                            (login, password_hash, login)
                        )
                        await db.commit()
                        new_user_id = cursor.lastrowid

                    user_id = new_user_id
                    user_sessions[websocket] = user_id
                    clients[user_id] = websocket
                    await update_user_online_status(user_id, True)

                    # Создаём чат AnonimGram
                    anonimgram_chat_id = f"anonimgram_{new_user_id}"
                    async with aiosqlite.connect(DATABASE) as db:
                        await db.execute("INSERT OR IGNORE INTO chats (id, name, type) VALUES (?, ?, ?)",
                                        (anonimgram_chat_id, "AnonimGram", 'user'))
                        await db.execute("INSERT OR IGNORE INTO chat_members (chat_id, user_id, role) VALUES (?, ?, ?)",
                                        (anonimgram_chat_id, new_user_id, 'member'))
                        await db.commit()
                    
                    active_chats[anonimgram_chat_id] = {"members": [new_user_id], "type": "user"}
                    await websocket.send(json.dumps({"status": "REGISTERED", "user_id": new_user_id}))
                    logger.info(f"Пользователь зарегистрирован: ID {new_user_id}")

                # --- ВХОД ---
                elif command == "LOGIN":
                    login = data.get("login")
                    user_info = await get_user_by_login(login)
                    if not user_info:
                        await websocket.send(json.dumps({"error": "Пользователь не найден"}))
                        continue

                    user_id = user_info["id"]
                    user_sessions[websocket] = user_id
                    clients[user_id] = websocket
                    await update_user_online_status(user_id, True)

                    # Проверяем наличие чата AnonimGram
                    anonimgram_chat_id = f"anonimgram_{user_id}"
                    async with aiosqlite.connect(DATABASE) as db:
                        cursor = await db.execute("SELECT 1 FROM chats WHERE id = ?", (anonimgram_chat_id,))
                        if not await cursor.fetchone():
                            await db.execute("INSERT INTO chats (id, name, type) VALUES (?, ?, ?)",
                                            (anonimgram_chat_id, "AnonimGram", 'user'))
                            await db.execute("INSERT INTO chat_members (chat_id, user_id, role) VALUES (?, ?, ?)",
                                            (anonimgram_chat_id, user_id, 'member'))
                            await db.commit()
                            active_chats[anonimgram_chat_id] = {"members": [user_id], "type": "user"}

                    await websocket.send(json.dumps({"status": "LOGGED_IN", "user_id": user_id}))
                    logger.info(f"Пользователь вошёл: ID {user_id}")

                # --- ПОЛУЧЕНИЕ СПИСКА ЧАТОВ ---
                elif command == "GET_CHATS":
                    async with aiosqlite.connect(DATABASE) as db:
                        db.row_factory = aiosqlite.Row
                        cursor = await db.execute("""
                            SELECT DISTINCT c.id, c.name, c.type
                            FROM chats c
                            JOIN chat_members cm ON c.id = cm.chat_id
                            WHERE cm.user_id = ?
                        """, (user_id,))
                        rows = await cursor.fetchall()

                    user_chats = []
                    for row in rows:
                        chat_id = row['id']
                        name = row['name']
                        chat_type = row['type']
                        avatar_path = ""
                        
                        if chat_type == 'user' and chat_id == f"anonimgram_{user_id}":
                            avatar_path = "GENERATE:AnonimGram:#2196F3"
                            name = "AnonimGram"
                        elif chat_type == 'user':
                            async with aiosqlite.connect(DATABASE) as db:
                                cursor = await db.execute(
                                    "SELECT user_id FROM chat_members WHERE chat_id = ? AND user_id != ?",
                                    (chat_id, user_id)
                                )
                                other = await cursor.fetchone()
                            if other:
                                other_info = await get_user_by_id(other[0])
                                if other_info:
                                    avatar_path = other_info.get('avatar_path', '')
                                    name = other_info.get('nickname', f"User {other[0]}")

                        user_chats.append({
                            "name": name,
                            "last_message": "Сообщения не сохраняются сервером",
                            "time": datetime.now().strftime('%H:%M'),
                            "avatar_path": avatar_path,
                            "id": chat_id,
                            "type": chat_type
                        })

                    await websocket.send(json.dumps({"cmd": "CHATS_LIST", "chats": user_chats}))

                # --- ПОЛУЧЕНИЕ СООБЩЕНИЙ ---
                elif command == "GET_MESSAGES":
                    target_chat_id = data.get("chat_id")
                    messages = []
                    if target_chat_id == f"anonimgram_{user_id}":
                        messages.append({
                            "text": "Добро пожаловать в AnonimGram! Сообщения в этом мессенджере не сохраняются сервером для вашей приватности.",
                            "time": datetime.now().strftime('%H:%M'),
                            "sender_id": 0
                        })
                    await websocket.send(json.dumps({"cmd": "MESSAGES", "messages": messages}))

                # --- ОТПРАВКА СООБЩЕНИЯ ---
                elif command == "SEND_MESSAGE":
                    target_chat_id = data.get("chat_id")
                    message_text = data.get("text")
                    if not target_chat_id or not message_text:
                        await websocket.send(json.dumps({"error": "Неверный формат"}))
                        continue

                    async with aiosqlite.connect(DATABASE) as db:
                        cursor = await db.execute("SELECT user_id FROM chat_members WHERE chat_id = ?", (target_chat_id,))
                        rows = await cursor.fetchall()

                    member_ids = [row[0] for row in rows]
                    if user_id not in member_ids:
                        await websocket.send(json.dumps({"error": "Нет доступа к чату"}))
                        continue

                    sent_time = datetime.now().strftime('%H:%M')
                    await websocket.send(json.dumps({"status": "MESSAGE_SENT", "time": sent_time}))

                    # Рассылаем сообщение всем участникам чата
                    for recipient_id in member_ids:
                        if recipient_id != user_id and recipient_id in clients:
                            try:
                                await clients[recipient_id].send(json.dumps({
                                    "cmd": "NEW_MESSAGE",
                                    "chat_id": target_chat_id,
                                    "sender_id": user_id,
                                    "text": message_text,
                                    "time": sent_time
                                }))
                            except Exception as e:
                                logger.warning(f"Не удалось отправить сообщение пользователю {recipient_id}: {e}")

                # --- ОБНОВЛЕНИЕ ПРОФИЛЯ ---
                elif command == "UPDATE_PROFILE":
                    new_nickname = data.get("nickname", "")
                    new_username = data.get("username", "")
                    avatar_b64_str = data.get("avatar", "")
                    hide_last_seen = data.get("hide_last_seen", False)
                    hide_online = data.get("hide_online", False)

                    async with aiosqlite.connect(DATABASE) as db:
                        await db.execute("""
                            UPDATE users
                            SET nickname = COALESCE(?, nickname),
                                username = COALESCE(?, username),
                                avatar_path = CASE WHEN ? != '' THEN ? ELSE avatar_path END,
                                hide_last_seen = ?,
                                hide_online = ?
                            WHERE id = ?
                        """, (new_nickname, new_username, avatar_b64_str, avatar_b64_str, 
                              hide_last_seen, hide_online, user_id))
                        await db.commit()
                    
                    await websocket.send(json.dumps({"status": "PROFILE_UPDATED"}))

                # --- СОЗДАНИЕ ЧАТА ---
                elif command == "CREATE_CHAT":
                    chat_type = data.get("type")
                    chat_name = data.get("name")
                    generated_id = data.get("id")
                    
                    if chat_type not in ['group', 'channel']:
                        await websocket.send(json.dumps({"error": "Неверный тип чата"}))
                        continue

                    async with aiosqlite.connect(DATABASE) as db:
                        await db.execute("INSERT INTO chats (id, name, type, owner_id) VALUES (?, ?, ?, ?)",
                                        (generated_id, chat_name, chat_type, user_id))
                        await db.execute("INSERT INTO chat_members (chat_id, user_id, role) VALUES (?, ?, ?)",
                                        (generated_id, user_id, 'owner'))
                        await db.commit()
                    
                    active_chats[generated_id] = {'members': [user_id], 'type': chat_type}
                    await websocket.send(json.dumps({
                        "status": "CHAT_CREATED",
                        "id": generated_id,
                        "name": chat_name,
                        "type": chat_type
                    }))

                # --- ПОИСК ПО ID ---
                elif command == "SEARCH_BY_ID":
                    search_id = data.get("search_id")
                    found = False
                    
                    # Поиск чата
                    async with aiosqlite.connect(DATABASE) as db:
                        db.row_factory = aiosqlite.Row
                        cursor = await db.execute("SELECT id, name, type FROM chats WHERE id = ?", (search_id,))
                        chat_result = await cursor.fetchone()
                        
                        if chat_result:
                            chat_info = {
                                "id": chat_result["id"], 
                                "name": chat_result["name"], 
                                "type": chat_result["type"]
                            }
                            await websocket.send(json.dumps({
                                "cmd": "SEARCH_RESULT", 
                                "type": "CHAT", 
                                "data": chat_info
                            }))
                            found = True
                        else:
                            # Поиск пользователя
                            try:
                                user_id_int = int(search_id)
                                user_result = await get_user_by_id(user_id_int)
                                if user_result:
                                    # Убираем чувствительные данные
                                    safe_user_info = {k: v for k, v in user_result.items() 
                                                     if k not in ['password_hash', 'login']}
                                    await websocket.send(json.dumps({
                                        "cmd": "SEARCH_RESULT", 
                                        "type": "USER", 
                                        "data": safe_user_info
                                    }))
                                    found = True
                            except ValueError:
                                pass
                    
                    if not found:
                        await websocket.send(json.dumps({"error": "Сущность с таким ID не найдена"}))

                # --- PING (поддержание соединения) ---
                elif command == "PING":
                    if user_id:
                        await update_user_online_status(user_id, True)
                        await websocket.send(json.dumps({"status": "PONG"}))

                # --- НЕИЗВЕСТНАЯ КОМАНДА ---
                else:
                    await websocket.send(json.dumps({"error": "Неизвестная команда"}))

            except json.JSONDecodeError:
                logger.error(f"Получено невалидное JSON сообщение от сессии {session_id}")
                await websocket.send(json.dumps({"error": "Невалидный JSON"}))
            except Exception as e:
                logger.error(f"Ошибка при обработке сообщения: {e}")
                await websocket.send(json.dumps({"error": "Ошибка обработки"}))

    except websockets.exceptions.ConnectionClosed:
        logger.info(f"Соединение закрыто клиентом (сессия: {session_id})")
    except Exception as e:
        logger.error(f"Неожиданная ошибка в handle_client: {e}")
    finally:
        # Очистка при отключении
        if websocket in user_sessions:
            uid = user_sessions.pop(websocket)
            await update_user_online_status(uid, False)
            clients.pop(uid, None)
            logger.info(f"Пользователь ID {uid} отключился (сессия: {session_id})")

# --- ОСНОВНАЯ ФУНКЦИЯ ЗАПУСКА ---
async def main():
    """Запуск сервера с поддержкой health check"""
    await init_database()
    
    # Создаем сервер с обработчиком health check
    async with websockets.serve(
        handle_client, 
        HOST, 
        PORT,
        process_request=health_check_handler,  # Критически важно для Render!
        ping_interval=20,  # Отправляем ping каждые 20 секунд
        ping_timeout=10    # Таймаут ответа на ping
    ):
        logger.info(f"WebSocket-сервер запущен на ws://{HOST}:{PORT}")
        logger.info("Health check endpoint доступен на http://localhost:8080/")
        logger.info("Сервер готов к работе...")
        
        # Держим сервер запущенным
        await asyncio.Future()  # работает вечно

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Сервер остановлен пользователем")
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        raise
