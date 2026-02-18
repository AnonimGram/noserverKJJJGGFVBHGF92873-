import asyncio
import websockets
import json
import aiosqlite
import hashlib
import logging
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, Set
import sys
import traceback

# --- НАСТРОЙКИ ---
HOST = '0.0.0.0'
PORT = 8080
DATABASE = 'anonimgram_server.db'

# --- ЛОГИРОВАНИЕ ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ---
clients: Dict[int, websockets.WebSocketServerProtocol] = {}
user_sessions: Dict[websockets.WebSocketServerProtocol, int] = {}
active_chats: Dict[str, Dict] = {}
online_users: Set[int] = set()

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# --- РАБОТА С БАЗОЙ ДАННЫХ ---
async def init_database():
    """Инициализация базы данных"""
    try:
        async with aiosqlite.connect(DATABASE) as db:
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

            cursor = await db.execute("PRAGMA table_info(users)")
            columns = [column[1] for column in await cursor.fetchall()]
            if 'is_online' not in columns:
                logger.info("Добавляем столбец is_online в таблицу users...")
                await db.execute('ALTER TABLE users ADD COLUMN is_online BOOLEAN DEFAULT 0')

            await db.execute('''
            CREATE TABLE IF NOT EXISTS chats (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT CHECK(type IN ('user', 'group', 'channel')) NOT NULL,
                owner_id INTEGER,
                FOREIGN KEY (owner_id) REFERENCES users (id)
            )''')

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
        logger.info("База данных инициализирована успешно")
    except Exception as e:
        logger.error(f"Ошибка инициализации БД: {e}")
        raise

async def get_user_by_login(login: str) -> Optional[Dict[str, Any]]:
    try:
        async with aiosqlite.connect(DATABASE) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT id, login, password_hash, nickname, username, avatar_path, hide_last_seen, hide_online, last_seen, is_online FROM users WHERE login = ?",
                (login,)
            )
            user = await cursor.fetchone()
            return dict(user) if user else None
    except Exception as e:
        logger.error(f"Ошибка get_user_by_login: {e}")
        return None

async def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    try:
        async with aiosqlite.connect(DATABASE) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT id, login, nickname, username, avatar_path, hide_last_seen, hide_online, last_seen, is_online FROM users WHERE id = ?",
                (user_id,)
            )
            user = await cursor.fetchone()
            return dict(user) if user else None
    except Exception as e:
        logger.error(f"Ошибка get_user_by_id: {e}")
        return None

async def update_user_online_status(user_id: int, is_online: bool):
    try:
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
    except Exception as e:
        logger.error(f"Ошибка update_user_online_status: {e}")

# --- НОВЫЙ: ФУНКЦИЯ ДЛЯ ОБРАБОТКИ ВСЕХ HTTP-ЗАПРОСОВ ---
async def handle_http_request(path, request_headers):
    """Обрабатывает HTTP-запросы (GET, HEAD) для health check и возвращает 200 OK."""
    logger.debug(f"Получен HTTP-запрос: {path}")
    # Возвращаем успешный ответ для любого запроса к корню или /health
    if path == "/" or path == "/health" or path == "/healthz":
        headers = [
            ("Content-Type", "text/plain"),
            ("Content-Length", "2"),
            ("Connection", "close")
        ]
        return (200, headers, b"OK")
    # Для всех остальных путей разрешаем WebSocket handshake
    return None

# --- ОСНОВНОЙ ОБРАБОТЧИК WEBSOCKET (БЕЗ ИЗМЕНЕНИЙ) ---
async def ws_handler(websocket):
    session_id = str(uuid.uuid4())[:8]
    logger.info(f"Новое WebSocket-подключение (сессия: {session_id})")
    user_id = None

    try:
        async for message in websocket:
            try:
                logger.debug(f"Получено сообщение от {session_id}: {message[:100]}")
                data = json.loads(message)
                command = data.get("cmd")
                logger.info(f"Команда от {session_id}: {command}")

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

                    if user_id in clients:
                        try:
                            await clients[user_id].close()
                        except:
                            pass

                    user_sessions[websocket] = user_id
                    clients[user_id] = websocket
                    await update_user_online_status(user_id, True)

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
                    logger.info(f"Пользователь вошёл: ID {user_id} (логин: {login})")

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
                            "text": "Добро пожаловать в AnonimGram! Сообщения не сохраняются сервером.",
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
                    await websocket.send(json.dumps({
                        "cmd": "NEW_MESSAGE",
                        "chat_id": target_chat_id,
                        "sender_id": user_id,
                        "text": message_text,
                        "time": sent_time
                    }))

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

                # --- PING ---
                elif command == "PING":
                    if user_id:
                        await update_user_online_status(user_id, True)
                        await websocket.send(json.dumps({"status": "PONG", "time": datetime.now().strftime('%H:%M:%S')}))

                else:
                    logger.warning(f"Неизвестная команда: {command}")
                    await websocket.send(json.dumps({"error": f"Неизвестная команда: {command}"}))

            except json.JSONDecodeError as e:
                logger.error(f"Невалидный JSON от сессии {session_id}: {e}")
                await websocket.send(json.dumps({"error": "Невалидный JSON"}))
            except Exception as e:
                logger.error(f"Ошибка обработки команды: {e}")
                logger.error(traceback.format_exc())
                await websocket.send(json.dumps({"error": f"Внутренняя ошибка сервера: {str(e)}"}))

    except websockets.exceptions.ConnectionClosed as e:
        logger.info(f"Соединение закрыто клиентом (сессия: {session_id}): {e}")
    except Exception as e:
        logger.error(f"Неожиданная ошибка в ws_handler: {e}")
        logger.error(traceback.format_exc())
    finally:
        if websocket in user_sessions:
            uid = user_sessions.pop(websocket)
            await update_user_online_status(uid, False)
            if uid in clients:
                clients.pop(uid, None)
            logger.info(f"Пользователь ID {uid} отключился (сессия: {session_id})")

# --- ОСНОВНАЯ ФУНКЦИЯ ---
async def main():
    try:
        await init_database()

        # Главное изменение: передаем handle_http_request в process_request
        async with websockets.serve(
            ws_handler,
            HOST,
            PORT,
            process_request=handle_http_request,  # <-- ВОТ ЭТО КЛЮЧЕВОЕ ИЗМЕНЕНИЕ
            ping_interval=20,
            ping_timeout=60,
            max_size=10_485_760
        ) as server:
            logger.info(f"✅ WebSocket-сервер запущен на ws://{HOST}:{PORT}")
            logger.info(f"🌐 Health check endpoint: http://{HOST}:{PORT}/ (отвечает 200 OK на GET/HEAD)")
            logger.info(f"🐍 Python версия: {sys.version}")
            logger.info("⏳ Сервер готов к работе...")
            await asyncio.Future()

    except Exception as e:
        logger.error(f"❌ Критическая ошибка при запуске сервера: {e}")
        logger.error(traceback.format_exc())
        raise

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("👋 Сервер остановлен пользователем")
    except Exception as e:
        logger.error(f"💥 Фатальная ошибка: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)
