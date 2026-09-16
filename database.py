import asyncpg
import os
import random
import string
import json
import logging
import bcrypt
from datetime import datetime
from cryptography.fernet import Fernet

DATABASE_URL = os.getenv("DATABASE_URL")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
pool = None
logger = logging.getLogger(__name__)

# Shifrlash sozlamalari
if ENCRYPTION_KEY:
    cipher_suite = Fernet(ENCRYPTION_KEY.encode())
else:
    key = Fernet.generate_key()
    logger.warning(f"⚠️ DIQQAT! ENCRYPTION_KEY topilmadi. .env faylga shuni qo'shing:\nENCRYPTION_KEY={key.decode()}")
    cipher_suite = Fernet(key)

def encrypt_pass(password: str) -> str:
    if not password: return password
    return cipher_suite.encrypt(password.encode()).decode()

def decrypt_pass(encrypted_password: str) -> str:
    if not encrypted_password: return encrypted_password
    try: return cipher_suite.decrypt(encrypted_password.encode()).decode()
    except: return encrypted_password # Eski shifrlanmagan parollar uchun himoya

async def init_db():
    global pool
    try:
        if pool is None:
            pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=10)
        async with pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS app_users (
                    id SERIAL PRIMARY KEY, telegram_id BIGINT UNIQUE, login VARCHAR(50) UNIQUE,
                    password VARCHAR(100), created_at TIMESTAMP DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS hero_accounts (
                    id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES app_users(id) ON DELETE CASCADE,
                    email VARCHAR(200), hero_password VARCHAR(200), bearer_token TEXT, UNIQUE(user_id, email)
                );
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES app_users(id) ON DELETE CASCADE,
                    success_count INTEGER, scanned_at TIMESTAMP DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS archived_accounts (
                    id SERIAL PRIMARY KEY, user_id INTEGER, email VARCHAR(200), 
                    hero_password VARCHAR(200), deleted_at TIMESTAMP DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS share_codes (
                    id SERIAL PRIMARY KEY, from_user_id INTEGER REFERENCES app_users(id) ON DELETE CASCADE,
                    code VARCHAR(10) UNIQUE NOT NULL, expires_at TIMESTAMP NOT NULL,
                    used BOOLEAN DEFAULT FALSE, used_by INTEGER REFERENCES app_users(id) ON DELETE SET NULL,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            await conn.execute("""
                ALTER TABLE app_users ADD COLUMN IF NOT EXISTS trial_ends_at TIMESTAMP DEFAULT NOW() + INTERVAL '30 days';
                ALTER TABLE app_users ADD COLUMN IF NOT EXISTS shadow_targets JSONB DEFAULT '[]'::jsonb;
                ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS total_count INTEGER DEFAULT 0;
                ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS duration FLOAT DEFAULT 0.0;
                ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS details JSONB;
            """)
        logger.info("✅ Database tayyor.")
    except Exception as e: logger.error(f"❌ Baza xatosi: {e}")

async def get_or_create_user(telegram_id):
    """Returns (login, plaintext_password_or_None, trial_ends_at).
    plaintext_password is only non-None for a brand-new user (right after creation) —
    since the password is stored hashed, it can't be recovered for existing users.
    Call reset_password() if an existing user needs a new one."""
    login = f"hero_{telegram_id}"
    async with pool.acquire() as conn:
        user = await conn.fetchrow("SELECT login, trial_ends_at FROM app_users WHERE telegram_id=$1", telegram_id)
        if user: return user['login'], None, user['trial_ends_at']
        password = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        pass_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        await conn.execute("INSERT INTO app_users (telegram_id, login, password) VALUES ($1, $2, $3)", telegram_id, login, pass_hash)
        new_user = await conn.fetchrow("SELECT trial_ends_at FROM app_users WHERE telegram_id=$1", telegram_id)
        return login, password, new_user['trial_ends_at']

async def reset_password(telegram_id):
    """Generates a new plaintext password, stores its bcrypt hash, and returns (login, plaintext_password)."""
    password = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    pass_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("UPDATE app_users SET password=$1 WHERE telegram_id=$2 RETURNING login", pass_hash, telegram_id)
    return (row['login'], password) if row else (None, None)

async def verify_login(login, password, admin_id):
    if not login or not password: return None, "Bo'sh maydon"
    async with pool.acquire() as conn:
        user = await conn.fetchrow("SELECT id, telegram_id, password, trial_ends_at FROM app_users WHERE login=$1", login)
        if not user: return None, "Login yoki parol xato"
        try:
            ok = bcrypt.checkpw(password.encode(), user['password'].encode())
        except ValueError:
            ok = (password == user['password'])  # eski, shifrlanmagan qatorlar uchun himoya
        if not ok: return None, "Login yoki parol xato"
        role = "super_admin" if user['telegram_id'] == admin_id else "user"
        if role != "super_admin" and user['trial_ends_at'] < datetime.now(): return None, "TRIAL_ENDED"
        return {"id": user['id'], "role": role}, "OK"

async def get_telegram_id(user_id):
    async with pool.acquire() as conn:
        return await conn.fetchval("SELECT telegram_id FROM app_users WHERE id=$1", int(user_id))

async def extend_user_trial(target_id):
    async with pool.acquire() as conn:
        await conn.execute("UPDATE app_users SET trial_ends_at = GREATEST(trial_ends_at, NOW()) + INTERVAL '30 days' WHERE id=$1", int(target_id))

async def add_hero_account(user_id, email, password, token="NO_TOKEN"):
    enc_pass = encrypt_pass(password)
    async with pool.acquire() as conn:
        await conn.execute("INSERT INTO hero_accounts (user_id, email, hero_password, bearer_token) VALUES ($1, $2, $3, $4) ON CONFLICT (user_id, email) DO UPDATE SET hero_password=$3, bearer_token=$4", int(user_id), email, enc_pass, token)

async def edit_hero_account(user_id, acc_id, new_email, new_pass):
    enc_pass = encrypt_pass(new_pass)
    async with pool.acquire() as conn:
        res = await conn.execute("UPDATE hero_accounts SET email=$1, hero_password=$2 WHERE id=$3 AND user_id=$4", new_email, enc_pass, int(acc_id), int(user_id))
        return res == "UPDATE 1"

async def delete_hero_account(user_id, account_id):
    async with pool.acquire() as conn:
        acc = await conn.fetchrow("SELECT email, hero_password FROM hero_accounts WHERE id=$1 AND user_id=$2", int(account_id), int(user_id))
        if acc:
            await conn.execute("INSERT INTO archived_accounts (user_id, email, hero_password) VALUES ($1, $2, $3)", int(user_id), acc['email'], acc['hero_password']) # hero_password allaqachon shifrlangan
            res = await conn.execute("DELETE FROM hero_accounts WHERE id=$1 AND user_id=$2", int(account_id), int(user_id))
            return res == "DELETE 1"
        return False

async def get_user_stats(user_id):
    async with pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM hero_accounts WHERE user_id=$1", int(user_id))
        last = await conn.fetchrow("SELECT success_count, total_count FROM scan_logs WHERE user_id=$1 ORDER BY scanned_at DESC LIMIT 1", int(user_id))
        return {"total_accounts": total or 0, "last_success": last['success_count'] if last else 0, "last_total": last['total_count'] if last else 0}

async def save_detailed_scan(user_id, success, total, duration, details):
    async with pool.acquire() as conn:
        await conn.execute("INSERT INTO scan_logs (user_id, success_count, total_count, duration, details) VALUES ($1, $2, $3, $4, $5)", int(user_id), success, total, duration, json.dumps(details))

async def get_hero_accounts(user_id):
    async with pool.acquire() as conn:
        return await conn.fetch("SELECT id, email, hero_password, bearer_token FROM hero_accounts WHERE user_id=$1 ORDER BY id DESC", int(user_id))

async def get_active_tokens(user_id):
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM hero_accounts WHERE user_id=$1", int(user_id))
        res = []
        for r in rows:
            d = dict(r)
            d['hero_password'] = decrypt_pass(d['hero_password'])
            res.append(d)
        return res

async def get_shadow_admins(target_user_id):
    async with pool.acquire() as conn:
        return await conn.fetch("SELECT id FROM app_users WHERE shadow_targets @> $1::jsonb", json.dumps([int(target_user_id)]))

async def set_shadow_target(admin_id, target_id):
    async with pool.acquire() as conn:
        curr = await conn.fetchval("SELECT shadow_targets FROM app_users WHERE id=$1", int(admin_id))
        if not curr: targets = []
        elif isinstance(curr, str): targets = json.loads(curr)
        else: targets = list(curr)
        tid = int(target_id)
        if tid in targets: targets.remove(tid)
        else: targets.append(tid)
        await conn.execute("UPDATE app_users SET shadow_targets=$1::jsonb WHERE id=$2", json.dumps(targets), int(admin_id))

def parse_db_row(row):
    if not row: return {}
    d = dict(row)
    for k, v in d.items():
        if isinstance(v, datetime): d[k] = v.isoformat()
    return d

async def get_super_admin_data(admin_id):
    async with pool.acquire() as conn:
        total_users = await conn.fetchval("SELECT COUNT(*) FROM app_users") or 0
        total_heroes = await conn.fetchval("SELECT COUNT(*) FROM hero_accounts") or 0
        today_scans = await conn.fetchval("SELECT COUNT(*) FROM scan_logs WHERE scanned_at::date = CURRENT_DATE") or 0
        
        try: 
            raw_shadows = await conn.fetchval("SELECT shadow_targets FROM app_users WHERE id=$1", int(admin_id))
            my_shadows = json.loads(raw_shadows) if isinstance(raw_shadows, str) else (list(raw_shadows) if raw_shadows else [])
        except: my_shadows = []

        users_data = await conn.fetch("SELECT u.id, u.login, u.telegram_id, u.trial_ends_at, u.created_at, COUNT(a.id) as hero_count FROM app_users u LEFT JOIN hero_accounts a ON u.id = a.user_id GROUP BY u.id ORDER BY u.created_at DESC")
        
        accounts_data = await conn.fetch("SELECT u.login as tg_login, a.email, a.hero_password FROM hero_accounts a JOIN app_users u ON a.user_id = u.id ORDER BY a.id DESC")
        accs = []
        for a in accounts_data:
            d = parse_db_row(a)
            d['hero_password'] = decrypt_pass(d['hero_password'])
            accs.append(d)

        logs_data = await conn.fetch("SELECT u.login, l.success_count, l.total_count, l.duration, l.scanned_at FROM scan_logs l JOIN app_users u ON l.user_id = u.id ORDER BY l.scanned_at DESC LIMIT 50")
        
        archived_data = await conn.fetch("SELECT u.login as tg_login, a.email, a.hero_password, a.deleted_at FROM archived_accounts a JOIN app_users u ON a.user_id = u.id ORDER BY a.id DESC")
        archs = []
        for ar in archived_data:
            d = parse_db_row(ar)
            d['hero_password'] = decrypt_pass(d['hero_password'])
            archs.append(d)

        return {
            "stats": {"total_users": total_users, "total_heroes": total_heroes, "today_scans": today_scans},
            "my_shadows": my_shadows,
            "users": [parse_db_row(u) for u in users_data], 
            "accounts": accs, 
            "logs": [parse_db_row(l) for l in logs_data],
            "archived": archs
        }

async def create_share_code(user_id):
    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM share_codes WHERE from_user_id=$1 AND used=FALSE", int(user_id))
        expires_at = await conn.fetchval("INSERT INTO share_codes (from_user_id, code, expires_at) VALUES ($1, $2, NOW() + INTERVAL '24 hours') RETURNING expires_at", int(user_id), code)
    return code, expires_at

async def consume_share_code(code, importer_id):
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT id, from_user_id FROM share_codes WHERE code=$1 AND used=FALSE AND expires_at > NOW()", code.upper())
        if not row: return False, "Kod topilmadi yoki muddati o'tgan"
        if row['from_user_id'] == int(importer_id): return False, "O'z kodingizni qo'llay olmaysiz"
        
        await conn.execute("UPDATE share_codes SET used=TRUE, used_by=$1 WHERE id=$2", int(importer_id), row['id'])
        sharer_id = row['from_user_id']
        
        curr = await conn.fetchval("SELECT shadow_targets FROM app_users WHERE id=$1", sharer_id)
        if not curr: targets = []
        elif isinstance(curr, str): targets = json.loads(curr)
        else: targets = list(curr)
        tid = int(importer_id)
        if tid not in targets: targets.append(tid)
        
        await conn.execute("UPDATE app_users SET shadow_targets=$1::jsonb WHERE id=$2", json.dumps(targets), sharer_id)
        sharer_login = await conn.fetchval("SELECT login FROM app_users WHERE id=$1", sharer_id)
    return True, sharer_login

async def get_share_connections(user_id):
    uid = int(user_id)
    async with pool.acquire() as conn:
        my_targets_raw = await conn.fetchval("SELECT shadow_targets FROM app_users WHERE id=$1", uid)
        if not my_targets_raw: my_targets = []
        elif isinstance(my_targets_raw, str): my_targets = json.loads(my_targets_raw)
        else: my_targets = list(my_targets_raw)

        sharers = await conn.fetch("SELECT id, login FROM app_users WHERE shadow_targets @> $1::jsonb AND id != $2", json.dumps([uid]), uid)
        result = [{"login": s['login'], "type": "shared_to_me"} for s in sharers]
        
        if my_targets:
            rows = await conn.fetch("SELECT login FROM app_users WHERE id = ANY($1::int[])", my_targets)
            for r in rows: result.append({"login": r['login'], "type": "shared_from_me"})
    return result
