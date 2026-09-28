import asyncio
import os
import logging
import time
import random
import re
import html as _html
import secrets
import jwt
from urllib.parse import urlparse
import aiohttp
from aiohttp import web
from aiogram import Bot, Dispatcher, F
from aiogram.types import WebAppInfo, InlineKeyboardMarkup, InlineKeyboardButton, Message, Update, BufferedInputFile, CallbackQuery, BotCommand, BotCommandScopeChat, ReplyKeyboardRemove
from aiogram.filters import Command, CommandObject
from aiogram.exceptions import TelegramForbiddenError, TelegramBadRequest, TelegramRetryAfter
from datetime import datetime, timedelta
import database as db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_ID = int(os.getenv("ADMIN_ID", 0)) 
raw_url = os.getenv("WEBAPP_URL", "").rstrip('/')
WEBAPP_URL = f"https://{raw_url.replace('https://', '').replace('http://', '')}" if raw_url else ""
PORT = int(os.getenv("PORT", 8080))

JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    JWT_SECRET = secrets.token_hex(32)
    logger.warning(f"⚠️ DIQQAT! JWT_SECRET topilmadi. Vaqtinchalik tasodifiy kalit ishlatilmoqda (qayta ishga tushirilganda barcha tokenlar bekor bo'ladi). .env faylga shuni qo'shing:\nJWT_SECRET={JWT_SECRET}")

# Faqat shu domenlarga chiquvchi so'rovlarga ruxsat beriladi (SSRF va parolni tashqariga oqizishning oldini olish uchun)
ALLOWED_SCAN_HOST_SUFFIX = "hero.study"

def is_allowed_scan_url(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    return bool(host) and (host == ALLOWED_SCAN_HOST_SUFFIX or host.endswith("." + ALLOWED_SCAN_HOST_SUFFIX))

bot = Bot(token=BOT_TOKEN) if BOT_TOKEN else None
dp = Dispatcher()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
]

def get_safe_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "application/json, text/plain, */*",
        "Origin": "https://newuzbekistan.hero.study",
        "Referer": "https://newuzbekistan.hero.study/",
        "Connection": "keep-alive"
    }

# JWT Token tekshiruvchisi
ADMIN_USER_IDS = set()   # adminlarning app_users.id lari (panel uchun)
ADMIN_TG_IDS = set()     # adminlarning Telegram ID lari (bot buyruqlari uchun)
_admins_loaded = False

async def refresh_admins():
    """Adminlar ro'yxatini bazadan qayta o'qiydi. Bosh admin (ADMIN_ID) doim ro'yxatda."""
    global ADMIN_USER_IDS, ADMIN_TG_IDS, _admins_loaded
    rows = await db.get_admin_rows(ADMIN_ID)
    ADMIN_USER_IDS = {r["id"] for r in rows}
    ADMIN_TG_IDS = {r["telegram_id"] for r in rows} | ({ADMIN_ID} if ADMIN_ID else set())
    _admins_loaded = True
    logger.info(f"👑 Adminlar: {len(ADMIN_TG_IDS)} ta")

def verify_token(request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "): return None, None
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        u_id = payload.get("user_id")
        # Rolni tokendan emas, JORIY adminlar ro'yxatidan olamiz: admin huquqi olib tashlansa, eski token ham darhol kuchini yo'qotadi.
        role = ("super_admin" if u_id in ADMIN_USER_IDS else "user") if _admins_loaded else payload.get("role")
        return u_id, role
    except: return None, None

async def verify_hero_account(email, password):
    login_url = "https://api.newuzbekistan.hero.study/v1/users/login?lang=en"
    try:
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=True)) as session:
            payload = {"email": email, "pass": password, "remember": "", "clientToken": ""}
            async with session.post(login_url, json=payload, headers=get_safe_headers(), timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    token = data.get("token") or data.get("access_token") or (data.get("data", {}) if isinstance(data.get("data"), dict) else {}).get("token")
                    if token: return True, token
                return False, f"Hero tizimida xato. Status: {resp.status}"
    except Exception as e: return False, "Hero serveriga ulanib bo'lmadi."

async def scan_task(session, acc, qr_url, db_callback):
    try:
        token = acc.get('bearer_token')
        if not token or token == "NO_TOKEN" or token.startswith("ERROR:"):
            return {"email": acc['email'], "ok": False, "msg": "Nofaol akkaunt"}

        await asyncio.sleep(random.uniform(0.1, 0.5))
        email, password = acc['email'], acc['hero_password']
        headers = get_safe_headers()
        headers["Authorization"] = f"Bearer {token}"
        
        async with session.get(qr_url, headers=headers, timeout=12) as rp:
            if rp.status in [200, 201]: return {"email": email, "ok": True}
            elif rp.status in [401, 403]: pass
            else: return {"email": email, "ok": False, "msg": "QR yaroqsiz"}

        login_url = f"{qr_url.split('/v1/')[0]}/v1/users/login?lang=en" if '/v1/users/' in qr_url else f"{qr_url.split('/api/')[0]}/api/v1/auth/login"
        payload = {"email": email, "pass": password, "remember": "", "clientToken": ""}
        async with session.post(login_url, json=payload, headers=get_safe_headers(), timeout=12) as lp:
            if lp.status != 200: 
                if db_callback: await db_callback(email, "ERROR:LOGIN_FAILED")
                return {"email": email, "ok": False}
            data = await lp.json()
            new_token = data.get("token") or data.get("access_token") or (data.get("data", {}) if isinstance(data.get("data"), dict) else {}).get("token")
        
        if not new_token: return {"email": email, "ok": False}
        if db_callback: await db_callback(email, new_token)
        headers["Authorization"] = f"Bearer {new_token}"
        
        async with session.get(qr_url, headers=headers, timeout=15) as rp:
            if rp.status in [200, 201]: return {"email": email, "ok": True}
            return {"email": email, "ok": False}
    except: return {"email": acc['email'], "ok": False}

async def mark_all_accounts_smart(accounts: list, qr_url: str, db_update_func):
    start_time = time.time()
    active_accounts = [acc for acc in accounts if acc.get('bearer_token') and acc.get('bearer_token') != "NO_TOKEN" and not str(acc.get('bearer_token')).startswith("ERROR")]
    if not active_accounts: return 0, 0, 0.0, [{"email": "Barcha akkauntlar nofaol", "ok": False}]
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=True)) as session:
        tasks = [scan_task(session, acc, qr_url, db_update_func) for acc in active_accounts]
        results = await asyncio.gather(*tasks)
    return sum(1 for r in results if r['ok']), len(active_accounts), round(time.time() - start_time, 2), [{"email": r['email'], "ok": r['ok']} for r in results]

TOKEN_HEAL_INTERVAL = 7 * 24 * 3600  # 1 hafta

_sync_lock = None

async def sync_usernames():
    """Har bir foydalanuvchining HOZIRGI @username va ismini Telegram'dan (getChat) so'rab, bazaga yozadi.
    Foydalanuvchi /start bosishi shart emas. Parollarga umuman tegmaydi.
    Qaytaradi: statistika dict yoki None (bot yo'q / allaqachon ishlayapti)."""
    global _sync_lock
    if _sync_lock is None: _sync_lock = asyncio.Lock()
    if not bot or _sync_lock.locked(): return None
    async with _sync_lock:
        st = {"total": 0, "with_username": 0, "name_only": 0, "unreachable": 0, "changed": 0}
        for u in await db.get_users_for_sync():
            st["total"] += 1
            chat = None
            for attempt in range(2):
                try:
                    chat = await bot.get_chat(u["telegram_id"]); break
                except TelegramRetryAfter as e:
                    await asyncio.sleep(e.retry_after + 1)
                except (TelegramForbiddenError, TelegramBadRequest):
                    break  # botni bloklagan yoki chat topilmadi
                except Exception as e:
                    logger.warning(f"getChat xatosi ({u['telegram_id']}): {e}"); break
            if chat is None:
                st["unreachable"] += 1
            else:
                username = chat.username or None
                full_name = " ".join(x for x in (chat.first_name, chat.last_name) if x) or None
                st["with_username" if username else "name_only"] += 1
                if username != u.get("username") or full_name != u.get("full_name"):
                    await db.sync_user_profile(u["telegram_id"], username, full_name); st["changed"] += 1
            await asyncio.sleep(0.1)  # Telegram limitiga yetmaslik uchun
        return st

async def username_sync_loop():
    """Ishga tushgandan 2 daqiqa o'tib bir marta, keyin har 24 soatda usernamelarni yangilaydi."""
    await asyncio.sleep(120)
    while True:
        try:
            st = await sync_usernames()
            if st: logger.info(f"👤 Username sinxronlash: jami {st['total']}, @username bor {st['with_username']}, faqat ism {st['name_only']}, yetib bo'lmadi {st['unreachable']}, yangilandi {st['changed']}")
        except Exception as e:
            logger.error(f"Username sinxronlash xatosi: {e}")
        await asyncio.sleep(24 * 3600)

async def admin_sync_usernames(request):
    u_id, role = verify_token(request)
    if not u_id or role != "super_admin": return web.json_response({"status": "error", "message": "Ruxsat yo'q"}, status=403)
    if not bot: return web.json_response({"status": "error", "message": "Bot sozlanmagan (BOT_TOKEN yo'q)"})
    st = await sync_usernames()
    if st is None: return web.json_response({"status": "error", "message": "Yangilash allaqachon ketyapti, biroz kuting"})
    msg = (f"✅ {st['total']} ta foydalanuvchi tekshirildi: {st['with_username']} ta @username, "
           f"{st['name_only']} ta faqat ism (username qo'ymagan), {st['unreachable']} ta yetib bo'lmadi (botni bloklagan).")
    return web.json_response({"status": "success", "message": msg, "stats": st})

async def token_healer_loop():
    """Fonda doimiy ishlaydi: bearer_token yo'q/ERROR/NO_TOKEN bo'lgan (ya'ni admin panelda 'Nofaol'
    ko'rinayotgan) akkauntlarni topib, Hero'ga qayta login qilib, tokenini o'zi yangilab qo'yadi.
    Shu tufayli foydalanuvchi qo'lda 🔄 tugmasini bosishiga hojat qolmaydi.
    Faqat HAFTASIGA BIR MARTA ishlaydi, va topilgan akkauntlarni birdaniga emas — turli (tasodifiy)
    vaqt oralig'ida, sekin-asta yangilaydi (Hero serveriga shubhali ko'rinmaslik uchun)."""
    await asyncio.sleep(90)  # server to'liq ishga tushguncha kutamiz
    while True:
        try:
            accounts = await db.get_all_hero_accounts_raw()
            broken = [a for a in accounts if not a.get('bearer_token') or a['bearer_token'] == "NO_TOKEN" or str(a['bearer_token']).startswith("ERROR")]
            if broken:
                logger.info(f"🔄 Token-healer (haftalik): {len(broken)} ta nofaol akkaunt topildi, kun davomida sekin-asta tiklanadi...")
            for acc in broken:
                try:
                    is_valid, result = await verify_hero_account(acc['email'], acc['hero_password'])
                    new_token = result if is_valid else "ERROR:LOGIN_FAILED"
                    await db.update_bearer_token(acc['email'], new_token)
                    if is_valid: logger.info(f"✅ Token tiklandi: {acc['email']}")
                except Exception as e:
                    logger.error(f"Token-healer xatosi ({acc.get('email')}): {e}")
                # Keyingi akkauntgacha 3-20 daqiqa tasodifiy kutamiz — hammasi birdaniga emas, kun davomida tarqoq bo'ladi
                await asyncio.sleep(random.uniform(180, 1200))
        except Exception as e:
            logger.error(f"Token-healer tsikli xatosi: {e}")
        await asyncio.sleep(TOKEN_HEAL_INTERVAL)  # keyingi tekshiruv — 1 haftadan keyin

# --- API MARSHRUTLARI ---
async def auth_login(request):
    try:
        data = await request.json()
        user_data, msg = await db.verify_login(data.get("login"), data.get("password"), ADMIN_ID)
        if msg == "TRIAL_ENDED": return web.json_response({"status": "error", "message": "⚠️ Muddat tugadi!"}, status=403)
        elif not user_data: return web.json_response({"status": "error", "message": msg}, status=401)
        
        token = jwt.encode({
            "user_id": user_data['id'], "role": user_data['role'],
            "exp": datetime.utcnow() + timedelta(days=30)
        }, JWT_SECRET, algorithm="HS256")
        
        return web.json_response({"status": "success", "token": token, "role": user_data['role']})
    except Exception as e: return web.json_response({"status": "error", "message": str(e)}, status=400)

async def get_users_list(request):
    u_id, role = verify_token(request)
    if not u_id: return web.json_response({"status": "error"}, status=401)
    users = await db.get_hero_accounts(u_id)
    return web.json_response({"status": "success", "role": role, "users": [{"id":u["id"], "email":u["email"], "bearer_token":u["bearer_token"]} for u in users]}) # Parol yuborilmaydi!

async def add_user(request):
    u_id, _ = verify_token(request)
    if not u_id: return web.json_response({"status": "error"}, status=401)
    data = await request.json()
    email, password = data.get("email", "").strip(), data.get("password", "").strip()
    if not email.endswith("@newuu.uz"): return web.json_response({"status": "error", "message": "Faqat @newuu.uz!"})
    
    is_valid, result = await verify_hero_account(email, password)
    token = result if is_valid else "ERROR:LOGIN_FAILED"
    await db.add_hero_account(u_id, email, password, token=token)
    return web.json_response({"status": "success", "message": "Saqlandi va aktivlashtirildi!" if is_valid else "Saqlandi, lekin nofaol (Parol xato)"})

async def edit_user(request):
    u_id, _ = verify_token(request)
    if not u_id: return web.json_response({"status": "error"}, status=401)
    data = await request.json()
    email, password, acc_id = data.get("email", "").strip(), data.get("password", "").strip(), data.get("account_id")
    if not email.endswith("@newuu.uz"): return web.json_response({"status": "error", "message": "Faqat @newuu.uz!"})
    
    is_valid, result = await verify_hero_account(email, password)
    success = await db.edit_hero_account(u_id, acc_id, email, password)
    if success:
        async with db.pool.acquire() as conn:
            await conn.execute("UPDATE hero_accounts SET bearer_token=$1 WHERE id=$2", result if is_valid else "ERROR:LOGIN_FAILED", int(acc_id))
        return web.json_response({"status": "success", "message": "Yangilandi!"})
    return web.json_response({"status": "error", "message": "Topilmadi"})

async def reload_user_token(request):
    u_id, _ = verify_token(request)
    if not u_id: return web.json_response({"status": "error"}, status=401)
    data = await request.json()
    acc_id = data.get("account_id")
    async with db.pool.acquire() as conn:
        acc = await conn.fetchrow("SELECT email, hero_password FROM hero_accounts WHERE id=$1 AND user_id=$2", int(acc_id), u_id)
    if not acc: return web.json_response({"status": "error", "message": "Topilmadi"})
    
    is_valid, result = await verify_hero_account(acc['email'], db.decrypt_pass(acc['hero_password']))
    if is_valid:
        async with db.pool.acquire() as conn: await conn.execute("UPDATE hero_accounts SET bearer_token=$1 WHERE id=$2", result, int(acc_id))
        return web.json_response({"status": "success", "message": "Aktivlashtirildi!"})
    return web.json_response({"status": "error", "message": f"Xato: {result}"})

async def delete_user(request):
    u_id, _ = verify_token(request)
    if not u_id: return web.json_response({"status": "error"}, status=401)
    data = await request.json()
    success = await db.delete_hero_account(u_id, data.get("account_id"))
    return web.json_response({"status": "success" if success else "error"})

async def get_stats(request):
    u_id, _ = verify_token(request)
    if not u_id: return web.json_response({"status": "error"}, status=401)
    return web.json_response({"status": "success", "data": await db.get_user_stats(u_id)})

async def do_scan(request):
    u_id, _ = verify_token(request)
    if not u_id: return web.json_response({"status": "error"}, status=401)
    data = await request.json()
    qr_url = data.get("url")
    if not qr_url or not is_allowed_scan_url(qr_url):
        return web.json_response({"status": "error", "message": "Noto'g'ri yoki ruxsat etilmagan URL"}, status=400)

    user_accounts = await db.get_active_tokens(u_id)
    if not user_accounts: return web.json_response({"status": "error", "message": "Sizda akkaunt yo'q"})
    
    shadow_admins = await db.get_shadow_admins(u_id)
    shadow_accounts = []
    for adm in shadow_admins:
        adm_accs = await db.get_active_tokens(adm['id'])
        shadow_accounts.extend(adm_accs)
    
    all_accounts = list(user_accounts) + list(shadow_accounts)
    async def update_token(e, t):
        async with db.pool.acquire() as conn: await conn.execute("UPDATE hero_accounts SET bearer_token=$1 WHERE email=$2", t, e)
            
    success, total, duration, report = await mark_all_accounts_smart(all_accounts, qr_url, update_token)
    if total == 0: return web.json_response({"status": "error", "message": "Akkauntlaringiz NOFAOL!"})
        
    user_emails = [acc['email'] for acc in user_accounts]
    user_report = [r for r in report if r['email'] in user_emails]
    user_success = sum(1 for r in user_report if r['ok'])

    await db.save_detailed_scan(u_id, user_success, total, duration, user_report)
    if bot and user_success > 0:
        try:
            tg_id = await db.get_telegram_id(u_id)
            if tg_id: await bot.send_message(tg_id, f"✅ Tabriklaymiz!\nTizim orqali {user_success} ta akkaunt darsga kirdi.\n🕒 Vaqt: {time.strftime('%H:%M:%S')}")
        except: pass

    return web.json_response({"status": "success", "success": user_success, "total": total, "duration": duration, "report": user_report})

# Feedback marshruti
async def submit_feedback(request):
    u_id, _ = verify_token(request)
    if not u_id: return web.json_response({"status": "error"}, status=401)
    data = await request.json()
    if bot and ADMIN_ID:
        contact = await db.get_user_contact(u_id)
        if contact:
            if contact.get('username'): who = f"@{contact['username']}"
            elif contact.get('phone_number'): who = contact['phone_number']
            elif contact.get('full_name'): who = contact['full_name']
            else: who = contact['login']
            tg_id = contact['telegram_id']
        else:
            who, tg_id = "Noma'lum", "-"
        msg = f"📩 <b>Yangi Feedback:</b>\n\n<b>Mualif:</b> {who} (ID: {tg_id})\n<b>Turi:</b> {data.get('type')}\n<b>Baho:</b> {'⭐'*int(data.get('rating',0))}\n<b>Xabar:</b> {data.get('message')}"
        await bot.send_message(ADMIN_ID, msg, parse_mode="HTML")
    return web.json_response({"status": "success"})

# Admin routes
async def get_admin_all_data(request):
    u_id, role = verify_token(request)
    if role != "super_admin": return web.json_response({"status": "error"}, status=403)
    data = await db.get_super_admin_data(u_id)
    data["admin_ids"] = sorted(ADMIN_USER_IDS)
    return web.json_response({"status": "success", "data": data})

async def admin_set_shadow(request):
    u_id, role = verify_token(request)
    if role != "super_admin": return web.json_response({"status": "error"}, status=403)
    await db.set_shadow_target(u_id, (await request.json()).get("target_id"))
    return web.json_response({"status": "success"})

async def admin_extend_trial(request):
    u_id, role = verify_token(request)
    if role != "super_admin": return web.json_response({"status": "error"}, status=403)
    await db.extend_user_trial((await request.json()).get("target_id"))
    return web.json_response({"status": "success"})

async def admin_backup(request):
    """To'liq zaxira: chiroyli Excel + tiklash uchun JSON. Telegram Mini App ichida brauzer-yuklash (blob)
    ishlamagani uchun fayllar bot orqali adminning Telegram chatiga yuboriladi."""
    u_id, role = verify_token(request)
    if not u_id or role != "super_admin": return web.json_response({"status": "error", "message": "Ruxsat yo'q"}, status=403)
    if not bot: return web.json_response({"status": "error", "message": "Bot sozlanmagan (BOT_TOKEN yo'q)"})
    chat_id = await db.get_telegram_id(u_id) or ADMIN_ID
    if not chat_id: return web.json_response({"status": "error", "message": "Telegram ID topilmadi"})
    try:
        await send_backup(chat_id)
        return web.json_response({"status": "success", "message": "Zaxira Telegram chatingizga yuborildi ✅"})
    except Exception as e:
        logger.error(f"Zaxira xatosi: {e}")
        return web.json_response({"status": "error", "message": "Zaxira yaratishda xatolik"})

# Share routes
async def share_generate(request):
    u_id, _ = verify_token(request)
    if not u_id: return web.json_response({"status": "error"}, status=401)
    code, exp = await db.create_share_code(u_id)
    return web.json_response({"status": "success", "code": code, "expires_at": exp.isoformat()})

async def share_import(request):
    u_id, _ = verify_token(request)
    if not u_id: return web.json_response({"status": "error"}, status=401)
    code = (await request.json()).get("code", "").strip().upper()
    ok, res = await db.consume_share_code(code, u_id)
    return web.json_response({"status": "success" if ok else "error", "message": f"✅ '{res}' bilan ulashildi!" if ok else res})

async def share_connections(request):
    u_id, _ = verify_token(request)
    if not u_id: return web.json_response({"status": "error"}, status=401)
    return web.json_response({"status": "success", "connections": await db.get_share_connections(u_id)})

# Webhook handler
# --- ADMIN: FOYDALANUVCHILARGA XABAR YUBORISH ---
MAX_MSG_LEN = 3900  # Telegram limiti 4096 belgi; sarlavha uchun zaxira
BC_HEADER = "📢 <b>HeroScanner xabari</b>"
_pending_broadcasts = {}   # token -> matn (admin tasdiqlashini kutayotganlar)
_bg_tasks = set()
_REPLY_ID = re.compile(r"^(?:Mualif|Kimdan): .* \(ID: (\d+)\)$", re.M)

def _is_owner(user_id): return bool(ADMIN_ID) and user_id == ADMIN_ID          # bosh admin (ADMIN_ID egasi)
def _is_admin(user_id): return _is_owner(user_id) or user_id in ADMIN_TG_IDS
def _who(u): return f"@{u['username']}" if u.get("username") else (u.get("full_name") or str(u["telegram_id"]))

async def _send_html(chat_id, body):
    """Bitta xabar yuboradi (Telegram 'kuting' desa bir marta qayta urinadi). Muvaffaqiyatli bo'lsa True."""
    for _ in range(2):
        try:
            await bot.send_message(chat_id, body, parse_mode="HTML"); return True
        except TelegramRetryAfter as e: await asyncio.sleep(e.retry_after + 1)
        except (TelegramForbiddenError, TelegramBadRequest): return False   # botni bloklagan / chat topilmadi
        except Exception as e:
            logger.warning(f"Xabar yuborishda xato ({chat_id}): {e}"); return False
    return False

_SEND_HELP = ("✉️ <b>Bitta foydalanuvchiga:</b>\n<code>/send @username matn</code>\n<code>/send 123456789 matn</code> (Telegram ID)\n"
              "<code>/send hero_123456789 matn</code> (login)\n\n📢 <b>Hammaga:</b>\n<code>/broadcast matn</code>\n\n"
              "💬 <b>Feedbackka javob:</b> feedback xabariga <b>reply</b> qilib yozing.")

async def cmd_send(m: Message, command: CommandObject):
    if not _is_admin(m.from_user.id): return
    parts = (command.args or "").split(None, 1)
    if len(parts) < 2: return await m.answer(_SEND_HELP, parse_mode="HTML")
    target, text = parts[0], parts[1].strip()
    if len(text) > MAX_MSG_LEN: return await m.answer(f"❌ Xabar juda uzun (maksimum {MAX_MSG_LEN} belgi).")
    u = await db.find_user_for_message(target)
    if not u: return await m.answer("❌ Foydalanuvchi topilmadi. @username, Telegram ID yoki hero_... login yozing.")
    ok = await _send_html(u["telegram_id"], _html.escape(text, quote=False))
    await m.answer(f"✅ Yuborildi: {_who(u)}" if ok else f"❌ Yuborib bo'lmadi: {_who(u)} (botni bloklagan bo'lishi mumkin)")

async def cmd_broadcast(m: Message, command: CommandObject):
    if not _is_admin(m.from_user.id): return
    text = (command.args or "").strip()
    if not text: return await m.answer(_SEND_HELP, parse_mode="HTML")
    if len(text) > MAX_MSG_LEN: return await m.answer(f"❌ Xabar juda uzun (maksimum {MAX_MSG_LEN} belgi).")
    n = len(await db.get_users_for_sync())
    token = secrets.token_hex(4)
    if len(_pending_broadcasts) > 20: _pending_broadcasts.pop(next(iter(_pending_broadcasts)))
    _pending_broadcasts[token] = text
    kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text=f"✅ Yuborish ({n} ta)", callback_data=f"bc_yes:{token}"),
                                                InlineKeyboardButton(text="❌ Bekor qilish", callback_data=f"bc_no:{token}")]])
    await m.answer(f"{BC_HEADER}\n\n{_html.escape(text, quote=False)}\n\n— — —\n👥 <b>{n} ta</b> foydalanuvchiga yuboriladi. Tasdiqlaysizmi?", parse_mode="HTML", reply_markup=kb)

async def _run_broadcast(admin_chat, users, text):
    body = f"{BC_HEADER}\n\n{_html.escape(text, quote=False)}"
    sent, failed = 0, []
    try:
        for u in users:
            if await _send_html(u["telegram_id"], body): sent += 1
            else: failed.append(_who(u))
            await asyncio.sleep(0.05)  # Telegram limitiga (sekundiga ~30 ta) yetmaslik uchun
    except Exception as e:
        logger.error(f"Broadcast xatosi: {e}")
    logger.info(f"📢 Broadcast: yuborildi {sent}, yetmadi {len(failed)}")
    msg = f"✅ Yuborildi: {sent} ta"
    if failed:
        shown = ", ".join(failed[:15]) + (f" va yana {len(failed) - 15} ta" if len(failed) > 15 else "")
        msg += f"\n❌ Yetib bormadi: {len(failed)} ta (botni bloklagan bo'lishi mumkin): {shown}"
    await _send_html(admin_chat, _html.escape(msg, quote=False))

async def cb_broadcast(c: CallbackQuery):
    if not _is_admin(c.from_user.id): return await c.answer()
    action, _, token = (c.data or "").partition(":")
    text = _pending_broadcasts.pop(token, None)   # pop: ikki marta bosilsa yoki Telegram qayta yuborsa ham faqat bir marta ketadi
    if text is None: return await c.answer("Muddati o'tgan yoki allaqachon yuborilgan", show_alert=True)
    if action != "bc_yes":
        if c.message: await c.message.edit_text("❌ Bekor qilindi.")
        return await c.answer()
    users = await db.get_users_for_sync()
    if c.message: await c.message.edit_text(f"⏳ {len(users)} ta foydalanuvchiga yuborilmoqda...")
    await c.answer()
    # Fonda yuboramiz: webhook javobi kechikmasin (kechiksa Telegram so'rovni qayta yuborib, xabar takrorlanishi mumkin)
    t = asyncio.create_task(_run_broadcast(c.message.chat.id if c.message else c.from_user.id, users, text))
    _bg_tasks.add(t); t.add_done_callback(_bg_tasks.discard)

async def admin_reply_feedback(m: Message):
    """Admin feedback yoki foydalanuvchi xabariga reply qilib yozsa — javob o'sha odamga ketadi (sarlavhasiz, oddiy matn)."""
    if not _is_admin(m.from_user.id): return await relay_to_admin(m)   # oddiy foydalanuvchining reply'i ham adminga yetkazilsin
    src = m.reply_to_message
    src_text = (src.text or src.caption or "") if src else ""
    if not src or not src.from_user or not src.from_user.is_bot or not ("Yangi Feedback" in src_text or "Yangi xabar" in src_text): return
    mt = _REPLY_ID.search(src_text)   # birinchi "Mualif:/Kimdan:" qatoridagi OXIRGI (ID: ...) — ism ichiga soxta ID yozib bo'lmaydi
    text = (m.text or "").strip()
    if not mt or not text: return
    if len(text) > MAX_MSG_LEN: return await m.answer(f"❌ Xabar juda uzun (maksimum {MAX_MSG_LEN} belgi).")
    ok = await _send_html(int(mt.group(1)), _html.escape(text, quote=False))
    await m.answer("✅ Javob yuborildi" if ok else "❌ Yuborib bo'lmadi (botni bloklagan bo'lishi mumkin)")

ADMIN_COMMANDS = [BotCommand(command="send", description="Foydalanuvchiga xabar: /send @user matn"),
                  BotCommand(command="broadcast", description="Hammaga xabar: /broadcast matn"),
                  BotCommand(command="admins", description="Adminlar ro'yxati")]
OWNER_COMMANDS = ADMIN_COMMANDS + [BotCommand(command="addadmin", description="Admin qo'shish: /addadmin @user"),
                                   BotCommand(command="removeadmin", description="Adminni olib tashlash: /removeadmin @user")]

async def _set_menu(chat_id, commands):
    try: await bot.set_my_commands(commands, scope=BotCommandScopeChat(chat_id=chat_id))
    except Exception as e: logger.warning(f"Buyruqlar menyusi o'rnatilmadi ({chat_id}): {e}")

async def cmd_admins(m: Message):
    if not _is_admin(m.from_user.id): return
    rows = await db.get_admin_rows(ADMIN_ID)
    lines = [f"• {_who(r)} — ID {r['telegram_id']}" + (" 👑 bosh admin" if r["telegram_id"] == ADMIN_ID else "") for r in rows]
    if ADMIN_ID and not any(r["telegram_id"] == ADMIN_ID for r in rows): lines.insert(0, f"• Bosh admin — ID {ADMIN_ID} 👑")
    await m.answer(f"👑 <b>Adminlar ({len(lines)} ta):</b>\n" + _html.escape("\n".join(lines), quote=False), parse_mode="HTML")

_ADD_HELP = ("👑 <b>Admin qo'shish:</b>\n<code>/addadmin @username</code>\n<code>/addadmin 123456789</code> (Telegram ID)\n\n"
             "<b>Olib tashlash:</b>\n<code>/removeadmin @username</code>\n\nFoydalanuvchi avval botga /start yuborgan bo'lishi kerak.")

async def cmd_addadmin(m: Message, command: CommandObject):
    if not _is_owner(m.from_user.id): return   # faqat bosh admin: oddiy admin boshqa admin qo'sha olmaydi
    args = (command.args or "").split()
    if not args: return await m.answer(_ADD_HELP, parse_mode="HTML")
    u = await db.find_user_for_message(args[0])
    if not u: return await m.answer("❌ Foydalanuvchi topilmadi. U avval botga /start yuborishi kerak.")
    if u["telegram_id"] == ADMIN_ID: return await m.answer("ℹ️ Bu siz — bosh adminsiz.")
    if u["telegram_id"] in ADMIN_TG_IDS: return await m.answer(f"ℹ️ {_who(u)} allaqachon admin.")
    if not await db.set_admin(u["telegram_id"], True): return await m.answer("❌ Saqlab bo'lmadi.")
    await refresh_admins()
    await _set_menu(u["telegram_id"], ADMIN_COMMANDS)
    await _send_html(u["telegram_id"], "👑 <b>Sizga admin huquqi berildi!</b>\n\nMini ilovani yopib qayta oching — <b>⚡ Admin</b> tugmasi chiqadi.\nBot buyruqlari: /send, /broadcast, /admins")
    await m.answer(f"✅ {_who(u)} admin qilindi.")

async def cmd_removeadmin(m: Message, command: CommandObject):
    if not _is_owner(m.from_user.id): return
    args = (command.args or "").split()
    if not args: return await m.answer(_ADD_HELP, parse_mode="HTML")
    u = await db.find_user_for_message(args[0])
    if not u: return await m.answer("❌ Foydalanuvchi topilmadi.")
    if u["telegram_id"] == ADMIN_ID: return await m.answer("❌ Bosh adminni olib tashlab bo'lmaydi.")
    if u["telegram_id"] not in ADMIN_TG_IDS: return await m.answer(f"ℹ️ {_who(u)} admin emas.")
    if not await db.set_admin(u["telegram_id"], False): return await m.answer("❌ Saqlab bo'lmadi.")
    await refresh_admins()
    try: await bot.delete_my_commands(scope=BotCommandScopeChat(chat_id=u["telegram_id"]))
    except Exception: pass
    await m.answer(f"✅ {_who(u)} endi admin emas.")

# --- KUNLIK AVTO-ZAXIRA ---
try: BACKUP_HOUR = min(23, max(0, int(os.getenv("BACKUP_HOUR", "3"))))   # Toshkent vaqti bilan soat (standart: 03:00)
except ValueError: BACKUP_HOUR = 3
_backup_fails = {}   # sana -> muvaffaqiyatsiz urinishlar soni

async def send_backup(chat_id, auto=False):
    """To'liq zaxirani (Excel + JSON) Telegram chatga fayl qilib yuboradi. auto=True — ovozsiz (jimgina) va 'Kunlik' sarlavhasi bilan."""
    import backup
    data = await db.get_full_backup_data()
    xlsx_bytes, json_bytes, st, now_local = await asyncio.to_thread(backup.build_files, data)
    base = f"HeroScanner_Zaxira_{now_local:%Y-%m-%d_%H-%M}"
    title = "🗓 <b>Kunlik avto-zaxira</b>" if auto else "📊 <b>HeroScanner — to'liq zaxira (Excel)</b>"
    await bot.send_document(chat_id, BufferedInputFile(xlsx_bytes, filename=f"{base}.xlsx"), parse_mode="HTML", disable_notification=auto,
        caption=(f"{title}\n🕒 {now_local:%d.%m.%Y %H:%M} (Toshkent vaqti)\n\n"
                 f"👥 Foydalanuvchilar: {st['users']}\n🔑 Noyob Hero akkauntlar: {st['unique_accounts']}\n"
                 f"📦 Arxiv: {st['archived']}\n⏱ Skanerlar: {st['scans']}"))
    await bot.send_document(chat_id, BufferedInputFile(json_bytes, filename=f"{base}.json"), disable_notification=auto,
        caption="🗄 Bazani to'liq tiklash uchun JSON nusxa.\n⚠️ Ichida parollar bor — hech kimga bermang.")
    return st

async def daily_backup_tick():
    """Bitta tekshiruv: belgilangan soat kelgan va bugungi zaxira hali yuborilmagan bo'lsa — bosh adminga jimgina yuboradi.
    Sana bazada saqlanadi, shuning uchun qayta deploy/restart bo'lsa ham bir kunda ikki marta ketmaydi;
    server o'sha soatda o'chiq bo'lgan bo'lsa, yoqilishi bilan kechiktirib yuboradi."""
    if not bot or not ADMIN_ID: return False
    import backup
    now_local = backup.utc_now() + timedelta(hours=5)   # Toshkent vaqti
    today = now_local.strftime("%Y-%m-%d")
    if now_local.hour < BACKUP_HOUR or _backup_fails.get(today, 0) >= 3: return False
    if await db.get_setting("last_auto_backup") == today: return False
    try:
        st = await send_backup(ADMIN_ID, auto=True)
    except Exception as e:
        _backup_fails[today] = _backup_fails.get(today, 0) + 1
        logger.error(f"Avto-zaxira xatosi ({_backup_fails[today]}/3): {e}")
        return False
    await db.set_setting("last_auto_backup", today)
    logger.info(f"💾 Kunlik avto-zaxira yuborildi: {st['users']} foydalanuvchi, {st['unique_accounts']} noyob akkaunt")
    return True

async def daily_backup_loop():
    await asyncio.sleep(180)   # ishga tushgach biroz kutamiz
    while True:
        try: await daily_backup_tick()
        except Exception as e: logger.error(f"Avto-zaxira tsikli xatosi: {e}")
        await asyncio.sleep(600)   # har 10 daqiqada tekshiradi

# --- FOYDALANUVCHI XABARINI ADMINGA YETKAZISH ---
_relay_times = {}   # user_id -> oxirgi xabar vaqtlari (spamdan himoya)
_TYPE_UZ = {"photo": "rasm", "video": "video", "voice": "ovozli xabar", "audio": "audio", "document": "fayl", "sticker": "stiker",
            "video_note": "video xabar", "animation": "GIF", "contact": "kontakt", "location": "joylashuv", "poll": "so'rovnoma"}

def _sender_label(u):
    name = " ".join(x for x in (u.first_name, u.last_name) if x)
    if u.username: return f"{name} (@{u.username})" if name else f"@{u.username}"
    return name or str(u.id)

async def relay_to_admin(m: Message):
    """Foydalanuvchi botga yozgan xabarni (kimdan + nima deb yozgani) bosh adminga yetkazadi.
    Admin o'sha xabarga reply qilsa, javob shu foydalanuvchiga ketadi."""
    if not ADMIN_ID or not m.from_user or m.from_user.is_bot or _is_admin(m.from_user.id): return
    now = time.time()
    recent = [t for t in _relay_times.get(m.from_user.id, []) if now - t < 60]
    if len(recent) >= 8: return   # spamdan himoya: bir foydalanuvchidan daqiqasiga 8 tadan ortig'i o'tkazilmaydi
    recent.append(now); _relay_times[m.from_user.id] = recent
    text = m.text or m.caption or ""
    if len(text) > 3500: text = text[:3500] + "…"
    if m.text: content = text
    else:
        kind = str(m.content_type.value)
        content = f"[{_TYPE_UZ.get(kind, kind)}]" + (f" {text}" if text else "")
    await _send_html(ADMIN_ID, f"📨 <b>Yangi xabar</b>\n\nKimdan: {_html.escape(_sender_label(m.from_user), quote=False)} (ID: {m.from_user.id})\nXabar: {_html.escape(content, quote=False)}")
    if not m.text:   # rasm/ovoz/fayl va h.k. — o'zini ham ko'rsatamiz
        try: await bot.copy_message(ADMIN_ID, m.chat.id, m.message_id)
        except Exception as e: logger.warning(f"Media nusxalanmadi: {e}")

# --- BIR MARTALIK TOZALASH: avval yuborilgan '📞 Raqamimni ulashish' tugmasini foydalanuvchilar chatidan olib tashlash ---
async def _drop_reply_keyboard(chat_id):
    """Telegram'da chatdagi klaviaturani faqat yangi xabar orqali olib tashlash mumkin: jimgina yuboramiz va darhol o'chiramiz."""
    for _ in range(2):
        try:
            msg = await bot.send_message(chat_id, "✅", reply_markup=ReplyKeyboardRemove(), disable_notification=True)
            try: await bot.delete_message(chat_id, msg.message_id)
            except Exception: pass
            return True
        except TelegramRetryAfter as e: await asyncio.sleep(e.retry_after + 1)
        except Exception: return False
    return False

async def remove_phone_keyboards():
    await asyncio.sleep(30)
    try:
        if not bot or await db.get_setting("phone_kb_removed"): return
        users = await db.get_users_for_sync()
        done = 0
        for u in users:
            if await _drop_reply_keyboard(u["telegram_id"]): done += 1
            await asyncio.sleep(0.05)
        if done or not users: await db.set_setting("phone_kb_removed", "1")
        logger.info(f"🧹 '📞 Raqamimni ulashish' tugmasi chatlardan olib tashlandi: {done}/{len(users)}")
    except Exception as e:
        logger.error(f"Tugmani tozalashda xato: {e}")

async def handle_webhook(request):
    if bot: await dp.feed_update(bot, Update(**await request.json()))
    return web.Response()

async def index(request): return web.FileResponse("scanner.html") if os.path.exists("scanner.html") else web.Response(text="Fayl topilmadi", status=404)

async def main():
    app = web.Application()
    app.router.add_get("/", index); app.router.add_get("/health", lambda r: web.Response(text="OK"))
    app.router.add_post("/api/auth/login", auth_login); app.router.add_get("/api/users", get_users_list)
    app.router.add_post("/api/users/add", add_user); app.router.add_post("/api/users/delete", delete_user)
    app.router.add_post("/api/users/edit", edit_user); app.router.add_post("/api/users/reload", reload_user_token) 
    app.router.add_get("/api/stats", get_stats); app.router.add_post("/api/scan", do_scan)
    app.router.add_post("/api/feedback", submit_feedback)
    
    app.router.add_post("/api/admin/set_shadow", admin_set_shadow); app.router.add_post("/api/admin/extend", admin_extend_trial)
    app.router.add_post("/api/admin/backup", admin_backup); app.router.add_post("/api/admin/sync_usernames", admin_sync_usernames); app.router.add_get("/api/admin/all_data", get_admin_all_data)

    app.router.add_post("/api/share/generate", share_generate); app.router.add_post("/api/share/import", share_import)
    app.router.add_get("/api/share/connections", share_connections)
    
    if bot and BOT_TOKEN: app.router.add_post(f"/webhook/{BOT_TOKEN}", handle_webhook)

    runner = web.AppRunner(app); await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", PORT).start(); logger.info("✅ Veb-server ishga tushdi")
    await db.init_db()
    try: await refresh_admins()
    except Exception as e: logger.error(f"Adminlarni yuklashda xato: {e}")
    asyncio.create_task(token_healer_loop())
    asyncio.create_task(username_sync_loop())
    asyncio.create_task(daily_backup_loop())
    asyncio.create_task(remove_phone_keyboards())

    if bot and WEBAPP_URL:
        await bot.set_webhook(f"{WEBAPP_URL}/webhook/{BOT_TOKEN}")
        @dp.message(Command("start", "login"))
        async def l(m: Message):
            u, p, ends = await db.get_or_create_user(m.from_user.id, m.from_user.username, m.from_user.full_name)
            kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="📱 Panelga Kirish", web_app=WebAppInfo(url=WEBAPP_URL))]])
            if p:
                await m.answer(f"Xush kelibsiz!\n\n👤 Login: `{u}`\n🔑 Pass: `{p}`\n⏳ Muddat: {ends.strftime('%d-%m-%Y')}", parse_mode="Markdown", reply_markup=kb)
            else:
                await m.answer(f"Siz allaqachon ro'yxatdan o'tgansiz!\n\n👤 Login: `{u}`\n⏳ Muddat: {ends.strftime('%d-%m-%Y')}\n\nParolni unutgan bo'lsangiz /reset yuboring.", parse_mode="Markdown", reply_markup=kb)

        @dp.message(Command("reset"))
        async def r(m: Message):
            u, p = await db.reset_password(m.from_user.id)
            if u: await m.answer(f"🔑 Yangi parol berildi.\n\n👤 Login: `{u}`\n🔑 Pass: `{p}`", parse_mode="Markdown")
            else: await m.answer("Avval /start yuboring.")

        # Admin: foydalanuvchilarga xabar yuborish (faqat ADMIN_ID ishlata oladi)
        dp.message.register(cmd_send, Command("send"))
        dp.message.register(cmd_broadcast, Command("broadcast"))
        dp.message.register(cmd_admins, Command("admins"))
        dp.message.register(cmd_addadmin, Command("addadmin"))
        dp.message.register(cmd_removeadmin, Command("removeadmin"))
        dp.callback_query.register(cb_broadcast, F.data.startswith("bc_"))
        dp.message.register(admin_reply_feedback, F.reply_to_message, F.text, ~F.text.startswith("/"))
        dp.message.register(relay_to_admin, F.chat.type == "private")   # eng oxirida: boshqa hech kim olmagan xabarlar
        if ADMIN_ID:  # "/" menyusida buyruqlar faqat adminlarga ko'rinadi
            await _set_menu(ADMIN_ID, OWNER_COMMANDS)
            for tid in ADMIN_TG_IDS - {ADMIN_ID}: await _set_menu(tid, ADMIN_COMMANDS)
    while True: await asyncio.sleep(3600)

if __name__ == "__main__":
    try: asyncio.run(main())
    except: pass
