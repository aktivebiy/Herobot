import asyncio
import os
import logging
import time
import random
import secrets
import csv
import jwt
from io import StringIO
from urllib.parse import urlparse
import aiohttp
from aiohttp import web
from aiogram import Bot, Dispatcher
from aiogram.types import WebAppInfo, InlineKeyboardMarkup, InlineKeyboardButton, Message, Update
from aiogram.filters import Command
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
def verify_token(request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "): return None, None
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload.get("user_id"), payload.get("role")
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
    u_id, _ = verify_token(request)
    if not u_id: return web.json_response({"status": "error"}, status=401)
    users = await db.get_hero_accounts(u_id)
    return web.json_response({"status": "success", "users": [{"id":u["id"], "email":u["email"], "bearer_token":u["bearer_token"]} for u in users]}) # Parol yuborilmaydi!

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
        tg_id = await db.get_telegram_id(u_id)
        msg = f"📩 <b>Yangi Feedback:</b>\n\n<b>Mualif ID:</b> {tg_id}\n<b>Turi:</b> {data.get('type')}\n<b>Baho:</b> {'⭐'*int(data.get('rating',0))}\n<b>Xabar:</b> {data.get('message')}"
        await bot.send_message(ADMIN_ID, msg, parse_mode="HTML")
    return web.json_response({"status": "success"})

# Admin routes
async def get_admin_all_data(request):
    u_id, role = verify_token(request)
    if role != "super_admin": return web.json_response({"status": "error"}, status=403)
    return web.json_response({"status": "success", "data": await db.get_super_admin_data(u_id)})

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

async def admin_export_csv(request):
    u_id, role = verify_token(request)
    if not u_id or role != "super_admin": return web.Response(status=403)

    data = await db.get_super_admin_data(u_id)
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Foydalanuvchi", "Hero Email", "Hero Parol", "Holati", "O'chirilgan vaqti"])
    
    for acc in data.get('accounts', []): writer.writerow([acc.get('tg_login', ''), acc.get('email', ''), acc.get('hero_password', ''), "Aktiv", ""])
    for arch in data.get('archived', []): writer.writerow([arch.get('tg_login', ''), arch.get('email', ''), arch.get('hero_password', ''), "O'chirilgan", arch.get('deleted_at', '')])
        
    return web.Response(text=output.getvalue(), content_type='text/csv', headers={"Content-Disposition": "attachment; filename=HeroScanner_Zaxira.csv"})

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
    app.router.add_get("/api/admin/export", admin_export_csv); app.router.add_get("/api/admin/all_data", get_admin_all_data)

    app.router.add_post("/api/share/generate", share_generate); app.router.add_post("/api/share/import", share_import)
    app.router.add_get("/api/share/connections", share_connections)
    
    if bot and BOT_TOKEN: app.router.add_post(f"/webhook/{BOT_TOKEN}", handle_webhook)

    runner = web.AppRunner(app); await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", PORT).start(); logger.info("✅ Veb-server ishga tushdi")
    await db.init_db()

    if bot and WEBAPP_URL:
        await bot.set_webhook(f"{WEBAPP_URL}/webhook/{BOT_TOKEN}")
        @dp.message(Command("start", "login"))
        async def l(m: Message):
            u, p, ends = await db.get_or_create_user(m.from_user.id)
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
    while True: await asyncio.sleep(3600)

if __name__ == "__main__":
    try: asyncio.run(main())
    except: pass
