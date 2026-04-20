"""
Codex Toolkit — Telegram Bot

Commands + InlineKeyboard hybrid. Directly imports core modules and
reuses web/app.py task infrastructure.

Usage:
  python -m bot.tg_bot
  # or: TG_BOT_TOKEN=xxx python -m bot.tg_bot
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import threading
from pathlib import Path

# ── Project root ──
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, ContextTypes, filters,
)
from telegram.constants import ParseMode

from core import load_config
from core.api import (CPAAdmin, CPAMgmt, DataManager, decode_jwt_claims,
                      check_deactivated, generate_payment_link)

# Import task infra from web.app (shared in-memory store)
from web.app import (
    _create_task, _log, _finish, _is_stopped, tasks,
    _run_register, _run_session, _run_writeback, _run_relogin,
    _run_oauth, _run_oauth_free, _run_oauth_multi, _run_subscribe_flow,
    _run_health_check, _run_deactivation_scan,
    RegisterReq, SingleEmailReq, OAuthFreeReq, OAuthMultiReq,
    HealthCheckReq, DeactivationScanReq, SubscribeFlowReq,
    _get_proxy, _parse_proxy, _mask_proxy, _save_proxy,
    CFG, OUTPUT_DIR,
)

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("tg_bot")

# ── Config ──
BOT_TOKEN = CFG.get("tg_bot_token") or os.environ.get("TG_BOT_TOKEN", "")
ALLOWED_USERS: list[int] = CFG.get("tg_allowed_users", [])
AUTH_PASSWORD = os.environ.get("AUTH_PASSWORD", CFG.get("auth_password", "lishuai"))
# Owner ID: always pre-authed, no /auth needed
OWNER_ID = 8111025282

# Track per-chat running task for /stop
_chat_tasks: dict[int, str] = {}  # chat_id → task_id
# Authenticated user IDs (password-verified this session)
_authed_users: set[int] = {OWNER_ID}


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def _auth_check(update: Update) -> bool:
    uid = update.effective_user.id
    if uid == OWNER_ID:
        return True
    return uid in _authed_users


def _denied(update: Update):
    return update.message.reply_text("🔒 Please authenticate first:\n/auth <password>")


def _esc(text: str) -> str:
    """Escape MarkdownV2 special chars."""
    for ch in r"_*[]()~`>#+-=|{}.!\\":
        text = text.replace(ch, f"\\{ch}")
    return text


def _trim(text: str, limit: int = 3800) -> str:
    """Trim text to Telegram message limit."""
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... (truncated)"


async def _run_task_and_report(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    command: str,
    req,
    runner_fn,
):
    """Start a background task, send progress updates, report result."""
    chat_id = update.effective_chat.id
    task_id = _create_task(command, req.model_dump() if hasattr(req, "model_dump") else {})
    _chat_tasks[chat_id] = task_id

    msg = await update.message.reply_text(f"⏳ {command} started...")

    # Run in thread
    threading.Thread(target=runner_fn, args=(task_id, req), daemon=True).start()

    # Poll and update message
    last_text = ""
    while True:
        await asyncio.sleep(3)
        task = tasks.get(task_id)
        if not task:
            break

        log_lines = task["logs"][-12:]
        status = task["status"]
        icon = "⏳" if status == "running" else ("✅" if status == "done" else "🛑")
        body = "\n".join(log_lines) if log_lines else "(waiting...)"
        text = f"{icon} {command} — {status}\n\n{_trim(body, 3600)}"

        if text != last_text:
            try:
                await msg.edit_text(text)
            except Exception:
                pass
            last_text = text

        if status != "running":
            break

    # Final result
    task = tasks.get(task_id, {})
    result = task.get("result")
    if result and command == "session" and isinstance(result, dict) and result.get("ok"):
        full_json = json.dumps(result, indent=2, ensure_ascii=False)
        await update.message.reply_text(_trim(full_json, 4000))
    elif result:
        result_text = json.dumps(result, indent=2, ensure_ascii=False)
        await update.message.reply_text(f"📋 Result:\n{_trim(result_text, 3900)}")

    _chat_tasks.pop(chat_id, None)


# ---------------------------------------------------------------------------
#  Command handlers
# ---------------------------------------------------------------------------

async def cmd_auth(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args or []
    if not args:
        return await update.message.reply_text("Usage: /auth <password>")
    pw = args[0]
    if pw == AUTH_PASSWORD:
        uid = update.effective_user.id
        _authed_users.add(uid)
        logger.info("User %d authenticated", uid)
        try:
            await update.message.delete()
        except Exception:
            pass
        await context.bot.send_message(
            update.effective_chat.id, "✅ Authenticated! Use /start to begin.")
    else:
        await update.message.reply_text("❌ Wrong password")


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _auth_check(update):
        return await _denied(update)
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("📝 Register", callback_data="menu_register"),
         InlineKeyboardButton("🔑 Session", callback_data="menu_session")],
        [InlineKeyboardButton("🔄 Writeback", callback_data="menu_writeback"),
         InlineKeyboardButton("🔁 Relogin", callback_data="menu_relogin")],
        [InlineKeyboardButton("🔐 OAuth", callback_data="menu_oauth"),
         InlineKeyboardButton("🆓 OAuth-Free", callback_data="menu_oauth_free")],
        [InlineKeyboardButton("🏢 OAuth Multi", callback_data="menu_oauth_multi"),
         InlineKeyboardButton("🩺 Health Check", callback_data="menu_health")],
        [InlineKeyboardButton("🔍 Deact Scan", callback_data="menu_deactivation"),
         InlineKeyboardButton("📨 Invite", callback_data="menu_invite")],
        [InlineKeyboardButton("💳 Pay Link", callback_data="menu_pay"),
         InlineKeyboardButton("✅ Mark Paid", callback_data="menu_mark_paid")],
        [InlineKeyboardButton("📊 Accounts", callback_data="menu_accounts"),
         InlineKeyboardButton("📋 Tasks", callback_data="menu_tasks")],
    ])
    await update.message.reply_text("🔧 Codex Toolkit\n\nSelect an operation:", reply_markup=kb)


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _auth_check(update):
        return await _denied(update)
    text = ("🔧 Codex Toolkit Commands\n\n"
            "📝 /register [count] [domain] — Register accounts\n"
            "🔁 /register_loop [min_s] [max_s] — Loop register\n"
            "🛑 /stop — Stop current loop task\n"
            "🔑 /session <email> — Get full session\n"
            "🔄 /writeback [email] [count] — DM Writeback\n"
            "🔁 /relogin [email] [count] — Relogin\n"
            "🔐 /oauth [email] [count] — OAuth to CPAB\n"
            "🆓 /oauth_free [email] [count] [cat] — OAuth-Free\n"
            "🏢 /oauth_multi <email> — OAuth all workspaces\n"
            "🩺 /health [dry] — Health Check\n"
            "🔍 /deactivation [cat] — Deactivation Scan\n"
            "📨 /invite <source> <target> [role] — Invite user\n"
            "🔴 /deact <email> [email2] — Check deactivated\n"
            "👁 /watch on [min] | off — Deact watchdog\n"
            "🔎 /check <email> — Check account\n"
            "📊 /accounts [query] — Search accounts\n"
            "💳 /pay [email] [country] [seats] — Payment link\n"
            "✅ /mark_paid <email|link> [cat] — Mark subscribed\n"
            "📋 /tasks — Recent tasks\n"
            "🌐 /proxy [url] — View/set proxy")
    await update.message.reply_text(text)


async def cmd_register(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Usage: /register [count] [domain]"""
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    count = 1
    domain = None
    for a in args:
        if a.isdigit():
            count = int(a)
        elif "." in a:
            domain = a
    req = RegisterReq(count=count, domain=domain)
    await _run_task_and_report(update, context, "register", req, _run_register)


async def cmd_register_loop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Usage: /register_loop [domain] [min_sleep] [max_sleep]
    Runs in background. Use /stop to halt.
    """
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    domain = None
    min_s = 30
    max_s = 180
    nums = []
    for a in args:
        if "." in a and not a.isdigit():
            domain = a
        elif a.isdigit():
            nums.append(int(a))
    if len(nums) >= 2:
        min_s, max_s = nums[0], nums[1]
    elif len(nums) == 1:
        min_s = nums[0]
        max_s = max(min_s, 180)

    req = RegisterReq(count=1, loop=True, domain=domain,
                      min_sleep=min_s, max_sleep=max_s)
    task_id = _create_task("register", req.model_dump())
    chat_id = update.effective_chat.id
    _chat_tasks[chat_id] = task_id

    # Run in background thread — don't await, so /stop can be received
    threading.Thread(target=_run_register, args=(task_id, req), daemon=True).start()

    async def _poll_loop():
        msg = await update.message.reply_text(
            f"🔁 Loop register started (sleep {min_s}-{max_s}s"
            + (f", domain={domain}" if domain else "") + ")\n"
            f"Task: {task_id}\n"
            f"Use /stop to halt")
        last_text = ""
        while True:
            await asyncio.sleep(5)
            task = tasks.get(task_id)
            if not task:
                break
            log_lines = task["logs"][-8:]
            status = task["status"]
            icon = "🔁" if status == "running" else ("✅" if status == "done" else "🛑")
            body = "\n".join(log_lines) if log_lines else "(starting...)"
            text = f"{icon} register loop — {status}\n\n{_trim(body, 3600)}"
            if text != last_text:
                try:
                    await msg.edit_text(text)
                except Exception:
                    pass
                last_text = text
            if status != "running":
                _chat_tasks.pop(chat_id, None)
                break

    # Fire and forget the polling coroutine
    asyncio.create_task(_poll_loop())


async def cmd_stop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _auth_check(update):
        return await _denied(update)
    chat_id = update.effective_chat.id
    task_id = _chat_tasks.get(chat_id)

    # Also check all running tasks if no chat-specific one
    if not task_id:
        running = [t for t in tasks.values() if t["status"] == "running"]
        if running:
            task_id = running[0]["id"]

    if not task_id:
        return await update.message.reply_text("No running task to stop.")
    task = tasks.get(task_id)
    if task:
        task["stop_requested"] = True
        await update.message.reply_text(
            f"🛑 Stop requested: {task['command']} ({task_id})")
    else:
        await update.message.reply_text("Task not found.")


async def cmd_session(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    if not args:
        return await update.message.reply_text("Usage: /session <email>")
    req = SingleEmailReq(email=args[0])
    await _run_task_and_report(update, context, "session", req, _run_session)


async def cmd_writeback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    email = None
    count = 0
    for a in args:
        if "@" in a:
            email = a
        elif a.isdigit():
            count = int(a)
    req = SingleEmailReq(email=email, count=count)
    await _run_task_and_report(update, context, "writeback", req, _run_writeback)


async def cmd_relogin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    email = None
    count = 1
    for a in args:
        if "@" in a:
            email = a
        elif a.isdigit():
            count = int(a)
    req = SingleEmailReq(email=email, count=count)
    await _run_task_and_report(update, context, "relogin", req, _run_relogin)


async def cmd_oauth(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    email = args[0] if args else None
    count = int(args[1]) if len(args) > 1 else 0
    req = SingleEmailReq(email=email, count=count)
    await _run_task_and_report(update, context, "oauth", req, _run_oauth)


async def cmd_oauth_free(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Usage: /oauth_free [email] [count] [category] [dry]"""
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    email = None
    count = 0
    cat = None
    dry = False
    for a in args:
        al = a.lower()
        if al == "dry" or al == "dry_run" or al == "preview":
            dry = True
        elif "@" in a:
            email = a
        elif a.isdigit():
            count = int(a)
        else:
            cat = a
    req = OAuthFreeReq(email=email, count=count, category=cat, dry_run=dry)
    await _run_task_and_report(update, context, "oauth-free", req, _run_oauth_free)


async def cmd_oauth_multi(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Usage: /oauth_multi <email> [writeback]"""
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    if not args:
        return await update.message.reply_text(
            "Usage: /oauth_multi <email> [writeback]\n"
            "Add 'writeback' to also write AT back to DM")
    email = None
    writeback = False
    for a in args:
        if "@" in a:
            email = a
        elif a.lower() in ("writeback", "wb"):
            writeback = True
    if not email:
        email = args[0]
    req = OAuthMultiReq(email=email, writeback=writeback)
    await _run_task_and_report(update, context, "oauth-multi", req, _run_oauth_multi)


async def cmd_health(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    dry = "dry" in " ".join(args).lower()
    req = HealthCheckReq(dry_run=dry)
    await _run_task_and_report(update, context, "health-check", req, _run_health_check)


async def cmd_deactivation(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    cat = args[0] if args else None
    req = DeactivationScanReq(category=cat)
    await _run_task_and_report(update, context, "deactivation-scan", req, _run_deactivation_scan)


async def cmd_invite(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    if len(args) < 2:
        return await update.message.reply_text(
            "Usage: /invite <source_email> <target_email> [role]\n"
            "Roles: standard-user, account-admin")

    source_email = args[0]
    target_email = args[1]
    role = args[2] if len(args) > 2 else "standard-user"

    await update.message.reply_text(f"📨 Inviting {target_email} via {source_email}...")

    dm = DataManager(CFG["dm_base"], CFG["dm_token"])
    acc = dm.find_account(source_email)
    if not acc:
        return await update.message.reply_text(f"❌ {source_email} not found in DM")

    at = acc.get("access_token", "")
    if not at or len(at) < 100:
        return await update.message.reply_text("❌ No valid AT for this account")

    claims = decode_jwt_claims(at)
    auth_info = claims.get("https://api.openai.com/auth", {})
    account_id = auth_info.get("chatgpt_account_id", "")
    plan = auth_info.get("chatgpt_plan_type", "?")

    if not account_id:
        return await update.message.reply_text("❌ No account_id in AT JWT")

    # Direct invite via ChatGPT API
    from curl_cffi import requests as cffi_requests
    proxy = _get_proxy()
    proxies = {"https": proxy, "http": proxy} if proxy else None
    headers = {
        "Authorization": f"Bearer {at}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/",
    }

    r = cffi_requests.post(
        f"https://chatgpt.com/backend-api/accounts/{account_id}/invites",
        headers=headers,
        json={"email_addresses": [target_email], "role": role},
        impersonate="chrome136",
        proxies=proxies,
        timeout=30,
    )

    if r.status_code in (200, 201):
        data = r.json()
        invites = data.get("account_invites", [])
        errors = data.get("errored_emails", [])
        parts = [f"✅ Invite sent!",
                 f"Source: {source_email} (plan={plan})",
                 f"Target: {target_email} -> {role}"]
        if invites:
            parts.append(f"Invite ID: {invites[0].get('id', '?')}")
        if errors:
            parts.append(f"⚠️ Errors: {errors}")
        await update.message.reply_text("\n".join(parts))
    else:
        await update.message.reply_text(f"❌ Invite failed: HTTP {r.status_code}\n{r.text[:300]}")


async def cmd_check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    if not args:
        return await update.message.reply_text("Usage: /check <email>")

    email = args[0]
    dm = DataManager(CFG["dm_base"], CFG["dm_token"])
    acc = dm.find_account(email, include_disabled=True)

    if not acc:
        return await update.message.reply_text(f"❌ {email} not found in DM")

    at = acc.get("access_token", "")
    at_info = ""
    if at and len(at) > 100:
        claims = decode_jwt_claims(at)
        auth = claims.get("https://api.openai.com/auth", {})
        at_info = (f"  JWT plan: {auth.get('chatgpt_plan_type', '?')}\n"
                   f"  account_id: {auth.get('chatgpt_account_id', '?')}\n"
                   f"  AT len: {len(at)}")
        vr = dm.verify_token(at)
        at_info += f"\n  verify: {'✅' if vr.get('ok') else '❌'} {vr.get('reason', '')}"

    deact = check_deactivated(email, CFG.get("otp_token", ""))
    deact_str = "🔴 YES" if deact.get("deactivated") else "🟢 No"

    text = (f"🔎 {email}\n\n"
            f"ID: {acc.get('id')}\n"
            f"Category: {acc.get('category', '?')}\n"
            f"Status: {acc.get('status', '?')}\n"
            f"Token ctx: {acc.get('token_context', '?')}\n"
            f"Seats: {acc.get('seats_total', '?')} total / {acc.get('seats_left', '?')} left\n"
            f"Sub status: {acc.get('subscription_status', '?')}\n"
            f"Deactivated: {deact_str}\n")
    if at_info:
        text += f"\n📜 AT Info\n{at_info}\n"
    if acc.get("last_error"):
        text += f"\n⚠️ Last error:\n{acc['last_error'][:200]}"

    await update.message.reply_text(text)


async def cmd_deact(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Check if email(s) are deactivated by scanning inbox.
    Usage: /deact <email> [email2] [email3] ...
    """
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    if not args:
        return await update.message.reply_text("Usage: /deact <email> [email2] ...")

    otp_token = CFG.get("otp_token", "")
    results = []

    if len(args) > 1:
        await update.message.reply_text(f"🔍 Checking {len(args)} emails...")

    for email in args:
        if "@" not in email:
            results.append(f"⚠️ {email} — invalid email")
            continue
        r = check_deactivated(email, otp_token)
        if r.get("error"):
            results.append(f"⚠️ {email} — error: {r['error']}")
        elif r.get("deactivated"):
            count = r.get("matched_count", 0)
            matches = r.get("matches", [])
            subject = matches[0].get("subject", "")[:60] if matches else ""
            results.append(f"🔴 {email} — DEACTIVATED ({count} match)\n   {subject}")
        else:
            results.append(f"🟢 {email} — OK")

    await update.message.reply_text("\n".join(results))


async def cmd_accounts(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    query = args[0].lower() if args else ""

    dm = DataManager(CFG["dm_base"], CFG["dm_token"])
    accounts = dm.list_accounts()

    if query:
        accounts = [a for a in accounts if query in (a.get("email") or "").lower()]

    if not accounts:
        return await update.message.reply_text("No accounts found.")

    lines = []
    for a in accounts[:30]:
        email = a.get("email", "?")
        cat = a.get("category", "?")
        tc = a.get("token_context", "?")
        st = a.get("status", "?")
        st_icon = "🟢" if st == "active" else "🔴"
        lines.append(f"{st_icon} `{email}` {cat}/{tc}")

    total = len(accounts)
    text = f"📊 *Accounts* ({total} total" + (f", showing {len(lines)})" if total > 30 else ")") + "\n\n"
    text += "\n".join(lines)
    await update.message.reply_text(text)


async def cmd_tasks(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _auth_check(update):
        return await _denied(update)

    sorted_tasks = sorted(tasks.values(), key=lambda t: t["created_at"], reverse=True)[:15]
    if not sorted_tasks:
        return await update.message.reply_text("No tasks yet.")

    lines = []
    for t in sorted_tasks:
        st = t["status"]
        icon = "⏳" if st == "running" else ("✅" if st == "done" else "🛑")
        cmd = t["command"]
        time_str = t["created_at"][:19].replace("T", " ") if t.get("created_at") else ""
        lines.append(f"{icon} {t['id']} | {cmd} | {time_str}")

    await update.message.reply_text("📋 Recent Tasks\n\n" + "\n".join(lines))


async def cmd_proxy(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Proxy management.
    /proxy                          — show status
    /proxy <url>                    — set global proxy
    /proxy none                    — clear global proxy
    /proxy register <url>          — set proxy for register only
    /proxy register none           — register uses no proxy (direct)
    /proxy register clear          — remove register override (use global)
    """
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    import web.app as wa

    _COMMANDS = {"register", "session", "writeback", "relogin", "oauth",
                 "oauth-free", "oauth-multi", "health-check", "deactivation-scan"}

    if not args:
        lines = ["🌐 Proxy Settings\n",
                 f"Global: {_mask_proxy(wa._runtime_proxy) or '(config default)'}",
                 f"Config: {_mask_proxy(CFG.get('proxy')) or 'none'}",
                 f"Active: {_mask_proxy(_get_proxy()) or 'none'}"]
        if wa._task_proxies:
            lines.append("\nPer-task overrides:")
            for cmd, val in sorted(wa._task_proxies.items()):
                display = "DIRECT (no proxy)" if val == wa._DIRECT else _mask_proxy(val)
                lines.append(f"  {cmd}: {display}")
        return await update.message.reply_text("\n".join(lines))

    # Check if first arg is a command name
    if args[0].lower() in _COMMANDS:
        cmd = args[0].lower()
        if len(args) < 2:
            val = wa._task_proxies.get(cmd)
            if val:
                display = "DIRECT (no proxy)" if val == wa._DIRECT else _mask_proxy(val)
                return await update.message.reply_text(f"🌐 {cmd}: {display}")
            return await update.message.reply_text(f"🌐 {cmd}: (using global)")

        raw = args[1]
        if raw.lower() == "clear":
            wa._task_proxies.pop(cmd, None)
            return await update.message.reply_text(f"🌐 {cmd}: override removed (using global)")
        if raw.lower() in ("none", "direct"):
            wa._task_proxies[cmd] = wa._DIRECT
            return await update.message.reply_text(f"🌐 {cmd}: set to DIRECT (no proxy)")
        parsed = _parse_proxy(raw)
        if not parsed:
            return await update.message.reply_text(f"❌ Invalid proxy: {raw}")
        wa._task_proxies[cmd] = parsed
        return await update.message.reply_text(f"🌐 {cmd}: set to {_mask_proxy(parsed)}")

    # Global proxy
    raw = args[0]
    if raw.lower() in ("none", "clear", "reset"):
        wa._runtime_proxy = None
        _save_proxy(None)
        return await update.message.reply_text("🌐 Global proxy cleared")

    parsed = _parse_proxy(raw)
    if not parsed:
        return await update.message.reply_text(f"❌ Invalid proxy: {raw}")

    wa._runtime_proxy = parsed
    _save_proxy(parsed)
    await update.message.reply_text(f"🌐 Global proxy set: {_mask_proxy(parsed)}")


def _pick_valid_accounts(dm: DataManager, count: int) -> tuple[list, int]:
    """Pick up to `count` unsubscribed accounts with valid AT. Mark expired as unknown."""
    all_accounts = dm.list_accounts()
    candidates = []
    for a in all_accounts:
        tc = (a.get("token_context") or "").lower()
        st = (a.get("status") or "").lower()
        sub = (a.get("subscription_status") or "").lower()
        at = a.get("access_token") or ""
        if st not in ("active", "error"):
            continue
        if tc == "team":
            continue
        if sub in ("active", "paid", "subscribed"):
            continue
        if a.get("payment_link"):
            continue
        if not at or len(at) < 100:
            continue
        candidates.append(a)

    candidates.sort(key=lambda x: (
        0 if (x.get("token_context") or "").lower() == "free" else 1,
        int(x.get("id") or 10**9),
    ))

    valid = []
    expired = 0
    for cand in candidates:
        if len(valid) >= count:
            break
        vr = dm.verify_token(cand.get("access_token", ""))
        if vr.get("ok"):
            valid.append(cand)
        else:
            expired += 1
            cand_id = cand.get("id")
            tc = (cand.get("token_context") or "").lower()
            # Only mark non-team accounts as unknown (don't downgrade team accounts)
            if cand_id and tc != "team":
                dm.patch_account(cand_id, {"token_context": "unknown"})
    return valid, expired


async def cmd_pay(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Generate payment link(s).
    /pay [country] [count]              — auto-pick N accounts
    /pay email@x.com [country]          — specific account
    /pay DE 3                           — 3 accounts, Germany
    """
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []

    _COUNTRIES = {"US", "DE", "GB", "JP", "FR", "IT", "ES", "NL", "CA", "AU", "SG", "HK", "KR", "BR"}
    emails = []
    country = "US"
    count = 1
    for a in args:
        if a.upper() in _COUNTRIES:
            country = a.upper()
        elif "@" in a:
            emails.append(a)
        elif a.isdigit():
            count = int(a)

    currency = {"US": "USD", "DE": "EUR", "GB": "GBP", "JP": "JPY",
                "FR": "EUR", "IT": "EUR", "ES": "EUR", "NL": "EUR",
                "CA": "CAD", "AU": "AUD", "SG": "SGD", "HK": "HKD",
                "KR": "KRW", "BR": "BRL",
                }.get(country, "USD")
    seats = 5
    dm = DataManager(CFG["dm_base"], CFG["dm_token"])
    proxy = _get_proxy()

    # Build account list
    accounts_to_process = []
    if emails:
        for em in emails:
            acc = dm.find_account(em)
            if acc:
                accounts_to_process.append(acc)
            else:
                await update.message.reply_text(f"⚠️ {em} not found, skipping")
    else:
        want = max(count, 1)
        await update.message.reply_text(f"🔍 Finding {want} account(s) with valid AT...")
        valid, expired = _pick_valid_accounts(dm, want)
        if expired:
            await update.message.reply_text(f"⚠️ {expired} expired accounts marked unknown")
        if not valid:
            return await update.message.reply_text(
                "❌ No accounts with valid AT.\nRun /relogin first.")
        accounts_to_process = valid

    await update.message.reply_text(
        f"💳 Generating {len(accounts_to_process)} link(s) — {country} ({currency})")

    results = []
    for acc in accounts_to_process:
        email = acc.get("email", "?")
        at = acc.get("access_token", "")
        acc_id = acc.get("id")

        r = generate_payment_link(
            access_token=at, country=country,
            currency=currency, seat_quantity=seats, proxy=proxy)

        if r.get("ok"):
            link = r["payment_link"]
            if acc_id:
                dm.patch_account(acc_id, {
                    "payment_link": link,
                    "subscription_status": "pending_payment",
                })
            results.append(f"✅ {email}\n🔗 {link}")
        else:
            results.append(f"❌ {email}: {r.get('error', '?')[:80]}")

    await update.message.reply_text("\n\n".join(results))


def _resolve_account_by_input(dm: DataManager, token: str) -> dict | None:
    """Resolve an account from email, payment URL (checkout or success-team),
    or access token. Payment URLs are matched by extracting cs_live_... session id
    or account_id from query string."""
    import re as _re
    token = token.strip()

    # 1) Email
    if "@" in token and "chatgpt.com" not in token:
        return dm.find_account(token, include_disabled=True)

    # 2) Payment URL (checkout or payments/success-team)
    if ("chatgpt.com" in token or "checkout" in token or
        "cs_live_" in token or "cs_test_" in token):
        m = _re.search(r"cs_(?:live|test)_[A-Za-z0-9]+", token)
        session_id = m.group(0) if m else ""
        m = _re.search(r"[?&]account_id=([0-9a-fA-F-]{16,})", token)
        account_id = m.group(1) if m else ""

        all_accs = dm.list_accounts(include_disabled=True)

        if session_id:
            for a in all_accs:
                pl = a.get("payment_link") or ""
                if pl and session_id in pl:
                    return a

        if account_id:
            for a in all_accs:
                if (a.get("team_account_id") or "").lower() == account_id.lower():
                    return a

        for a in all_accs:
            pl = a.get("payment_link") or ""
            if pl and (token in pl or pl in token):
                return a
        return None

    # 3) Access token / JWT — decode to find email
    if len(token) > 100 and "." in token:
        claims = decode_jwt_claims(token)
        profile = claims.get("https://api.openai.com/profile", {})
        email = profile.get("email", "")
        if email:
            return dm.find_account(email, include_disabled=True)

    return None


async def cmd_mark_paid(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Mark account(s) as subscribed.
    /mark_paid <email|link|token> [email2|link2] ... [category]
    Supports batch: multiple emails/links/tokens in one command.
    """
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []

    if not args:
        return await update.message.reply_text(
            "Usage: /mark_paid <items...> [category]\n\n"
            "Items: email, payment link, or access token\n"
            "Category: enterprise, business, plus (default: enterprise)\n\n"
            "Examples:\n"
            "/mark_paid user@x.com\n"
            "/mark_paid user@x.com user2@y.com enterprise\n"
            "/mark_paid https://chatgpt.com/checkout/...")

    _CATEGORIES = {"enterprise", "business", "plus", "free", "team"}
    category = "enterprise"
    targets = []
    for a in args:
        if a.lower() in _CATEGORIES:
            category = a.lower()
        else:
            targets.append(a)

    if not targets:
        return await update.message.reply_text("❌ No email/link/token provided")

    dm = DataManager(CFG["dm_base"], CFG["dm_token"])
    seats = 9  # actual seats after subscription

    if len(targets) > 1:
        await update.message.reply_text(f"📝 Processing {len(targets)} item(s) as {category}...")

    import datetime as _dt
    results = []
    for t in targets:
        acc = _resolve_account_by_input(dm, t)
        if not acc:
            label = t if len(t) < 40 else t[:37] + "..."
            results.append(f"❌ {label} — not found")
            continue

        email = acc.get("email", "?")
        acc_id = acc.get("id")

        fields = [
            ("category", category),
            ("status", "active"),
            ("subscription_status", "active"),
            ("subscription_at", _dt.datetime.now(_dt.timezone.utc).isoformat()),
            ("seats_total", seats),
            ("seats_left", seats),
            ("token_context", "free"),
        ]

        failed = []
        for k, v in fields:
            for _retry in range(2):
                r = dm.patch_account(acc_id, {k: v})
                if r.get("ok"):
                    break
                import time as _t; _t.sleep(0.3)
            else:
                failed.append(k)

        if not failed:
            results.append(f"✅ {email} → {category} ({seats} seats)")
        else:
            results.append(f"⚠️ {email} → partial (failed: {', '.join(failed)})")

    await update.message.reply_text("\n".join(results))


async def cmd_subscribe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Unified post-subscription flow: mark_paid → writeback → oauth_multi.
    Usage: /subscribe <email|link|token> [category]
    Optional flags in args: nomark / nowriteback / nooauth / nowb
    """
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    if not args:
        return await update.message.reply_text(
            "Usage: /subscribe <email|link|token> [category] [flags]\n\n"
            "Runs: mark_paid → writeback → oauth_multi (+ DM writeback)\n"
            "Flags (disable a step): nomark | nowriteback | nooauth | nowb\n"
            "Categories: enterprise (default), business, plus")

    _CATEGORIES = {"enterprise", "business", "plus"}
    _FLAGS = {"nomark", "nowriteback", "nooauth", "nowb"}
    target = None
    category = "enterprise"
    flags = set()
    for a in args:
        al = a.lower()
        if al in _FLAGS:
            flags.add(al)
        elif al in _CATEGORIES:
            category = al
        elif not target:
            target = a

    if not target:
        return await update.message.reply_text("❌ Provide email, payment link, or AT")

    req = SubscribeFlowReq(
        target=target,
        category=category,
        do_mark_paid=("nomark" not in flags),
        do_writeback=("nowriteback" not in flags),
        do_oauth_multi=("nooauth" not in flags),
        dm_writeback=("nowb" not in flags),
    )
    await _run_task_and_report(update, context, "subscribe-flow", req, _run_subscribe_flow)


# ---------------------------------------------------------------------------
#  Callback query handler (InlineKeyboard menu)
# ---------------------------------------------------------------------------

async def menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    data = query.data
    prompts = {
        "menu_register": "Send count and domain:\n`/register [count] [domain]`\nor just `/register`",
        "menu_session": "Send email:\n`/session <email>`",
        "menu_writeback": "Send email and count:\n`/writeback [email] [count]`\nor just `/writeback`",
        "menu_relogin": "Send email and count:\n`/relogin [email] [count]`",
        "menu_oauth": "Send email and count:\n`/oauth [email] [count]`\nor just `/oauth`",
        "menu_oauth_free": "Send params:\n`/oauth_free [email] [count] [category]`\nor just `/oauth_free`",
        "menu_oauth_multi": "Send email:\n`/oauth_multi <email>`",
        "menu_health": "Run health check:\n`/health` or `/health dry`",
        "menu_deactivation": "Run deactivation scan:\n`/deactivation [category]`\nor just `/deactivation`",
        "menu_invite": "Send source and target:\n/invite <source_email> <target_email> [role]",
        "menu_pay": "Generate payment link:\n/pay [email] [country] [seats]\n\nLeave email blank to auto-pick.",
        "menu_mark_paid": "Mark account as subscribed:\n/mark_paid <email_or_link> [category]\n\nCategory: enterprise, business, plus",
        "menu_accounts": "Search accounts:\n/accounts [query]\nor just /accounts",
        "menu_tasks": "Show tasks:\n/tasks",
    }

    text = prompts.get(data, "Unknown menu item")
    await query.message.reply_text(text)


# ---------------------------------------------------------------------------
#  Deactivation Watchdog — periodic inbox scan + TG alert
# ---------------------------------------------------------------------------

# Track already-alerted emails to avoid spam
_alerted_emails: set[str] = set()
_watchdog_chat_id: int | None = None  # chat to send alerts to
_watchdog_interval: int = 3600  # seconds (default 60 min)


# One representative domain per worker (2 workers)
_WATCHDOG_DOMAINS = ["zrfr.dpdns.org", "aitech.email"]

def _is_deact_email(msg: dict) -> bool:
    """Check if an email is an OpenAI deactivation notice.
    Rule: subject contains both 'openai' and 'deactivated'."""
    subj = (msg.get("subject") or "").lower()
    return "deactivated" in subj and "openai" in subj


async def _scan_inbox_deactivation(otp_token: str) -> list:
    """Scan the 2 worker inboxes for new deactivation emails within the interval.
    Returns list of {email, subject, date} for emails NOT yet alerted."""
    global _alerted_emails
    import urllib.request, json as _json
    from datetime import datetime, timezone, timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=_watchdog_interval + 60)

    new_hits = []
    for domain in _WATCHDOG_DOMAINS:
        all_emails = []
        page = 0
        while True:
            offset = page * 100
            url = f"https://m.{domain}/api/emails?limit=100&offset={offset}"
            headers = {"Authorization": f"Bearer {otp_token}"}
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as r:
                    data = _json.loads(r.read())
            except Exception as e:
                logger.warning("Watchdog inbox: %s page %d failed: %s", domain, page, e)
                break
            items = data if isinstance(data, list) else (data.get("items") or data.get("data") or [])
            if not items:
                break
            all_emails.extend(items)
            oldest_date = items[-1].get("created_at", "")
            try:
                oldest_dt = datetime.fromisoformat(oldest_date.replace("Z", "+00:00"))
                if oldest_dt < cutoff:
                    break
            except Exception:
                break
            page += 1
            if page > 10:
                break

        for msg in all_emails:
            if not _is_deact_email(msg):
                continue
            rcpt = (msg.get("rcpt_to") or "").lower()
            if rcpt in _alerted_emails:
                continue
            _alerted_emails.add(rcpt)
            new_hits.append({
                "email": rcpt,
                "subject": msg.get("subject", "")[:60],
                "date": msg.get("created_at", "")[:19],
            })
    return new_hits


# Track AT verification state to avoid re-alerting each cycle
_at_failed_alerted: set[str] = set()
_at_error_alerted: set[str] = set()


def _verify_team_ats(dm: DataManager) -> dict:
    """Verify all team-context account ATs via DM /api/token/verify.
    Returns {broken: [...], errors: [...], healthy_count: int}."""
    broken = []    # deactivated/unauthorized — will auto-disable
    errors = []    # network/api failures — manual check
    healthy = 0

    try:
        accounts = dm.list_accounts(include_disabled=False)
    except Exception as e:
        logger.error("Watchdog AT: list_accounts failed: %s", e)
        return {"broken": [], "errors": [{"email": "(list_accounts)", "error": str(e)}],
                "healthy_count": 0}

    for acc in accounts:
        tc = (acc.get("token_context") or "").lower()
        st = (acc.get("status") or "").lower()
        at = acc.get("access_token") or ""
        email = (acc.get("email") or "").lower()
        # Only check active/error team accounts with valid AT
        if tc != "team" or st not in ("active", "error"):
            continue
        if not at or len(at) < 100:
            continue

        try:
            r = dm.verify_token(at)
        except Exception as e:
            if email not in _at_error_alerted:
                _at_error_alerted.add(email)
                errors.append({"email": email, "acc_id": acc.get("id"),
                               "error": f"exception: {e}"})
            continue

        if r.get("ok"):
            healthy += 1
            _at_failed_alerted.discard(email)
            _at_error_alerted.discard(email)
            continue

        http_status = r.get("status", 0)
        reason = r.get("reason", "")
        is_fatal = (http_status == 401 or
                    reason in ("unauthorized", "account_deactivated",
                               "token_invalidated", "forbidden"))

        if is_fatal:
            if email not in _at_failed_alerted:
                _at_failed_alerted.add(email)
                broken.append({
                    "email": email,
                    "acc_id": acc.get("id"),
                    "category": acc.get("category", "?"),
                    "status": http_status,
                    "reason": reason,
                })
        else:
            if email not in _at_error_alerted:
                _at_error_alerted.add(email)
                errors.append({
                    "email": email,
                    "acc_id": acc.get("id"),
                    "error": f"HTTP {http_status} {reason}".strip(),
                })

    return {"broken": broken, "errors": errors, "healthy_count": healthy}


async def _handle_deactivated(dm: DataManager, email: str) -> dict:
    """Auto-disable a deactivated account in DM and delete from CPAB."""
    acc = dm.find_account(email, include_disabled=True)
    result = {"dm_disabled": False, "cpab_deleted": 0, "error": None,
              "already_disabled": False}
    if not acc:
        result["error"] = "not_in_dm"
        return result

    # Skip if already disabled
    if (acc.get("status") or "").lower() == "disabled":
        result["already_disabled"] = True
    else:
        try:
            pr = dm.patch_account(acc["id"], {"status": "disabled"})
            result["dm_disabled"] = pr.get("ok", False)
        except Exception as e:
            result["error"] = f"dm_patch: {e}"

    try:
        cpa = CPAAdmin(CFG["cpa_admin_base"], CFG["cpa_admin_user"],
                       CFG["cpa_admin_password"])
        if cpa.login():
            files = cpa.list_auth_files()
            auth_ids = [a["auth_id"] for a in cpa.collect_auth_ids_for_emails({email}, files)]
            for aid in auth_ids:
                if cpa.delete_auth_file(aid):
                    result["cpab_deleted"] += 1
    except Exception as e:
        result["error"] = (result["error"] or "") + f" cpab: {e}"

    return result


async def _watchdog_job(context: ContextTypes.DEFAULT_TYPE):
    """Periodic: scan inbox for deactivation + verify team AT + auto-handle."""
    chat_id = _watchdog_chat_id
    if not chat_id:
        return

    otp_token = CFG.get("otp_token", "")
    dm = DataManager(CFG["dm_base"], CFG["dm_token"])

    # 1) Inbox scan
    new_deact = await _scan_inbox_deactivation(otp_token)

    action_lines = []
    for d in new_deact:
        actions = await _handle_deactivated(dm, d["email"])
        # Skip notification if already disabled (nothing new to report)
        if actions.get("already_disabled") and actions["cpab_deleted"] == 0:
            continue
        tag = []
        if actions["dm_disabled"]:
            tag.append("DM disabled")
        elif actions.get("already_disabled"):
            tag.append("already disabled")
        if actions["cpab_deleted"]:
            tag.append(f"CPAB -{actions['cpab_deleted']}")
        if actions["error"]:
            tag.append(f"err: {actions['error']}")
        if not tag:
            tag.append("not found")
        action_lines.append(f"🔴 {d['email']}  [{', '.join(tag)}]\n   {d['subject']}")

    # 2) Team AT verification
    at_check = _verify_team_ats(dm)
    broken_ats = at_check["broken"]
    at_errors = at_check["errors"]

    deact_emails = {d["email"] for d in new_deact}
    for b in broken_ats:
        if b["email"] in deact_emails:
            continue
        actions = await _handle_deactivated(dm, b["email"])
        tag = [f"AT {b['status']}/{b.get('reason','')}".strip("/")]
        if actions["dm_disabled"]:
            tag.append("DM disabled")
        if actions["cpab_deleted"]:
            tag.append(f"CPAB -{actions['cpab_deleted']}")
        action_lines.append(f"🔴 {b['email']} ({b['category']})  [{', '.join(tag)}]")

    # 3) Compose notification
    lines = []
    if action_lines:
        lines.append(f"🚨 Deactivation — {len(action_lines)} account(s)\n")
        lines.extend(action_lines)
    if at_errors:
        lines.append(f"\n⚠️ AT verify errors — {len(at_errors)} (manual check)\n")
        for e in at_errors[:10]:
            lines.append(f"  {e['email']}: {e['error'][:80]}")
        if len(at_errors) > 10:
            lines.append(f"  ... +{len(at_errors) - 10} more")

    if lines:
        try:
            await context.bot.send_message(chat_id, "\n".join(lines))
        except Exception as e:
            logger.error("Watchdog: send alert failed: %s", e)
    else:
        logger.info("Watchdog: no issues — %d team ATs healthy",
                    at_check["healthy_count"])

    # Persist status for Web UI consumption
    try:
        import datetime as _dt
        status_data = {
            "running": True,
            "interval_sec": _watchdog_interval,
            "last_run": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "alerted_count": len(_alerted_emails),
            "team_ats_healthy": at_check["healthy_count"],
            "team_ats_broken": len(broken_ats),
            "team_ats_errors": len(at_errors),
            "last_alerts": action_lines[:5],
        }
        with open("/tmp/codex_watchdog.json", "w") as f:
            json.dump(status_data, f)
    except Exception as e:
        logger.warning("Watchdog: failed to write status file: %s", e)


async def cmd_watch(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Control deactivation watchdog.
    /watch          — show status
    /watch on [min] — start (default 5 min interval)
    /watch off      — stop
    """
    if not _auth_check(update):
        return await _denied(update)

    global _watchdog_chat_id, _watchdog_interval, _alerted_emails
    args = context.args or []
    job_queue = context.application.job_queue

    if not args:
        # Status
        jobs = job_queue.get_jobs_by_name("deact_watchdog")
        if jobs:
            await update.message.reply_text(
                f"👁 Watchdog is ON\n"
                f"Interval: {_watchdog_interval}s ({_watchdog_interval // 60}m)\n"
                f"Alerted: {len(_alerted_emails)} emails\n"
                f"Chat: {_watchdog_chat_id}")
        else:
            await update.message.reply_text("👁 Watchdog is OFF\n\nUse /watch on [minutes] to start")
        return

    action = args[0].lower()

    if action == "on":
        interval_min = int(args[1]) if len(args) > 1 and args[1].isdigit() else 60
        _watchdog_interval = max(60, interval_min * 60)
        _watchdog_chat_id = update.effective_chat.id

        # Remove old jobs
        for job in job_queue.get_jobs_by_name("deact_watchdog"):
            job.schedule_removal()

        # Schedule new
        job_queue.run_repeating(
            _watchdog_job,
            interval=_watchdog_interval,
            first=10,  # first run in 10s
            name="deact_watchdog",
        )
        await update.message.reply_text(
            f"👁 Watchdog started!\n"
            f"Scanning every {interval_min} min\n"
            f"Alerts will be sent to this chat")

    elif action == "off":
        for job in job_queue.get_jobs_by_name("deact_watchdog"):
            job.schedule_removal()
        await update.message.reply_text("👁 Watchdog stopped")

    elif action == "reset":
        _alerted_emails.clear()
        await update.message.reply_text(f"👁 Alert history cleared — will re-check all accounts")

    else:
        await update.message.reply_text("Usage: /watch on [minutes] | off | reset")


# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------

def main():
    if not BOT_TOKEN:
        logger.error("No bot token. Set tg_bot_token in config.json or TG_BOT_TOKEN env var")
        sys.exit(1)

    logger.info("Starting Codex Toolkit Telegram Bot...")
    if ALLOWED_USERS:
        logger.info("Allowed users: %s", ALLOWED_USERS)

    app = Application.builder().token(BOT_TOKEN).build()

    # Commands
    app.add_handler(CommandHandler("auth", cmd_auth))
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("register", cmd_register))
    app.add_handler(CommandHandler("register_loop", cmd_register_loop))
    app.add_handler(CommandHandler("stop", cmd_stop))
    app.add_handler(CommandHandler("session", cmd_session))
    app.add_handler(CommandHandler("writeback", cmd_writeback))
    app.add_handler(CommandHandler("relogin", cmd_relogin))
    app.add_handler(CommandHandler("oauth", cmd_oauth))
    app.add_handler(CommandHandler("oauth_free", cmd_oauth_free))
    app.add_handler(CommandHandler("oauth_multi", cmd_oauth_multi))
    app.add_handler(CommandHandler("health", cmd_health))
    app.add_handler(CommandHandler("deactivation", cmd_deactivation))
    app.add_handler(CommandHandler("invite", cmd_invite))
    app.add_handler(CommandHandler("check", cmd_check))
    app.add_handler(CommandHandler("accounts", cmd_accounts))
    app.add_handler(CommandHandler("tasks", cmd_tasks))
    app.add_handler(CommandHandler("proxy", cmd_proxy))
    app.add_handler(CommandHandler("deact", cmd_deact))
    app.add_handler(CommandHandler("pay", cmd_pay))
    app.add_handler(CommandHandler("mark_paid", cmd_mark_paid))
    app.add_handler(CommandHandler("subscribe", cmd_subscribe))
    app.add_handler(CommandHandler("watch", cmd_watch))

    # Inline keyboard
    app.add_handler(CallbackQueryHandler(menu_callback))

    # Set bot commands menu + auto-start watchdog for owner
    async def post_init(application):
        await application.bot.set_my_commands([
            ("auth", "Authenticate: /auth <password>"),
            ("start", "Show main menu"),
            ("help", "List all commands"),
            ("check", "Check account: /check <email>"),
            ("session", "Get session: /session <email>"),
            ("register", "Register: /register [count] [domain]"),
            ("register_loop", "Loop register: /register_loop [min] [max]"),
            ("stop", "Stop running task"),
            ("writeback", "Writeback: /writeback [email] [count]"),
            ("relogin", "Relogin: /relogin [email] [count]"),
            ("oauth", "OAuth CPAB: /oauth [email] [count]"),
            ("oauth_free", "OAuth Free: /oauth_free [email]"),
            ("oauth_multi", "OAuth all WS: /oauth_multi <email>"),
            ("health", "Health check: /health [dry]"),
            ("deactivation", "Deact scan: /deactivation [cat]"),
            ("invite", "Invite: /invite <src> <target>"),
            ("accounts", "Search: /accounts [query]"),
            ("tasks", "Recent tasks"),
            ("deact", "Check deactivated: /deact <email> ..."),
            ("watch", "Deact watchdog: /watch on [min] | off"),
            ("pay", "Payment link: /pay [email] [country] [seats]"),
            ("mark_paid", "Mark paid: /mark_paid <email|link> [cat]"),
            ("subscribe", "Subscribe flow: mark+writeback+oauth_multi"),
            ("proxy", "Proxy: /proxy [url]"),
        ])

        # Auto-start watchdog: bind to owner's DM chat (chat_id == user_id for private chats)
        global _watchdog_chat_id
        _watchdog_chat_id = OWNER_ID
        jq = application.job_queue
        if jq:
            for job in jq.get_jobs_by_name("deact_watchdog"):
                job.schedule_removal()
            jq.run_repeating(
                _watchdog_job,
                interval=_watchdog_interval,
                first=30,  # first run 30s after boot
                name="deact_watchdog",
            )
            logger.info("Watchdog auto-started: chat=%s, interval=%ds",
                        OWNER_ID, _watchdog_interval)
        else:
            logger.warning("JobQueue unavailable — watchdog not started")

    app.post_init = post_init

    # Error handler
    async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
        logger.error("Exception: %s", context.error, exc_info=context.error)
        if update and hasattr(update, "effective_chat") and update.effective_chat:
            try:
                await context.bot.send_message(
                    update.effective_chat.id,
                    f"❌ Error: {context.error}")
            except Exception:
                pass

    app.add_error_handler(error_handler)

    logger.info("Bot is running. Press Ctrl+C to stop.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
