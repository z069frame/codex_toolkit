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
    _run_oauth, _run_oauth_free, _run_oauth_multi,
    _run_health_check, _run_deactivation_scan,
    RegisterReq, SingleEmailReq, OAuthFreeReq, OAuthMultiReq,
    HealthCheckReq, DeactivationScanReq,
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

# Track per-chat running task for /stop
_chat_tasks: dict[int, str] = {}  # chat_id → task_id
# Authenticated user IDs (password-verified this session)
_authed_users: set[int] = set()


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def _auth_check(update: Update) -> bool:
    uid = update.effective_user.id
    # Whitelist takes priority (if configured)
    if ALLOWED_USERS:
        return uid in ALLOWED_USERS
    # Otherwise password-based auth
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
        at = result.get("access_token", "")
        cookie = result.get("session_cookie", "")
        plan = result.get("plan_type", "?")
        email = result.get("email", "?")
        summary = (f"🔑 Session for {email}\n"
                   f"Plan: {plan}\n"
                   f"AT: {len(at)} chars\n"
                   f"Cookie: {len(cookie)} chars")
        await update.message.reply_text(summary)
        # Send full AT as plain text for easy copy
        await update.message.reply_text(at)
        if cookie:
            await update.message.reply_text(f"Session Cookie:\n{cookie}")
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
            "🔎 /check <email> — Check account\n"
            "📊 /accounts [query] — Search accounts\n"
            "💳 /pay [email] [country] [seats] — Payment link\n"
            "✅ /mark_paid <email|link> [cat] — Mark subscribed\n"
            "📋 /tasks — Recent tasks\n"
            "🌐 /proxy [url] — View/set proxy")
    await update.message.reply_text(text)


async def cmd_register(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    count = int(args[0]) if args else 1
    domain = args[1] if len(args) > 1 else None
    req = RegisterReq(count=count, domain=domain)
    await _run_task_and_report(update, context, "register", req, _run_register)


async def cmd_register_loop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    min_s = int(args[0]) if args else 30
    max_s = int(args[1]) if len(args) > 1 else 180
    req = RegisterReq(count=1, loop=True, min_sleep=min_s, max_sleep=max_s)
    await _run_task_and_report(update, context, "register", req, _run_register)


async def cmd_stop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _auth_check(update):
        return await _denied(update)
    chat_id = update.effective_chat.id
    task_id = _chat_tasks.get(chat_id)
    if not task_id:
        return await update.message.reply_text("No running task to stop.")
    task = tasks.get(task_id)
    if task:
        task["stop_requested"] = True
        await update.message.reply_text(f"🛑 Stop requested for {task_id}")
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
    email = args[0] if args else None
    count = int(args[1]) if len(args) > 1 else 0
    req = SingleEmailReq(email=email, count=count)
    await _run_task_and_report(update, context, "writeback", req, _run_writeback)


async def cmd_relogin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    email = args[0] if args else None
    count = int(args[1]) if len(args) > 1 else 1
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
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    email = args[0] if args else None
    count = int(args[1]) if len(args) > 1 else 0
    cat = args[2] if len(args) > 2 else None
    req = OAuthFreeReq(email=email, count=count, category=cat)
    await _run_task_and_report(update, context, "oauth-free", req, _run_oauth_free)


async def cmd_oauth_multi(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []
    if not args:
        return await update.message.reply_text("Usage: /oauth_multi <email>")
    req = OAuthMultiReq(email=args[0])
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
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []

    if not args:
        # Show current proxy
        import web.app as wa
        text = (f"🌐 *Proxy*\n"
                f"Active: `{_mask_proxy(_get_proxy()) or 'none'}`\n"
                f"Config: `{_mask_proxy(CFG.get('proxy')) or 'none'}`\n"
                f"Override: `{_mask_proxy(wa._runtime_proxy) or 'none'}`")
        return await update.message.reply_text(text)

    # Set proxy
    import web.app as wa
    raw = args[0]
    if raw.lower() in ("none", "clear", "reset"):
        wa._runtime_proxy = None
        _save_proxy(None)
        return await update.message.reply_text("🌐 Proxy override cleared")

    parsed = _parse_proxy(raw)
    if not parsed:
        return await update.message.reply_text(f"❌ Invalid proxy: `{raw}`")

    wa._runtime_proxy = parsed
    _save_proxy(parsed)
    await update.message.reply_text(f"🌐 Proxy set: `{_mask_proxy(parsed)}`")


async def cmd_pay(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Generate payment link for a free account.
    Usage: /pay [email] [country] [seats]
    If no email: auto-pick an unsubscribed account with valid AT.
    """
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []

    # Parse flexible args: /pay [email] [country] [seats] — any order
    _COUNTRIES = {"US", "DE", "GB", "JP", "FR", "IT", "ES", "NL", "CA", "AU", "SG", "HK", "KR", "BR"}
    email = None
    country = "US"
    seats = 5
    for a in args:
        if a.upper() in _COUNTRIES:
            country = a.upper()
        elif "@" in a:
            email = a
        elif a.isdigit():
            seats = int(a)

    currency = {"US": "USD", "DE": "EUR", "GB": "GBP", "JP": "JPY",
                "FR": "EUR", "IT": "EUR", "ES": "EUR", "NL": "EUR",
                "CA": "CAD", "AU": "AUD", "SG": "SGD", "HK": "HKD",
                "KR": "KRW", "BR": "BRL",
                }.get(country, "USD")

    dm = DataManager(CFG["dm_base"], CFG["dm_token"])
    proxy = _get_proxy()

    if email:
        # Use specified account
        acc = dm.find_account(email)
        if not acc:
            return await update.message.reply_text(f"❌ {email} not found in DM")
    else:
        # Auto-pick: free/unknown token_context, active, no payment_link yet, has AT
        await update.message.reply_text("🔍 Auto-picking an unsubscribed account with valid AT...")
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
                continue  # already subscribed
            if sub in ("active", "paid", "subscribed"):
                continue
            if a.get("payment_link"):
                continue  # already has link
            if not at or len(at) < 100:
                continue  # no AT
            candidates.append(a)

        if not candidates:
            return await update.message.reply_text("❌ No eligible accounts found (all subscribed or no AT)")

        # Sort: prefer accounts with token_context=free over unknown
        candidates.sort(key=lambda x: (
            0 if (x.get("token_context") or "").lower() == "free" else 1,
            int(x.get("id") or 10**9),
        ))

        # Try candidates until we find one with valid AT; mark expired ones
        acc = None
        expired_count = 0
        checked = 0
        for cand in candidates[:20]:
            checked += 1
            vr = dm.verify_token(cand.get("access_token", ""))
            if vr.get("ok"):
                acc = cand
                break
            else:
                # Mark as unknown so relogin/session can refresh later
                expired_count += 1
                cand_id = cand.get("id")
                if cand_id:
                    dm.patch_account(cand_id, {"token_context": "unknown"})

        status_msg = f"Checked {checked} accounts"
        if expired_count:
            status_msg += f", {expired_count} expired (marked token_context=unknown)"
        await update.message.reply_text(f"🔍 {status_msg}")

        if not acc:
            return await update.message.reply_text(
                f"❌ No account with valid AT found.\n"
                f"Run /relogin to refresh expired accounts first.")

    email = acc.get("email", "?")
    at = acc.get("access_token", "")
    acc_id = acc.get("id")

    await update.message.reply_text(
        f"💳 Generating payment link...\n"
        f"Account: {email}\n"
        f"Country: {country} ({currency})\n"
        f"Seats: {seats}")

    result = generate_payment_link(
        access_token=at,
        country=country,
        currency=currency,
        seat_quantity=seats,
        proxy=proxy,
    )

    if not result.get("ok"):
        return await update.message.reply_text(f"❌ Failed: {result.get('error', '?')}")

    link = result["payment_link"]
    ws_name = result.get("workspace_name", "?")

    # Save link to DM
    if acc_id:
        dm.patch_account(acc_id, {
            "payment_link": link,
            "subscription_status": "pending_payment",
        })

    await update.message.reply_text(
        f"✅ Payment link generated!\n\n"
        f"Account: {email}\n"
        f"Workspace: {ws_name}\n"
        f"Country: {country} | Seats: {seats}\n\n"
        f"🔗 {link}")


async def cmd_mark_paid(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Mark an account as subscribed after payment.
    Usage: /mark_paid <email_or_link> [category]
    """
    if not _auth_check(update):
        return await _denied(update)
    args = context.args or []

    if not args:
        return await update.message.reply_text(
            "Usage: /mark_paid <email_or_payment_link> [category]\n"
            "Category: enterprise, business, plus (default: enterprise)")

    target = args[0]
    category = args[1].lower() if len(args) > 1 else "enterprise"

    dm = DataManager(CFG["dm_base"], CFG["dm_token"])

    # Determine if target is email or link
    if "@" in target:
        acc = dm.find_account(target)
        if not acc:
            return await update.message.reply_text(f"❌ {target} not found in DM")
    elif "chatgpt.com" in target or "checkout" in target:
        # Search by payment_link
        all_accounts = dm.list_accounts(include_disabled=True)
        acc = None
        for a in all_accounts:
            pl = a.get("payment_link") or ""
            if pl and (target in pl or pl in target):
                acc = a
                break
        if not acc:
            return await update.message.reply_text(f"❌ No account found with that payment link")
    else:
        return await update.message.reply_text("❌ Provide an email or payment link")

    email = acc.get("email", "?")
    acc_id = acc.get("id")

    # Seats: parse from args or default 5
    seats = 5
    for a in args:
        if a.isdigit():
            seats = int(a)
            break

    import datetime as _dt
    patch = {
        "category": category,
        "status": "active",
        "subscription_status": "active",
        "subscription_at": _dt.datetime.utcnow().isoformat() + "Z",
        "seats_total": seats,
        "seats_left": seats,
        "token_context": "free",  # needs writeback/session to get team AT
    }

    result = dm.patch_account(acc_id, patch)
    if result.get("ok"):
        await update.message.reply_text(
            f"✅ Marked as subscribed!\n\n"
            f"Account: {email}\n"
            f"Category: {category}\n"
            f"Seats: {seats}\n"
            f"Status: active\n"
            f"Token context: free (run /writeback {email} to get team AT)")
    else:
        await update.message.reply_text(f"❌ DM patch failed: {result}")


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
    app.add_handler(CommandHandler("pay", cmd_pay))
    app.add_handler(CommandHandler("mark_paid", cmd_mark_paid))

    # Inline keyboard
    app.add_handler(CallbackQueryHandler(menu_callback))

    # Set bot commands menu
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
            ("pay", "Payment link: /pay [email] [country] [seats]"),
            ("mark_paid", "Mark paid: /mark_paid <email|link> [cat]"),
            ("proxy", "Proxy: /proxy [url]"),
        ])

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
