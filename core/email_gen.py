"""
Email generation with daily domain rotation.
Format: <first_name><YYMMDD><3-digit random>@<domain>
"""
from __future__ import annotations

import random
import datetime

FIRST_NAMES = [
    "emma", "olivia", "ava", "isabella", "sophia",
    "liam", "noah", "oliver", "james", "benjamin",
    "charlotte", "amelia", "harper", "evelyn", "abigail",
    "william", "elijah", "lucas", "mason", "logan",
    "mia", "ella", "scarlett", "aria", "chloe",
    "ethan", "alexander", "henry", "jackson", "daniel",
]


def get_today_domain(domains: list[str], tz_name: str = "Asia/Shanghai") -> str:
    """Pick a domain based on the current date (daily rotation)."""
    try:
        import zoneinfo
        tz = zoneinfo.ZoneInfo(tz_name)
        today = datetime.datetime.now(tz).date()
    except Exception:
        today = datetime.date.today()

    day_index = (today - datetime.date(2025, 1, 1)).days
    return domains[day_index % len(domains)]


def generate_email(domains: list[str], tz_name: str = "Asia/Shanghai",
                   domain: str | None = None) -> str:
    """Generate a random email address.

    If `domain` is provided, use it directly; otherwise pick today's rotating
    domain from the `domains` list.
    """
    picked = domain or get_today_domain(domains, tz_name)
    name = random.choice(FIRST_NAMES)
    today = datetime.date.today()
    date_part = today.strftime("%y%m%d")
    rand_part = f"{random.randint(0, 999):03d}"
    return f"{name}{date_part}{rand_part}@{picked}"


def random_display_name() -> str:
    return random.choice(FIRST_NAMES).capitalize()


def random_birthdate() -> str:
    year = random.randint(1985, 2004)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return f"{year}-{month:02d}-{day:02d}"
