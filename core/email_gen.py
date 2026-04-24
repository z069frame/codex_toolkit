"""
Email + profile generation with anti-fingerprint randomization.

Previous pattern (`<firstname><YYMMDD><3digits>@domain`) got aitech.email
hit by OpenAI's registration_disallowed rule. New approach:

- Multiple email format templates randomly chosen
- Email prefix decoupled from profile display name (different name pool + last name)
- Birthdate distribution widened
- Some formats include last names, initials, years
"""
from __future__ import annotations

import random
import datetime
import string

# First name pool (lowercase for email, capitalized for profile)
FIRST_NAMES = [
    "emma", "olivia", "ava", "isabella", "sophia",
    "liam", "noah", "oliver", "james", "benjamin",
    "charlotte", "amelia", "harper", "evelyn", "abigail",
    "william", "elijah", "lucas", "mason", "logan",
    "mia", "ella", "scarlett", "aria", "chloe",
    "ethan", "alexander", "henry", "jackson", "daniel",
    # Extra variety
    "jack", "michael", "sebastian", "aiden", "owen",
    "luna", "grace", "zoe", "nora", "lily",
    "hazel", "violet", "stella", "riley", "quinn",
    "leo", "theo", "jude", "caleb", "wyatt",
]

LAST_NAMES = [
    "smith", "johnson", "williams", "brown", "jones",
    "garcia", "miller", "davis", "rodriguez", "martinez",
    "hernandez", "lopez", "gonzalez", "wilson", "anderson",
    "thomas", "taylor", "moore", "jackson", "martin",
    "lee", "perez", "thompson", "white", "harris",
    "sanchez", "clark", "ramirez", "lewis", "robinson",
    "walker", "young", "allen", "king", "wright",
    "scott", "torres", "nguyen", "hill", "flores",
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


def _short_year() -> str:
    """Random plausible birth year as 2-digit suffix (e.g. 85-04)."""
    y = random.randint(1980, 2003)
    return str(y)[2:]


def generate_email(domains: list[str], tz_name: str = "Asia/Shanghai",
                   domain: str | None = None) -> str:
    """Generate a randomized email address.

    Picks one of ~6 formats at random so batches look heterogeneous:
      - first.last          e.g. james.smith@aitech.email
      - firstlast           e.g. jamessmith@aitech.email
      - first_last          e.g. james_smith@aitech.email
      - f.last              e.g. j.smith@aitech.email
      - first + yy + n      e.g. james85123@aitech.email
      - first + last + yy   e.g. jamessmith90@aitech.email

    Digits are kept optional so OpenAI can't cheaply regex us.
    """
    picked = domain or get_today_domain(domains, tz_name)
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)
    yy = _short_year()
    n = random.randint(1, 999)  # variable length so fingerprint differs

    # Weighted template pick. Formats with both names are more common —
    # they look more like real people so don't stand out in a batch.
    tpl = random.choices(
        ["first.last", "firstlast", "first_last", "f.last",
         "first.lastyy", "firstyyn", "firstlastyy"],
        weights=[25, 15, 15, 10, 15, 10, 10],
        k=1,
    )[0]

    if tpl == "first.last":
        local = f"{first}.{last}"
    elif tpl == "firstlast":
        local = f"{first}{last}"
    elif tpl == "first_last":
        local = f"{first}_{last}"
    elif tpl == "f.last":
        local = f"{first[0]}.{last}"
    elif tpl == "first.lastyy":
        local = f"{first}.{last}{yy}"
    elif tpl == "firstyyn":
        local = f"{first}{yy}{n}"
    else:  # firstlastyy
        local = f"{first}{last}{yy}"

    return f"{local}@{picked}"


def _pick_display_firstname() -> str:
    """Sample from a broader pool (adds common names not in FIRST_NAMES to
    break the email↔display-name pairing that was fingerprintable)."""
    pool = FIRST_NAMES + [
        "alex", "sam", "chris", "pat", "morgan",
        "jordan", "taylor", "casey", "riley", "avery",
        "parker", "drew", "dakota", "rowan", "finley",
        "emma", "grace", "ella", "sophie", "emily",
        "daniel", "david", "michael", "matthew", "andrew",
    ]
    return random.choice(pool)


def random_display_name() -> str:
    """Return a realistic 'Firstname Lastname' display name. The names are
    picked independently from the email-generation pool so there's no
    deterministic email↔profile correlation OpenAI's risk model can latch
    onto.
    """
    first = _pick_display_firstname().capitalize()
    last = random.choice(LAST_NAMES).capitalize()
    return f"{first} {last}"


def random_birthdate() -> str:
    """Random plausible birthdate, widened range (age 22-45)."""
    # Center around adults, avoid under-18 edge (some APIs reject)
    year = random.randint(1979, 2003)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return f"{year}-{month:02d}-{day:02d}"
