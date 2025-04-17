from datetime import timedelta
from django.core.cache import cache
from django.utils import timezone

FAILURE_LIMIT = 5
LOCK_TIME_LEVELS = {
    1: timedelta(minutes=15),   # 1st block (after first 5 failures)
    2: timedelta(minutes=30),   # 2nd block (after another 5 failures)
    3: timedelta(hours=24),     # 3rd block (after another 5 failures)
}

def get_lockout_info(username):
    attempts = cache.get(f"login_attempts:{username}", 0)
    block_count = cache.get(f"login_block_count:{username}", 0)
    lockout_until = cache.get(f"login_lockout_until:{username}")
    return attempts, block_count, lockout_until

def update_lockout_info(username, attempts=0, block_count=0, lockout_until=None):
    timeout = 24 * 60 * 60  # seconds (1 day)
    cache.set(f"login_attempts:{username}", attempts, timeout=timeout)
    cache.set(f"login_block_count:{username}", block_count, timeout=timeout)
    if lockout_until:
        remaining = (lockout_until - timezone.now()).total_seconds()
        cache.set(f"login_lockout_until:{username}", lockout_until, timeout=remaining)
    else:
        cache.delete(f"login_lockout_until:{username}")





def format_duration(seconds):
    """
    Convert a duration in seconds to a human-readable string in hours and minutes.
    """
    total_minutes = int(seconds // 60)
    hours = total_minutes // 60
    minutes = total_minutes % 60
    parts = []
    if hours:
        parts.append(f"{hours} hour(s)")
    if minutes or not parts:
        parts.append(f"{minutes} minute(s)")
    return " and ".join(parts)