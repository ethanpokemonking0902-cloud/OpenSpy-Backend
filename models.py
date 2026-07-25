"""
Database models for HELIX OSINT Dashboard
"""

from datetime import datetime
from typing import Dict, List, Any
import json

# In-memory database (will be replaced with actual DB)
users_db = {}
scans_db = {}
user_state_db = {}


class User:
    """User model"""
    def __init__(self, discord_id: str, username: str, email: str, avatar: str = None):
        self.discord_id = discord_id
        self.username = username
        self.email = email
        self.avatar = avatar
        self.created_at = datetime.utcnow().isoformat()
        self.last_login = datetime.utcnow().isoformat()
        self.preferences = {
            'theme': 'dark',
            'notifications': True,
            'auto_save': True
        }

    def to_dict(self):
        return {
            'discord_id': self.discord_id,
            'username': self.username,
            'email': self.email,
            'avatar': self.avatar,
            'created_at': self.created_at,
            'last_login': self.last_login,
            'preferences': self.preferences
        }


class Scan:
    """Scan/lookup result model"""
    def __init__(self, discord_id: str, tool_name: str, target: str, result: Dict[str, Any]):
        self.id = f"{discord_id}_{tool_name}_{datetime.utcnow().timestamp()}"
        self.discord_id = discord_id
        self.tool_name = tool_name
        self.target = target
        self.result = result
        self.created_at = datetime.utcnow().isoformat()
        self.starred = False

    def to_dict(self):
        return {
            'id': self.id,
            'discord_id': self.discord_id,
            'tool_name': self.tool_name,
            'target': self.target,
            'result': self.result,
            'created_at': self.created_at,
            'starred': self.starred
        }


class UserState:
    """User app state model (current page, filters, etc)"""
    def __init__(self, discord_id: str):
        self.discord_id = discord_id
        self.current_page = 'overview'
        self.active_filters = {}
        self.recent_searches = []
        self.favorites = []
        self.last_updated = datetime.utcnow().isoformat()

    def to_dict(self):
        return {
            'discord_id': self.discord_id,
            'current_page': self.current_page,
            'active_filters': self.active_filters,
            'recent_searches': self.recent_searches,
            'favorites': self.favorites,
            'last_updated': self.last_updated
        }


# Database operations
def create_or_update_user(discord_id: str, username: str, email: str, avatar: str = None) -> User:
    """Create or update a user"""
    if discord_id in users_db:
        user = users_db[discord_id]
        user.last_login = datetime.utcnow().isoformat()
    else:
        user = User(discord_id, username, email, avatar)
        users_db[discord_id] = user
    return user


def get_user(discord_id: str) -> User:
    """Get user by Discord ID"""
    return users_db.get(discord_id)


def save_scan(discord_id: str, tool_name: str, target: str, result: Dict[str, Any]) -> Scan:
    """Save a scan result"""
    scan = Scan(discord_id, tool_name, target, result)
    if discord_id not in scans_db:
        scans_db[discord_id] = []
    scans_db[discord_id].append(scan)
    return scan


def get_user_scans(discord_id: str, limit: int = 50) -> List[Scan]:
    """Get user's scans"""
    scans = scans_db.get(discord_id, [])
    return sorted(scans, key=lambda x: x.created_at, reverse=True)[:limit]


def get_scan_by_id(scan_id: str) -> Scan:
    """Get scan by ID"""
    for user_scans in scans_db.values():
        for scan in user_scans:
            if scan.id == scan_id:
                return scan
    return None


def star_scan(scan_id: str):
    """Star/bookmark a scan"""
    scan = get_scan_by_id(scan_id)
    if scan:
        scan.starred = not scan.starred
    return scan


def get_user_state(discord_id: str) -> UserState:
    """Get user's app state"""
    if discord_id not in user_state_db:
        user_state_db[discord_id] = UserState(discord_id)
    return user_state_db[discord_id]


def save_user_state(discord_id: str, state: Dict[str, Any]) -> UserState:
    """Save user's app state"""
    user_state = get_user_state(discord_id)
    user_state.current_page = state.get('current_page', user_state.current_page)
    user_state.active_filters = state.get('active_filters', user_state.active_filters)
    user_state.recent_searches = state.get('recent_searches', user_state.recent_searches)
    user_state.favorites = state.get('favorites', user_state.favorites)
    user_state.last_updated = datetime.utcnow().isoformat()
    return user_state


def add_recent_search(discord_id: str, tool_name: str, target: str):
    """Add to user's recent searches"""
    user_state = get_user_state(discord_id)
    search = {'tool': tool_name, 'target': target, 'timestamp': datetime.utcnow().isoformat()}
    user_state.recent_searches.insert(0, search)
    # Keep only last 20
    user_state.recent_searches = user_state.recent_searches[:20]
    return user_state
