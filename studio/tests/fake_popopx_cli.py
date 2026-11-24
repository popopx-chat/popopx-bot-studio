#!/Users/elliot/popopx-chat/popopx-bot-studio/.venv/bin/python
"""Stand-in for popopx-cli: same flags, same WebSocket answers, no network.

Response shapes follow popopx-chat/bots/api/COMMANDS.md + TYPES.md:
  activeUser             {user: User}                         # /user, /_user, /_create user
  usersList              {users: [UserInfo]}                  # UserInfo = {user, unreadCount}
  userContactLinkCreated {user, connLinkContact: CreatedConnLink}
  userContactLinkUpdated {user, contactLink: UserContactLink}
  userContactLink        {user, contactLink: UserContactLink}
  groupCreated           {user, groupInfo: GroupInfo}
  groupLinkCreated       {user, groupInfo, groupLink: GroupLink}
  CreatedConnLink        {connFullLink, connShortLink}

Errors use the documented ChatError union (TYPES.md, ChatErrorType): ``/user`` on an
empty database answers ``noActiveUser`` and a second ``/_create user`` with the same
name answers ``userExists`` - the reason studio has to probe before creating.

Profiles are kept in a JSON sidecar next to ``--database`` so they survive a process
restart the way a real cli-data directory does: a stopped Bot, a rebooted host or a
restored cold backup all come back with the profile already in place.

Environment knobs:
  FAKE_CLI_EXISTING_USER=<name>  pre-seed a profile (id 3), like restored cli-data
  FAKE_CLI_ACTIVE_SHAPE=error    make /user claim there is no active user
  FAKE_CLI_ACTIVE_SHAPE=null     make /user answer activeUser with a null user
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import websockets

LINK = {"connFullLink": "popopx:/fakepermanentlink", "connShortLink": "popopx:/fakeshort"}
DB_HEADER = b"SQLite format 3\x00fake chat database"
STATE_TAG = b"\nPOPOPX_FAKE_STATE "
SEEDED_ID = 3


class Profiles:
    """The CLI's user table, kept inside the chat database the way popopx-cli does.

    Storing it in ``<prefix>_chat.db`` rather than a sidecar means a restored
    cli-data directory really does come back with its profile, and it keeps the
    file list that Studio cold-backs identical to the real binary's.
    """

    def __init__(self, prefix: str):
        self.path = Path(str(prefix) + "_chat.db")
        self.users: List[Dict[str, Any]] = []
        self.active: Optional[int] = None
        self.load()

    def load(self) -> None:
        try:
            raw = self.path.read_bytes()
        except OSError:
            return
        at = raw.rfind(STATE_TAG)
        if at < 0:
            return
        try:
            data = json.loads(raw[at + len(STATE_TAG):].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return
        if isinstance(data, dict) and isinstance(data.get("users"), list):
            self.users = [u for u in data["users"] if isinstance(u, dict) and u.get("userId")]
            self.active = data.get("active")

    def save(self) -> None:
        body = DB_HEADER
        if self.users:
            body += STATE_TAG + json.dumps({"users": self.users, "active": self.active}).encode("utf-8")
        try:
            self.path.write_bytes(body)
        except OSError:
            pass

    def seed(self, display_name: str) -> None:
        if self.users:
            return
        self.users.append({"userId": SEEDED_ID, "localDisplayName": display_name,
                           "displayName": display_name})
        self.active = SEEDED_ID
        self.save()

    def find(self, name: str) -> Optional[Dict[str, Any]]:
        lowered = str(name).lower()
        for user in self.users:
            if str(user.get("localDisplayName", "")).lower() == lowered:
                return user
        return None

    def by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        for user in self.users:
            if int(user["userId"]) == user_id:
                return user
        return None

    def active_user(self) -> Optional[Dict[str, Any]]:
        return self.by_id(int(self.active)) if self.active else None

    def create(self, display_name: str) -> Dict[str, Any]:
        user = {"userId": max([int(u["userId"]) for u in self.users] or [0]) + 1,
                "localDisplayName": display_name,
                "displayName": display_name}
        self.users.append(user)
        self.active = int(user["userId"])
        self.save()
        return user


def as_json(user: Dict[str, Any], active: bool = True) -> Dict[str, Any]:
    """Render one row as the API's ``User`` record (TYPES.md, User)."""
    return {
        "userId": int(user["userId"]),
        "localDisplayName": user.get("localDisplayName", ""),
        "profile": {"displayName": user.get("displayName", ""),
                    "fullName": user.get("displayName", ""), "peerType": "bot"},
        "activeUser": active,
    }


def chat_error(error_type: Dict[str, Any]) -> Dict[str, Any]:
    return {"type": "chatCmdError", "chatError": {"type": "error", "errorType": error_type}}


def parse():
    p = argparse.ArgumentParser()
    p.add_argument("--chat-server-port", type=int, required=True)
    p.add_argument("--database", required=True)
    p.add_argument("--files-folder", required=True)
    p.add_argument("--temp-folder", required=True)
    p.add_argument("--log-level", default="important")
    p.add_argument("--server", default="")
    p.add_argument("--user-display-name", default="")
    return p.parse_args()


def contact_link(settings=None):
    link = {
        "userContactLinkId": 1,
        "connLinkContact": dict(LINK),
        "shortLinkDataSet": True,
        "shortLinkLargeDataSet": False,
    }
    if settings is not None:
        link["addressSettings"] = settings
    return link


def answer(cmd, profiles: Profiles):
    active = profiles.active_user()
    who = as_json(active) if active else {"userId": 1}
    shape = os.environ.get("FAKE_CLI_ACTIVE_SHAPE", "").strip().lower()

    # /user is ShowActiveUser: noActiveUser is the documented empty-database answer.
    if cmd.split(None, 1)[0] == "/user":
        if active is None or shape == "error":
            return chat_error({"type": "noActiveUser"})
        if shape == "null":
            return {"type": "activeUser", "user": None}
        return {"type": "activeUser", "user": as_json(active)}

    if cmd.split(None, 1)[0] == "/users":
        return {
            "type": "usersList",
            "users": [{"user": as_json(u, active=(int(u["userId"]) == profiles.active)),"unreadCount": 0}
                      for u in profiles.users],
        }

    # /_user is APISetActiveUser - it activates an existing profile, never creates one.
    if cmd.split(None, 1)[0] == "/_user":
        try:
            wanted = int(cmd.split()[1])
        except (IndexError, ValueError):
            return chat_error({"type": "userUnknown"})
        found = profiles.by_id(wanted)
        if found is None:
            return chat_error({"type": "userUnknown"})
        profiles.active = wanted
        profiles.save()
        return {"type": "activeUser", "user": as_json(found)}

    if cmd.startswith("/_create user"):
        try:
            profile = json.loads(cmd.split(None, 2)[2]).get("profile") or {}
        except (IndexError, ValueError, json.JSONDecodeError):
            profile = {}
        name = str(profile.get("displayName") or "")
        # CreateActiveUser documents UserExists, so a name already in cli-data loses.
        clash = profiles.find(name)
        if clash is not None:
            return chat_error({"type": "userExists", "contactName": clash["localDisplayName"]})
        return {"type": "activeUser", "user": as_json(profiles.create(name))}

    if cmd.startswith("/_address_settings"):
        try:
            settings = json.loads(cmd.split(None, 2)[2])
        except (IndexError, json.JSONDecodeError):
            settings = {}
        return {"type": "userContactLinkUpdated", "user": who, "contactLink": contact_link(settings)}
    if cmd.startswith("/_address "):
        return {"type": "userContactLinkCreated", "user": who, "connLinkContact": dict(LINK)}
    if cmd.startswith("/_show_address"):
        return {"type": "userContactLink", "user": who, "contactLink": contact_link()}
    if cmd.startswith("/_group "):
        return {"type": "groupCreated", "user": who,
                "groupInfo": {"groupId": 42, "localDisplayName": "客服群"}}
    if cmd.startswith("/_create link"):
        return {
            "type": "groupLinkCreated",
            "user": who,
            "groupInfo": {"groupId": 42},
            "groupLink": {
                "userContactLinkId": 2,
                "connLinkContact": dict(LINK),
                "groupLinkId": "gl-42",
                "acceptMemberRole": "member",
            },
        }
    if cmd.startswith("/_contacts"):
        return {"type": "contactsList", "users": [{"userId": who["userId"]}],
                "contacts": [{"contactId": 7, "display_name": "小明"}]}
    if cmd.startswith("/_groups"):
        return {"type": "groupsList", "users": [{"userId": who["userId"]}],
                "groups": [{"groupInfo": {"groupId": 42, "localDisplayName": "客服群"}}]}
    if cmd.startswith("/_accept"):
        return {"type": "acceptingContactRequest", "user": who, "contact": {"contactId": 8}}
    if cmd.startswith("/_send"):
        return {
            "type": "newChatItems",
            "user": who,
            "chatItems": [
                {
                    "chatInfo": {"type": "group", "groupInfo": {"groupId": 42, "localDisplayName": "客服群",
                                     "groupProfile": {"displayName": "客服群", "fullName": "客服群"}}},
                    "chatItem": {
                        "chatDir": {"type": "groupSnd",
                                    "groupMember": {"groupMemberId": 1, "memberId": "m1",
                                                    "localDisplayName": "小助手",
                                                    "memberProfile": {"displayName": "小助手", "fullName": "小助手"}}},
                        "meta": {"itemId": 91, "itemTs": "2026-11-24T08:00:00Z",
                                 "itemText": "queued", "itemStatus": {"type": "sent"}},
                        "content": {"type": "text", "text": "queued"},
                    },
                }
            ],
        }
    if cmd.startswith("/_boom"):
        return {"type": "chatCmdError", "chatError": {"error": "syntax", "kind": "bad"}}
    return {"type": "response", "echo": cmd}


async def handler(ws, profiles: Profiles):
    await ws.send(
        json.dumps(
            {
                "resp": {
                    "type": "newChatItems",
                    "chatItems": [
                        {
                            "chatInfo": {"type": "direct", "contact": {"contactId": 7,
                                       "localDisplayName": "小明",
                                       "profile": {"displayName": "小明", "fullName": "小明"}}},
                    "chatItem": {
                        "chatDir": {"type": "directRcv"},
                        "meta": {"itemId": 77, "itemTs": "2026-11-24T08:00:00Z",
                                 "itemText": "你好，Bot", "itemStatus": {"type": "received"}},
                        "content": {"type": "text", "text": "你好，Bot"},
                    },
                        }
                    ],
                }
            }
        )
    )
    async for raw in ws:
        try:
            frame = json.loads(raw)
        except json.JSONDecodeError:
            await ws.send(json.dumps({"resp": {"type": "chatError", "chatError": {"error": "bad json"}}}))
            continue
        await ws.send(json.dumps({"corrId": frame.get("corrId"),
                                  "resp": answer(str(frame.get("cmd", "")), profiles)}))


async def main():
    args = parse()
    for directory in (os.path.dirname(args.database), args.files_folder, args.temp_folder):
        if directory:
            os.makedirs(directory, exist_ok=True)
    profiles = Profiles(args.database)
    seeded = os.environ.get("FAKE_CLI_EXISTING_USER", "").strip()
    if seeded:
        profiles.seed(seeded)
    # A CLI started with --user-display-name creates the profile only while the
    # database is still empty; a stored profile keeps its own name.
    if args.user_display_name and not profiles.users:
        profiles.create(args.user_display_name)
    profiles.save()
    with open(args.database + "_agent.db", "wb") as fh:
        fh.write(b"SQLite format 3\x00fake agent database")
    async with websockets.serve(lambda ws: handler(ws, profiles), "127.0.0.1", args.chat_server_port):
        await asyncio.Future()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
