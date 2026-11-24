#!/Users/elliot/popopx-chat/popopx-bot-studio/.venv/bin/python
"""Stand-in for popopx-cli: same flags, same WebSocket answers, no network.

Response shapes follow popopx-chat/bots/api/COMMANDS.md + TYPES.md:
  userContactLinkCreated {user, connLinkContact: CreatedConnLink}
  userContactLinkUpdated {user, contactLink: UserContactLink}
  userContactLink        {user, contactLink: UserContactLink}
  groupCreated           {user, groupInfo: GroupInfo}
  groupLinkCreated       {user, groupInfo, groupLink: GroupLink}
  CreatedConnLink        {connFullLink, connShortLink}
"""

import argparse
import asyncio
import json
import os
import sys

import websockets

LINK = {"connFullLink": "popopx:/fakepermanentlink", "connShortLink": "popopx:/fakeshort"}


def parse():
    p = argparse.ArgumentParser()
    p.add_argument("--chat-server-port", type=int, required=True)
    p.add_argument("--database", required=True)
    p.add_argument("--files-folder", required=True)
    p.add_argument("--temp-folder", required=True)
    p.add_argument("--log-level", default="important")
    p.add_argument("--server", default="")
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


def answer(cmd):
    if cmd.startswith("/_create user"):
        return {"type": "activeUser", "user": {"userId": 1, "localDisplayName": "fake"}}
    if cmd.startswith("/_address_settings"):
        try:
            settings = json.loads(cmd.split(None, 2)[2])
        except (IndexError, json.JSONDecodeError):
            settings = {}
        return {"type": "userContactLinkUpdated", "user": {"userId": 1}, "contactLink": contact_link(settings)}
    if cmd.startswith("/_address "):
        return {"type": "userContactLinkCreated", "user": {"userId": 1}, "connLinkContact": dict(LINK)}
    if cmd.startswith("/_show_address"):
        return {"type": "userContactLink", "user": {"userId": 1}, "contactLink": contact_link()}
    if cmd.startswith("/_group "):
        return {"type": "groupCreated", "user": {"userId": 1}, "groupInfo": {"groupId": 42, "localDisplayName": "客服群"}}
    if cmd.startswith("/_create link"):
        return {
            "type": "groupLinkCreated",
            "user": {"userId": 1},
            "groupInfo": {"groupId": 42},
            "groupLink": {
                "userContactLinkId": 2,
                "connLinkContact": dict(LINK),
                "groupLinkId": "gl-42",
                "acceptMemberRole": "member",
            },
        }
    if cmd.startswith("/_contacts"):
        return {"type": "contactsList", "users": [{"userId": 1}], "contacts": [{"contactId": 7, "display_name": "小明"}]}
    if cmd.startswith("/_groups"):
        return {"type": "groupsList", "users": [{"userId": 1}], "groups": [{"groupInfo": {"groupId": 42, "localDisplayName": "客服群"}}]}
    if cmd.startswith("/_accept"):
        return {"type": "acceptingContactRequest", "user": {"userId": 1}, "contact": {"contactId": 8}}
    if cmd.startswith("/_send"):
        return {
            "type": "newChatItems",
            "user": {"userId": 1},
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


async def handler(ws):
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
        await ws.send(json.dumps({"corrId": frame.get("corrId"), "resp": answer(str(frame.get("cmd", "")))}))


async def main():
    args = parse()
    for directory in (os.path.dirname(args.database), args.files_folder, args.temp_folder):
        if directory:
            os.makedirs(directory, exist_ok=True)
    with open(args.database + "_chat.db", "wb") as fh:
        fh.write(b"SQLite format 3\x00fake chat database")
    with open(args.database + "_agent.db", "wb") as fh:
        fh.write(b"SQLite format 3\x00fake agent database")
    async with websockets.serve(handler, "127.0.0.1", args.chat_server_port):
        await asyncio.Future()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
