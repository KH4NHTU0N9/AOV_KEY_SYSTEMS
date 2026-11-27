# backend/cli.py
import argparse
import time

import crypto
import db
from config import get_admin_token


def main() -> None:
    db.init_db()
    _, pub_b64 = crypto.ensure_keypair()

    parser = argparse.ArgumentParser(description="KeyAuth local management CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("keygen", help="Generate new license keys")
    p_gen.add_argument("-n", "--count", type=int, default=1)
    p_gen.add_argument("-p", "--prefix", default="KTAOV")
    p_gen.add_argument("--hours", type=int, default=720, help="Validity duration in hours (default 720 = 30 days)")
    p_gen.add_argument("--max-devices", type=int, default=1)
    p_gen.add_argument("--immediate", action="store_true", help="Start countdown immediately instead of first login")
    p_gen.add_argument("--note", default="")

    p_list = sub.add_parser("list", help="List existing keys")
    p_list.add_argument("--search", default="")

    p_ban = sub.add_parser("ban", help="Ban a key")
    p_ban.add_argument("key")
    p_ban.add_argument("--reason", default="Banned by CLI")

    p_unban = sub.add_parser("unban", help="Unban a key")
    p_unban.add_argument("key")

    p_reset = sub.add_parser("reset-device", help="Clear bound device IDs for a key")
    p_reset.add_argument("key")

    p_ext = sub.add_parser("extend", help="Extend key validity in hours")
    p_ext.add_argument("key")
    p_ext.add_argument("hours", type=int)

    p_del = sub.add_parser("delete", help="Delete a key")
    p_del.add_argument("key")

    sub.add_parser("pubkey", help="Print Ed25519 base64 public key for the iOS SDK")
    sub.add_parser("token", help="Print the Admin UI/API X-Admin-Token")

    args = parser.parse_args()

    if args.cmd == "keygen":
        created = db.create_keys(
            count=args.count,
            prefix=args.prefix,
            duration_hours=args.hours,
            max_devices=args.max_devices,
            note=args.note,
            activate_on_first_use=not args.immediate,
        )
        for k in created:
            print(f"{k['license_key']}  (duration={k['duration_hours']}h, max_devices={k['max_devices']}, status={k['computed_status']})")
    elif args.cmd == "list":
        rows = db.list_keys(args.search)
        if not rows:
            print("No keys found.")
            return
        for r in rows:
            exp = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["expires_at"])) if r["expires_at"] else "unused"
            devs = ",".join(r["bound_devices"]) or "-"
            print(f"{r['license_key']} | {r['computed_status']:7s} | dev {len(r['bound_devices'])}/{r['max_devices']} [{devs}] | exp: {exp} | {r['note']}")
    elif args.cmd == "ban":
        print("OK" if db.set_ban_status(args.key, True, args.reason) else "Key not found")
    elif args.cmd == "unban":
        print("OK" if db.set_ban_status(args.key, False, "") else "Key not found")
    elif args.cmd == "reset-device":
        print("OK" if db.reset_devices(args.key) else "Key not found")
    elif args.cmd == "extend":
        print("OK" if db.extend_key(args.key, args.hours) else "Key not found")
    elif args.cmd == "delete":
        print("OK" if db.delete_key(args.key) else "Key not found")
    elif args.cmd == "pubkey":
        print(pub_b64)
    elif args.cmd == "token":
        print(get_admin_token())


if __name__ == "__main__":
    main()
