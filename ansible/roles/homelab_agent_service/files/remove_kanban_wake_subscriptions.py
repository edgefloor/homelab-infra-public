#!/usr/bin/env python3
"""Remove existing native Kanban subscriptions that can wake an agent."""
from hermes_cli import kanban_db


def main():
    connection = kanban_db.connect()
    try:
        removed = 0
        for subscription in kanban_db.list_notify_subs(connection):
            if "wake" not in subscription["delivery_mode"]:
                continue
            kanban_db.remove_notify_sub(
                connection, task_id=subscription["task_id"],
                platform=subscription["platform"], chat_id=subscription["chat_id"],
                thread_id=subscription["thread_id"])
            removed += 1
        print(f"removed {removed} Kanban wake subscriptions")
    finally:
        connection.close()


if __name__ == "__main__":
    main()
