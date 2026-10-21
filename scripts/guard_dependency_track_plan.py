#!/usr/bin/env python3
"""Allow only the reviewed CPU/RAM increase for the existing incident guest."""
import json
import sys


def validate(plan):
    changes = [r for r in plan.get("resource_changes", []) if r["change"]["actions"] != ["no-op"]]
    if not changes:
        return "converged"
    if len(changes) != 1:
        raise ValueError("plan changes more than the existing incident guest")
    resource = changes[0]
    change = resource["change"]
    if resource["address"] != 'proxmox_virtual_environment_container.managed["incident"]' or change["actions"] != ["update"]:
        raise ValueError("only an in-place incident resource update is allowed")
    before, after = dict(change["before"]), dict(change["after"])
    if before.get("vm_id") != 214 or after.get("vm_id") != 214:
        raise ValueError("guest identity changed")
    for field, key, old, new in (("cpu", "cores", 2, 4), ("memory", "dedicated", 2048, 8192)):
        left, right = before.pop(field), after.pop(field)
        if len(left) != 1 or len(right) != 1:
            raise ValueError("unexpected resource shape")
        left, right = dict(left[0]), dict(right[0])
        if left.pop(key) not in (old, new) or right.pop(key) != new or left != right:
            raise ValueError("unreviewed CPU or RAM setting")
    if before != after:
        raise ValueError("plan also changes non-resource guest configuration")
    return "reviewed-update"


if __name__ == "__main__":
    try:
        print(validate(json.load(sys.stdin)))
    except (KeyError, TypeError, ValueError) as exc:
        sys.exit(f"Refusing Dependency-Track resource plan: {exc}")
