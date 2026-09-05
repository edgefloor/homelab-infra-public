"""Render an operator decision from a validated investigation; retain diagnostics in details."""

from __future__ import annotations

VERDICTS = {
    "urgent": "urgent remediation",
    "normal_update": "routine update",
    "targeted_check": "one check needed",
    "insufficient_evidence": "assessment incomplete",
}
REACHABILITY = {
    "confirmed": "The affected behavior is reachable in this deployment.",
    "plausible": "A plausible deployed path remains partly unverified.",
    "not_found": "A required condition was not met in the observed deployment.",
    "unknown": "Deployment reachability could not be established.",
}


def sentence(text: str) -> str:
    text = text.strip()
    return text if text.endswith((".", "!", "?")) else text + "."


def assessments(record: dict):
    groups = {g["group_id"]: g for g in record["scope"]["groups"]}
    paths = {p["path_id"]: p for p in record["scope"]["deployed_paths"]}
    for group in record["investigation"]["groups"]:
        for path in group["paths"]:
            yield group, groups[group["group_id"]], path, paths[path["path_id"]]


def action(path: dict, candidate: dict | None = None) -> str:
    decision, patch = path["decision"], path["patched_artifact"]
    replacement = "the verified replacement"
    if candidate and candidate.get("tag"):
        replacement = f"the verified {candidate['tag']} image"
    if decision == "urgent":
        return (
            f"Prioritize {replacement} now."
            if patch == "available"
            else "Prioritize containment or remediation now; a patched replacement has not been verified."
        )
    if decision == "normal_update":
        return (
            f"Use {replacement} during normal maintenance."
            if patch == "available"
            else "Keep running; update during normal maintenance once a fix is verified."
        )
    if decision == "targeted_check":
        return sentence(path["next_check"])
    return "Resolve the blocked verification before choosing remediation."


def paginate(
    header: str, items: list[str], footer: str = "", words: int = 160
) -> list[str]:
    """Paginate complete facts, preserving decision and qualifiers; reserve numbering space."""
    pages, current = [], []
    overhead = len((header + " " + footer).split()) + 3
    character_overhead = len(header) + len(footer) + 32
    for item in dict.fromkeys(filter(None, items)):
        if (
            len(item.split()) + overhead > words
            or len(item) + character_overhead > 11800
        ):
            raise ValueError("A complete alert item exceeds its word budget")
        if (
            len((" ".join(current) + " " + item).split()) + overhead > words
            or len("\n\n".join([*current, item])) + character_overhead > 11800
        ):
            pages.append("\n\n".join([header, *current, footer]).strip())
            current = []
        current.append(item)
    if current:
        pages.append("\n\n".join([header, *current, footer]).strip())
    return pages


def render_alert(record: dict) -> list[str]:
    pages = []
    buckets = {}
    for group, source, path, identity in assessments(record):
        items = [sentence(path["rationale"])]
        if path["reachability"] in {"unknown", "plausible"}:
            items.append(REACHABILITY[path["reachability"]])
        if not record["scope"]["complete"]:
            items.append(
                "The scanner input was incomplete; this assessment covers only the supplied findings."
            )
        candidate = record.get("patches", {}).get(
            group["group_id"] + ":" + path["path_id"]
        )
        items.append(action(path, candidate))
        key = (
            source["id"],
            source["package"],
            path["decision"],
            path["reachability"],
            tuple(items),
        )
        buckets.setdefault(key, []).append(identity["display_label"])
    priority = {
        "urgent": 0,
        "insufficient_evidence": 1,
        "targeted_check": 2,
        "normal_update": 3,
    }
    for (advisory, _package, decision, _reachability, items), labels in sorted(
        buckets.items(), key=lambda item: priority[item[0][2]]
    ):
        components = (
            ", ".join(labels) if len(labels) <= 3 else f"{len(labels)} components"
        )
        header = (
            f"{advisory} | {record['target']} / {components} — {VERDICTS[decision]}"
        )
        pages.extend(paginate(header, list(items), f"Evidence: {record['record_id']}"))
    if not pages:
        pages = [
            f"CVE | {record['target']} — assessment incomplete\n\nNo deployed paths were supplied.\n\nEvidence: {record['record_id']}"
        ]
    footer = f"Evidence: {record['record_id']}"
    blocks = [page.removesuffix(footer).strip() for page in pages]
    pages = paginate("", blocks, footer)
    return [
        f"({i}/{len(pages)}) {page}" if len(pages) > 1 else page
        for i, page in enumerate(pages, 1)
    ]


def evidence_pages(record: dict, receipts: list[dict]) -> list[str]:
    sources = {r["observation_id"]: r["operation"].replace("_", " ") for r in receipts}
    header = f"Evidence {record['record_id']} | {record['target']}"
    if not record.get("investigation"):
        items = [
            "The investigation is incomplete. "
            + record.get("error", "No validated conclusion is available.")
        ]
        for receipt in receipts:
            if receipt["status"] != "success":
                detail = " ".join(
                    receipt.get("limitations")
                    or ["No complete observation was obtained."]
                )
                items.append(
                    sentence(receipt["operation"].replace("_", " ") + ": " + detail)
                )
        return paginate(header, items, words=1200)
    items = []
    for group, source, path, identity in assessments(record):
        label = f"{source['id']} / {identity['display_label']}"
        items.append(f"{label}: {sentence(group['mechanism'])}")
        for condition in path["preconditions"]:
            provenance = ", ".join(dict.fromkeys(sources[r] for r in condition["refs"]))
            items.append(
                f"{label}: {sentence(condition['claim'])}"
                + (f" Source: {provenance}." if provenance else "")
            )
        items.extend(f"{label}: {sentence(l['text'])}" for l in path["limitations"])
        items.append(f"{label}: {sentence(path['rationale'])} {action(path)}")
        candidate = record.get("patches", {}).get(
            group["group_id"] + ":" + path["path_id"]
        )
        if candidate:
            items.append(
                f"{label}: Verified replacement {candidate['image']} for {candidate['platform']}."
            )
    pages = paginate(header, items, words=1200)
    return [f"({i}/{len(pages)}) {page}" for i, page in enumerate(pages, 1)]
