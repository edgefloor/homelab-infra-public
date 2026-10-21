"""Verify Zig's native profile, lifecycle tools, skill, and read-only boundary."""
import argparse
import json
import os
from pathlib import Path
from unittest import mock

from gateway.session_context import clear_session_vars, set_session_vars
from hermes_cli.config import load_config
from hermes_cli.plugins import get_plugin_manager
from hermes_cli.runtime_provider import resolve_runtime_provider
from incident_client import IncidentClient
from run_agent import AIAgent
from tools.registry import registry


ROOM = "!5JwKK2zosgeKhLrXTG:matrix.homelab.example"
OWNER = "@operator:matrix.homelab.example"
TOOLS = {
    "cve_lookup", "cve_work_scope", "cve_relationships", "cve_evidence",
    "cve_record_outcome", "cve_propose_change",
}
RETIRED = {"incident_query", "incident_investigate"}


parser = argparse.ArgumentParser()
parser.add_argument("--live", action="store_true")
args = parser.parse_args()

home = Path(os.environ["HERMES_HOME"])
assert home.parts[-2:] == ("profiles", "zig")
assert not any(key.startswith("HONCHO") for key in os.environ)
assert not os.access("/var/lib/hermes-agent/.hermes/honcho.json", os.R_OK)

runtime = resolve_runtime_provider()
assert runtime["base_url"] == "http://127.0.0.1:8792"
assert runtime["api_mode"] == "codex_responses"
manager = get_plugin_manager()
manager.discover_and_load()
for name in TOOLS:
    assert registry.get_entry(name).handler
for name in RETIRED:
    try:
        entry = registry.get_entry(name)
    except (KeyError, ValueError):
        entry = None
    assert entry is None, name
assert "investigate" not in manager._plugin_commands

skill = home / "skills/homelab-oncall/SKILL.md"
skill_text = skill.read_text()
assert "cve_work_scope" in skill_text and "cve_propose_change" in skill_text
assert "incident_investigate" not in skill_text

cfg = load_config()
assert cfg["onboarding"]["enabled"] is False
assert cfg["onboarding"]["profile_build"] == "off"
assert cfg["display"]["interim_assistant_messages"] is False
for key in ("dispatch_in_gateway", "auto_decompose",
            "auto_subscribe_on_create", "review_dispatch"):
    assert cfg["kanban"].get(key) is False, (key, cfg["kanban"].get(key))
assert "zig_incidents" in cfg["platform_toolsets"]["matrix"]
assert "kanban" in cfg["platform_toolsets"]["matrix"]


def bind(message_id):
    return set_session_vars(
        platform="matrix", chat_id=ROOM, chat_type="group", thread_id="$verification",
        user_id=OWNER, message_id=message_id)


tokens = bind("$zig-lifecycle-verification")
try:
    value = json.loads(registry.get_entry("cve_lookup").handler({}))
    assert isinstance(value.get("data"), dict) and "error" not in value["data"]
finally:
    clear_session_vars(tokens)


def agent():
    value = AIAgent(
        model="gpt-5.6-sol", provider=runtime["provider"], api_mode=runtime["api_mode"],
        base_url=runtime["base_url"], api_key=runtime["api_key"],
        enabled_toolsets=cfg["platform_toolsets"]["matrix"], session_db=None,
        save_trajectories=False, max_iterations=4, quiet_mode=True)
    assert TOOLS <= value.valid_tool_names, value.valid_tool_names
    assert RETIRED.isdisjoint(value.valid_tool_names), value.valid_tool_names
    assert not any((value._memory_enabled, value._user_profile_enabled,
                    value._memory_manager, value._memory_store))
    return value


agent()
print("Native Zig profile has passive Kanban, the managed skill, and six lifecycle tools; retired dispatch tools and personal memory are absent.")

if args.live:
    original = IncidentClient.call

    def read_only(self, action, **values):
        assert action in {
            "get", "query", "conversation_context", "investigation_scope",
            "remediation_scope", "relationships", "lifecycle_evidence",
        }, action
        return original(self, action, **values)

    with mock.patch.object(IncidentClient, "call", read_only):
        tokens = bind("$zig-native-conversation-verification")
        try:
            result = agent().run_conversation(
                "Summarize the retained lifecycle record in this Matrix thread. Do not change it.")
            assert result.get("final_response"), result.get("error")
        finally:
            clear_session_vars(tokens)
    print("Ordinary native Matrix-thread conversation completed without lifecycle mutations.")
