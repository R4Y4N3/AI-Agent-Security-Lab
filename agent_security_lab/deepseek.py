"""Opt-in DeepSeek transport. Keys remain server-side; no calls on page load."""

import json
import os
import re
from copy import deepcopy
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

from .agents import AgentError, MAX_RESPONSE_BYTES, NoRedirect, run_tool_agent, tool_definitions

ENDPOINT = "https://api.deepseek.com/chat/completions"


def provider_status():
    key_present = bool(os.environ.get("DEEPSEEK_API_KEY", "").strip())
    enabled = os.environ.get("DEEPSEEK_ENABLE_REQUESTS") == "1"
    model = os.environ.get("DEEPSEEK_MODEL", "deepseek-flash")
    valid_model = bool(re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", model))
    return {"name": "DeepSeek", "model": model if valid_model else "invalid configuration",
            "ready": key_present and enabled and valid_model,
            "message": "Ready for an explicitly authorized attempt." if key_present and enabled and valid_model else
            "DeepSeek is not connected yet. You can explore labs and prepare an attack; live attempts are disabled."}


def wire_messages(messages):
    """Convert internal tool-call objects to DeepSeek's JSON-string arguments."""
    result = []
    pending = []
    for source in messages:
        message = deepcopy(source)
        if message["role"] == "assistant":
            for call in message.get("tool_calls") or []:
                call["type"] = "function"
                if not isinstance(call.get("id"), str) or not call["id"]:
                    raise AgentError("DeepSeek returned a tool call without an ID")
                pending.append(call["id"])
                call["function"]["arguments"] = json.dumps(call["function"]["arguments"])
        elif message["role"] == "tool":
            if not pending:
                raise AgentError("Tool result has no matching model tool call")
            message.pop("tool_name", None)
            message["tool_call_id"] = pending.pop(0)
        result.append(message)
    return result


def request_message(endpoint, model, messages, seed=42, tools=None):
    if endpoint != ENDPOINT or not provider_status()["ready"]:
        raise AgentError("DeepSeek requests are disabled or not configured.")
    body = json.dumps({"model": model, "messages": wire_messages(messages),
        "tools": tool_definitions() if tools is None else tools, "stream": False, "temperature": 0, "max_tokens": 1024,
        "thinking": {"type": "disabled"}}).encode()
    request = Request(ENDPOINT, data=body, headers={"Content-Type": "application/json",
        "Authorization": "Bearer " + os.environ["DEEPSEEK_API_KEY"].strip()})
    try:
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=30) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise AgentError("DeepSeek response exceeded the size limit")
        data = json.loads(raw)
        choice = data["choices"][0]
        message = choice["message"]
        if not isinstance(message, dict):
            raise ValueError("Missing assistant message")
        for call in message.get("tool_calls") or []:
            arguments = call["function"]["arguments"]
            if not isinstance(arguments, str):
                raise ValueError("Expected serialized tool arguments")
            call["function"]["arguments"] = json.loads(arguments)
        message["_response_meta"] = {"model": data.get("model"), "done": True,
            "done_reason": choice.get("finish_reason"), "usage": data.get("usage")}
        return message
    except HTTPError as error:
        raise AgentError(f"DeepSeek request failed (HTTP {error.code}). Check the server's API configuration.") from None
    except (URLError, OSError):
        raise AgentError("DeepSeek could not be reached. No successful attempt was recorded.") from None
    except (ValueError, KeyError, IndexError, TypeError, UnicodeError):
        raise AgentError("DeepSeek returned an invalid tool-calling response.") from None


def run_deepseek(runtime):
    status = provider_status()
    if not status["ready"]:
        raise AgentError(status["message"])
    def requester(endpoint, model, messages, seed=42):
        return request_message(endpoint, model, messages, seed=seed,
            tools=runtime.tool_definitions() if hasattr(runtime, "tool_definitions") else None)
    name = f"deepseek:{status['model']}"
    if getattr(runtime, "lab_id", None) == "memory-poisoning":
        first = run_tool_agent(runtime, status["model"], ENDPOINT, requester, name, max_turns=3, max_calls=6)
        if first["status"] != "completed" or not runtime.input_observed or runtime.memory is None:
            # A completed preparation without a saved note is not a completed attempt.
            first["metrics"]["evaluation_valid"] = False
            first["metrics"]["exclusion_reason"] = "memory_preparation_incomplete"
            return first
        runtime.preparation_complete = True
        runtime.phase = 2
        report = run_tool_agent(runtime, status["model"], ENDPOINT, requester, name, max_turns=3, max_calls=6)
        report["trajectory"] = first["trajectory"] + report["trajectory"]
        report["model_responses"] = first["model_responses"] + report["model_responses"]
        report["phases"] = ["Store meeting note", "Reuse memory in fresh context"]
        return report
    return run_tool_agent(runtime, status["model"], ENDPOINT, requester, name, max_turns=6, max_calls=12)
