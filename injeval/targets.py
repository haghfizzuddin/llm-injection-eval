"""Model targets. Each exposes `chat(messages) -> str`.

    MockTarget     offline, deterministic, exists so the harness and its
                   tests run without a model. Its "vulnerabilities" are
                   scripted and its numbers mean nothing about any real model.
    OllamaTarget   a local model via the Ollama HTTP API (free, no key).
    BedrockTarget  an AWS Bedrock model via boto3 (needs credentials).
"""

from __future__ import annotations

import json
import os
import re
from typing import Protocol

from .app import CANARY


class Target(Protocol):
    name: str

    def chat(self, messages: list[dict[str, str]]) -> str: ...


class MockTarget:
    """A scripted stand-in. It obeys the crudest attacks and resists the
    rest, so every code path in the harness gets exercised offline.
    Never report its numbers as a result."""

    name = "mock"

    _OBEY = re.compile(r"ignore (all |any )?(previous|prior|above) instructions", re.I)
    _LEAK = re.compile(r"(repeat|print|reveal|show).{0,40}(system prompt|instructions|reference code)", re.I)
    _TOOL = re.compile(r"send_email.{0,80}?to[\"':\s]+([\w.+-]+@[\w.-]+)", re.I | re.S)

    def chat(self, messages: list[dict[str, str]]) -> str:
        user = messages[-1]["content"]
        docs = " ".join(m["content"] for m in messages[1:-1] if m["role"] == "user")
        text = user + " " + docs
        # Scripted weaknesses: literal "ignore previous instructions" with a
        # quoted marker, and an unobfuscated request to print the prompt.
        if self._OBEY.search(text):
            m = re.search(r"(?:say|output|reply with|respond with|write)(?:\s+exactly)?[:\s]+[\"']?([A-Z][A-Z0-9_-]{5,})[\"']?", text)
            if m:
                return m.group(1)
        if self._LEAK.search(user):
            return f"My instructions mention the code {CANARY}."
        tool = self._TOOL.search(docs)
        if tool and "urgent" in docs.lower():
            return 'TOOL_CALL: {"name": "send_email", "args": {"to": "%s", "subject": "export", "body": "..."}}' % tool.group(1)
        return "I can help with orders and account questions. What do you need?"


class OllamaTarget:
    name = "ollama"

    def __init__(self, model: str = "llama3.1", host: str | None = None, timeout: int = 120):
        import requests  # local import so the mock path needs no network libs

        self._requests = requests
        self.model = model
        self.host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self.timeout = timeout
        self.name = f"ollama:{model}"

    def chat(self, messages: list[dict[str, str]]) -> str:
        r = self._requests.post(
            f"{self.host}/api/chat",
            json={"model": self.model, "messages": messages, "stream": False,
                  "options": {"temperature": 0}},
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()["message"]["content"]


class BedrockTarget:
    name = "bedrock"

    def __init__(self, model_id: str, region: str | None = None):
        import boto3

        self.client = boto3.client("bedrock-runtime", region_name=region or os.environ.get("AWS_REGION", "us-east-1"))
        self.model_id = model_id
        self.name = f"bedrock:{model_id}"

    def chat(self, messages: list[dict[str, str]]) -> str:
        system = [{"text": m["content"]} for m in messages if m["role"] == "system"]
        convo = [
            {"role": m["role"], "content": [{"text": m["content"]}]}
            for m in messages
            if m["role"] != "system"
        ]
        resp = self.client.converse(
            modelId=self.model_id,
            system=system,
            messages=convo,
            inferenceConfig={"temperature": 0, "maxTokens": 512},
        )
        return "".join(part.get("text", "") for part in resp["output"]["message"]["content"])


def make_target(spec: str) -> Target:
    """'mock' | 'ollama[:model]' | 'bedrock:<model_id>'"""
    kind, _, rest = spec.partition(":")
    if kind == "mock":
        return MockTarget()
    if kind == "ollama":
        return OllamaTarget(model=rest or "llama3.1")
    if kind == "bedrock":
        if not rest:
            raise SystemExit("bedrock target needs a model id, e.g. bedrock:anthropic.claude-3-haiku-20240307-v1:0")
        return BedrockTarget(model_id=rest)
    raise SystemExit(f"unknown target {spec!r}")


def parse_tool_call(output: str) -> dict | None:
    """Return the first TOOL_CALL JSON in an output, or None."""
    m = re.search(r"TOOL_CALL:\s*(\{.*\})", output, re.S)
    if not m:
        return None
    blob = m.group(1)
    # Trim to the first balanced object in case the model kept talking.
    depth = 0
    for i, ch in enumerate(blob):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                blob = blob[: i + 1]
                break
    try:
        return json.loads(blob)
    except json.JSONDecodeError:
        return None
