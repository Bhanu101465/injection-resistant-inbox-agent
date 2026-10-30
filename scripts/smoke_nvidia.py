"""
NVIDIA API smoke test — run this manually AFTER setting up .env.

Usage:
    python scripts/smoke_nvidia.py

Checks:
1. GET /models endpoint availability
2. Plain chat completion
3. Tool-call completion (with graceful 422/404 fallback)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Make sure the project root is on sys.path
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from dotenv import load_dotenv

load_dotenv(_ROOT / ".env")


def _get_client():
    try:
        import openai
    except ImportError:
        sys.exit("[ERROR] openai not installed. Run: pip install openai")

    api_key = os.environ.get("NVIDIA_API_KEY", "")
    base_url = os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
    model = os.environ.get("AGENT_MODEL", "")

    if not api_key:
        sys.exit("[ERROR] NVIDIA_API_KEY is not set. Add it to .env")
    if not model:
        sys.exit("[ERROR] AGENT_MODEL is not set. Add it to .env")

    return openai.OpenAI(api_key=api_key, base_url=base_url), model, openai


def check_models_endpoint(client, openai):
    print("\n[1] Checking /models endpoint …")
    try:
        models = client.models.list()
        names = [m.id for m in models.data][:5]
        print(f"  OK — {len(getattr(models, 'data', []))} model(s) available (first 5): {names}")
    except Exception as exc:
        print(f"  WARNING — endpoint unavailable: {exc}")


def check_plain_chat(client, model, openai):
    print(f"\n[2] Plain chat completion (model={model}) …")
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Reply with exactly: SMOKE_OK"}],
            temperature=0,
            max_tokens=20,
        )
        text = resp.choices[0].message.content or ""
        print(f"  Response: {text.strip()!r}")
        if "SMOKE_OK" in text.upper():
            print("  OK — model responded correctly")
        else:
            print("  WARNING — unexpected response (model might not follow instructions precisely)")
    except Exception as exc:
        print(f"  FAIL — {exc}")


def check_tool_call(client, model, openai):
    print(f"\n[3] Tool-call completion (model={model}) …")
    dummy_tool = {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get the weather for a city.",
            "parameters": {
                "type": "object",
                "properties": {
                    "city": {"type": "string", "description": "City name"}
                },
                "required": ["city"],
            },
        },
    }
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "What's the weather in Paris?"}],
            tools=[dummy_tool],
            tool_choice="auto",
            temperature=0,
        )
        msg = resp.choices[0].message
        if msg.tool_calls:
            tc = msg.tool_calls[0]
            print(f"  OK — tool call returned: name={tc.function.name!r}, args={tc.function.arguments!r}")
        else:
            print(f"  NOTE — model returned text instead of tool call: {msg.content!r}")
    except openai.BadRequestError as exc:
        print(f"  NOTE — model does not support tool calls (422/400): {exc}")
    except openai.NotFoundError as exc:
        print(f"  NOTE — tool-call endpoint not found (404): {exc}")
    except Exception as exc:
        print(f"  FAIL — {exc}")


def main():
    print("=" * 60)
    print("  NVIDIA API Smoke Test")
    print("=" * 60)
    client, model, openai = _get_client()
    check_models_endpoint(client, openai)
    check_plain_chat(client, model, openai)
    check_tool_call(client, model, openai)
    print("\n" + "=" * 60)
    print("  Smoke test complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
