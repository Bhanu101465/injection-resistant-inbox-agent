import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI

# Fix Windows terminal encoding for emojis in responses
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Load nvidia.env (override=True ensures it always replaces any old session variables)
env_path = Path(__file__).parent / "nvidia.env"
load_dotenv(dotenv_path=env_path, override=True)

key = os.getenv("NEBIUS_API_KEY")
if key:
    key = key.strip().strip("'\"")

model = os.getenv("NEBIUS_MODEL_ID")
if model:
    model = model.strip().strip("'\"")

print("Key found:", bool(key))
print("Model:", model)

client = OpenAI(
    api_key=key,
    base_url="https://api.tokenfactory.nebius.com/v1/",
)

try:
    r = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": "Say hello"}],
    )
    print("\nResponse from model:")
    print(r.choices[0].message.content)
except Exception as e:
    print("ERROR TYPE:", type(e).__name__)
    print("ERROR:", e)
    print("--- Nemotron models on your account ---")
    try:
        for m in client.models.list().data:
            if "nemotron" in m.id.lower():
                print(m.id)
    except Exception as list_err:
        print("Could not list models:", list_err)
