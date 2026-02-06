# ai_groq.py
import json
import os
import urllib.request
import urllib.error
from typing import List, Dict, Optional

def groq_chat_completion(
    messages: List[Dict[str, str]],
    api_key: Optional[str],
    model: str,
    base_url: str,
    max_tokens: int = 300,
    temperature: float = 0.4,
    timeout: int = 30,
) -> str:
    """
    Llama a Groq usando endpoint OpenAI-compatible:
    POST {base_url}/chat/completions
    """
    if not api_key:
        return "IA no configurada (falta GROQ_API_KEY)."

    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": int(max_tokens),
        "temperature": float(temperature),
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        data=data,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
            obj = json.loads(raw)
            # OpenAI format: choices[0].message.content
            return (obj.get("choices", [{}])[0].get("message", {}) or {}).get("content", "").strip() or "Sin respuesta."
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return f"Error IA (HTTP {e.code}). {body[:300]}"
    except Exception as e:
        return f"Error IA: {e}"
