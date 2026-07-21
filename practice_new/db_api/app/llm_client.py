import json
import os
from typing import Optional

import requests

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL_NAME = "nvidia/nemotron-3-ultra-550b-a55b:free"

_SYSTEM_PROMPT = (
    "Ты анализируешь метаданные (название, описание, README) публичного "
    "PoC/эксплойт-репозитория. Оцени ТОЛЬКО по тексту, похоже ли это на "
    "завершённый, работоспособный эксплойт, или на черновик/заглушку/просто "
    "упоминание CVE без реального кода. Ты не можешь запускать код и не "
    "даёшь гарантий работоспособности — это лишь оценка правдоподобия по "
    "описанию. Ответь СТРОГО в формате JSON, без пояснений вне JSON: "
    '{"verdict": "likely_working" | "questionable" | "likely_broken", '
    '"reasoning": "краткое объяснение на русском, 1-2 предложения"}'
)


def analyze_exploit_text(
    title: str, raw_content: str, retries: int = 2, backoff_seconds: int = 5
) -> Optional[dict]:
    """
    Отправляет текст записи об эксплойте в LLM (через OpenRouter) для оценки
    правдоподобия. Возвращает {"verdict": ..., "reasoning": ...} или None
    при любой ошибке (нет ключа, лимит запросов у бесплатного провайдера,
    невалидный ответ) — отказ ИИ никогда не должен ронять основной ответ API.
    """
    if not OPENROUTER_API_KEY:
        return None

    user_text = f"Название: {title or '(нет)'}\n\nСодержимое:\n{(raw_content or '')[:4000]}"

    import time

    for attempt in range(1, retries + 1):
        try:
            response = requests.post(
                OPENROUTER_URL,
                headers={
                    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": MODEL_NAME,
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": user_text},
                    ],
                    "temperature": 0.2,
                },
                timeout=30,
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]

            # Бесплатные модели иногда оборачивают JSON в ```json ... ``` —
            # снимаем обёртку перед разбором, если она есть.
            cleaned = content.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.strip("`")
                if cleaned.startswith("json"):
                    cleaned = cleaned[4:]
                cleaned = cleaned.strip()

            parsed = json.loads(cleaned)
            verdict = parsed.get("verdict")
            if verdict not in ("likely_working", "questionable", "likely_broken"):
                return None

            return {"verdict": verdict, "reasoning": str(parsed.get("reasoning", ""))[:2000]}

        except requests.exceptions.HTTPError as e:
            # 429 у бесплатных моделей — временная перегрузка провайдера,
            # имеет смысл повторить попытку с паузой.
            if e.response is not None and e.response.status_code == 429 and attempt < retries:
                time.sleep(backoff_seconds)
                continue
            return None
        except Exception:
            return None

    return None