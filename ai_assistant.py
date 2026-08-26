import os

import ollama


def fallback_analysis(score, risk, risks):
    """Useful local result when the optional Ollama service is unavailable."""
    signs = ", ".join(risks[:2]) if risks else "явных признаков не найдено"
    conclusion = "Опасен" if score >= 70 else "Подозрителен" if score >= 30 else "Безопасен"
    recommendation = (
        "Не переходите по ссылке и не вводите данные." if score >= 30
        else "Перед вводом данных убедитесь, что домен официальный."
    )
    return (
        f"Причина: автоматическая оценка риска — {risk}.\n"
        f"Признаки: {signs}.\n"
        f"Рекомендация: {recommendation}\n"
        f"Вывод: {conclusion}"
    )


def get_ai_analysis(url, score, risk, risks):
    prompt = f"""
Ты — помощник системы обнаружения фишинга.

Проанализируй URL:
{url}

Баллы риска: {score}
Уровень риска: {risk}
Обнаруженные признаки: {risks}

Дай ОЧЕНЬ КРАТКИЙ ответ на русском языке.

Формат строго такой:

Причина: [1 короткое предложение]
Признаки: [1 короткое предложение]
Рекомендация: [1 короткое предложение]
Вывод: [Безопасен / Подозрителен / Опасен]

Не используй приветствия.
Не повторяй URL.
Не пиши длинные объяснения.
Не используй нумерованные списки.
Максимум 4 предложения.
"""

    # дальше твой код обращения к AI

    try:
        response = ollama.chat(
            model=os.environ.get("OLLAMA_MODEL", "deepseek-r1"),
            messages=[{"role": "user", "content": prompt}],
        )
        return response["message"]["content"]
    except Exception:
        return fallback_analysis(score, risk, risks)
