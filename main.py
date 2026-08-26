from urllib.parse import urlparse
import re
import socket


SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "password",
    "confirm",
    "confirmation",
    "bank",
    "paypal",
    "wallet",
    "payment",
    "billing",
    "unlock",
    "suspended",
    "recover"
]


def normalize_url(url):
    """
    Очищает URL от случайного Markdown и добавляет http://,
    если пользователь не указал протокол.
    """

    url = url.strip()

    # Если пользователь вставил Markdown-ссылку:
    # [https://example.com](https://example.com)
    markdown_match = re.search(
        r"\((https?://[^)\s]+)\)",
        url
    )

    if markdown_match:
        url = markdown_match.group(1)

    # Если внутри текста есть обычный URL
    url_match = re.search(
        r"https?://[^\s\]\)<>]+",
        url
    )

    if url_match:
        url = url_match.group(0)

    # Убираем лишние символы
    url = url.strip("\"'<>[]()")

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    return url


def check_dns(domain):
    """
    Проверяет существование домена через DNS.
    """

    try:
        ip = socket.gethostbyname(domain)
        return True, ip

    except socket.gaierror:
        return False, ""


def analyze_url(url):
    """
    Основной анализ URL.
    """

    url = normalize_url(url)

    parsed = urlparse(url)

    domain = parsed.hostname or ""

    domain = domain.lower()

    risks = []

    score = 0


    # --------------------------------------------------
    # 1. HTTPS
    # --------------------------------------------------

    if parsed.scheme != "https":

        risks.append("Нет HTTPS")

        score += 2


    # --------------------------------------------------
    # 2. Длина URL
    # --------------------------------------------------

    if len(url) > 100:

        risks.append("Слишком длинный URL")

        score += 1


    # --------------------------------------------------
    # 3. IP вместо домена
    # --------------------------------------------------

    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if re.match(ip_pattern, domain):

        risks.append(
            "Используется IP-адрес вместо доменного имени"
        )

        score += 3


    # --------------------------------------------------
    # 4. Слишком много поддоменов
    # --------------------------------------------------

    domain_parts = domain.split(".")

    if len(domain_parts) >= 4:

        risks.append(
            "Слишком много поддоменов"
        )

        score += 2


    # --------------------------------------------------
    # 5. Символ @
    # --------------------------------------------------

    if "@" in url:

        risks.append(
            "URL содержит символ @"
        )

        score += 3


    # --------------------------------------------------
    # 6. Кодирование %
    # --------------------------------------------------

    if "%" in url:

        risks.append(
            "URL содержит закодированные символы (%)"
        )

        score += 1


    # --------------------------------------------------
    # 7. Подозрительные слова
    # --------------------------------------------------

    found_words = []

    lower_url = url.lower()

    for word in SUSPICIOUS_WORDS:

        if word in lower_url:

            found_words.append(word)


    if found_words:

        unique_words = list(dict.fromkeys(found_words))

        risks.append(
            "Подозрительные слова: "
            + ", ".join(unique_words)
        )

        score += min(len(unique_words), 4)


    # --------------------------------------------------
    # 8. Дефис в домене
    # --------------------------------------------------

    if "-" in domain:

        risks.append(
            "Домен содержит дефис"
        )

        score += 1


    # --------------------------------------------------
    # 9. Большое количество цифр
    # --------------------------------------------------

    digit_count = sum(
        character.isdigit()
        for character in domain
    )

    if digit_count >= 4:

        risks.append(
            "Много цифр в доменном имени"
        )

        score += 2


    # --------------------------------------------------
    # 10. Слишком длинный домен
    # --------------------------------------------------

    if len(domain) > 30:

        risks.append(
            "Слишком длинное доменное имя"
        )

        score += 2


    # --------------------------------------------------
    # 11. Подозрительный порт
    # --------------------------------------------------

    try:

        port = parsed.port

        if port is not None and port not in [80, 443]:

            risks.append(
                f"Используется нестандартный порт: {port}"
            )

            score += 2

    except ValueError:

        risks.append(
            "Некорректно указан порт"
        )

        score += 3


    # --------------------------------------------------
    # 12. DNS
    # --------------------------------------------------

    if domain:

        dns_exists, ip_address = check_dns(domain)

    else:

        dns_exists = False
        ip_address = ""


    if not dns_exists:

        risks.append(
            "Домен не найден в DNS"
        )

        score += 3


    # --------------------------------------------------
    # Уровень риска
    # --------------------------------------------------

    if score <= 2:

        risk_level = "НИЗКИЙ РИСК"

        risk_color = "safe"


    elif score <= 5:

        risk_level = "СРЕДНИЙ РИСК"

        risk_color = "warning"


    else:

        risk_level = "ВЫСОКИЙ РИСК"

        risk_color = "danger"


    # --------------------------------------------------
    # Результат
    # --------------------------------------------------

    return {

        "url": url,

        "domain": domain,

        "ip": ip_address,

        "dns": dns_exists,

        "score": score,

        "risk": risk_level,

        "risk_color": risk_color,

        "risks": risks
    }


def main():

    print("=" * 60)

    print(
        "           АНАЛИЗАТОР ФИШИНГОВЫХ URL"
    )

    print("=" * 60)


    while True:

        url = input(
            "\nВведите URL "
            "(или exit для выхода): "
        ).strip()


        if url.lower() == "exit":

            print(
                "\nПрограмма завершена."
            )

            break


        if not url:

            print(
                "[ОШИБКА] URL не введён."
            )

            continue


        try:

            result = analyze_url(url)


            print("\n" + "-" * 60)

            print(
                "РЕЗУЛЬТАТ АНАЛИЗА"
            )

            print("-" * 60)


            print(
                f"URL: {result['url']}"
            )

            print(
                f"Домен: {result['domain']}"
            )


            if result["dns"]:

                print(
                    f"IP-адрес: {result['ip']}"
                )

                print(
                    "DNS: найден"
                )

            else:

                print(
                    "DNS: домен не найден"
                )


            print(
                f"Баллы риска: {result['score']}"
            )

            print(
                f"Уровень риска: {result['risk']}"
            )


            if result["risks"]:

                print(
                    "\nОбнаруженные признаки:"
                )


                for risk in result["risks"]:

                    print(
                        f"  [!] {risk}"
                    )


            else:

                print(
                    "\n[+] Подозрительных признаков "
                    "не обнаружено."
                )


            print("-" * 60)


        except Exception as error:

            print(
                f"\n[ОШИБКА] "
                f"Не удалось проанализировать URL: "
                f"{error}"
            )


if __name__ == "__main__":

    main()
