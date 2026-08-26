from urllib.parse import urlparse
import ipaddress
import socket
import whois
from datetime import datetime, timezone


# =========================================================
# ОПАСНЫЕ РАСШИРЕНИЯ ФАЙЛОВ
# =========================================================

DANGEROUS_EXTENSIONS = [
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".scr",
    ".com",
    ".pif",

    ".apk",

    ".dll",
    ".jar",

    ".zip",
    ".rar",
    ".7z",

    ".docm",
    ".xlsm",
    ".pptm",
]


# =========================================================
# ПОПУЛЯРНЫЕ ДОМЕНЫ
# =========================================================

POPULAR_DOMAINS = [
    "google.com",
    "paypal.com",
    "facebook.com",
    "instagram.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "telegram.org",
    "github.com",
    "youtube.com",
    "tiktok.com",
    "linkedin.com",
    "discord.com",
]


# =========================================================
# ПОДОЗРИТЕЛЬНЫЕ ДОМЕННЫЕ ЗОНЫ
# =========================================================

SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".click",
    ".online",
    ".site",
    ".shop",
    ".live",
    ".buzz",
]


# =========================================================
# ПОДОЗРИТЕЛЬНЫЕ СЛОВА
# =========================================================

SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "password",
    "confirm",
    "update",
    "wallet",
    "bank",
    "payment",
    "security",
    "recover",
    "unlock",
]


# =========================================================
# СОКРАЩЁННЫЕ ССЫЛКИ
# =========================================================

SHORT_LINKS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "cutt.ly",
    "shorturl.at",
]


def is_public_host(domain):
    """Allow network enrichment only for public Internet hosts.

    This prevents SSRF-style use of the analyzer against localhost, private
    networks and cloud metadata endpoints. Every resolved address must be
    globally routable, which also makes DNS rebinding fail closed.
    """
    if domain.lower().rstrip(".") in {"localhost", "localhost.localdomain"}:
        return False
    try:
        addresses = {
            item[4][0] for item in socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        }
        if not addresses:
            return False
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global:
                return False
        return True
    except (socket.gaierror, ValueError, UnicodeError):
        return False


# =========================================================
# ПРОВЕРКА ОПАСНЫХ ФАЙЛОВ
# =========================================================

def check_file_link(url):

    warnings = []
    score = 0

    url_lower = url.lower()

    # -----------------------------------------------------
    # Опасные расширения
    # -----------------------------------------------------

    for ext in DANGEROUS_EXTENSIONS:

        if ext in url_lower:

            score += 40

            warnings.append(
                f"Обнаружена ссылка на потенциально опасный файл: {ext}"
            )

    # -----------------------------------------------------
    # Двойные расширения
    # -----------------------------------------------------

    dangerous_patterns = [
        ".jpg.exe",
        ".jpeg.exe",
        ".png.exe",
        ".gif.exe",
        ".pdf.exe",
        ".doc.exe",
        ".txt.exe",

        ".jpg.scr",
        ".jpeg.scr",
        ".png.scr",
        ".pdf.scr",

        ".pdf.bat",
        ".pdf.cmd",

        ".jpg.zip",
        ".pdf.zip",
    ]

    for pattern in dangerous_patterns:

        if pattern in url_lower:

            score += 60

            warnings.append(
                "Обнаружена возможная маскировка опасного файла "
                f"({pattern})"
            )

    return score, warnings


# =========================================================
# ПРОВЕРКА СОКРАЩЁННЫХ ССЫЛОК
# =========================================================

def check_short_link(domain):

    warnings = []
    score = 0

    clean_domain = domain.lower()

    if clean_domain.startswith("www."):
        clean_domain = clean_domain[4:]

    if clean_domain in SHORT_LINKS:

        score += 30

        warnings.append(
            "Используется сокращённая ссылка: "
            "конечный адрес скрыт"
        )

    return score, warnings


# =========================================================
# LEVENSHTEIN
# =========================================================

def levenshtein(a, b):

    matrix = []

    for i in range(len(a) + 1):
        matrix.append(
            [0] * (len(b) + 1)
        )

    for i in range(len(a) + 1):
        matrix[i][0] = i

    for j in range(len(b) + 1):
        matrix[0][j] = j

    for i in range(1, len(a) + 1):

        for j in range(1, len(b) + 1):

            cost = 0

            if a[i - 1] != b[j - 1]:
                cost = 1

            matrix[i][j] = min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost
            )

    return matrix[-1][-1]


# =========================================================
# ПРОВЕРКА ПОХОЖЕГО ДОМЕНА
# =========================================================

def check_similar_domain(domain):

    warnings = []
    score = 0

    clean_domain = domain.lower()

    if clean_domain.startswith("www."):
        clean_domain = clean_domain[4:]

    for good_domain in POPULAR_DOMAINS:

        # Настоящий официальный домен не проверяем
        if clean_domain == good_domain:
            continue

        # Если официальный домен является частью домена,
        # не создаём лишнее срабатывание
        if good_domain in clean_domain:
            continue

        distance = levenshtein(
            clean_domain,
            good_domain
        )

        max_length = max(
            len(clean_domain),
            len(good_domain)
        )

        if max_length == 0:
            continue

        similarity = 1 - (
            distance / max_length
        )

        if similarity >= 0.75:

            score += 25

            warnings.append(
                f"Домен похож на официальный сайт: {good_domain}"
            )

    return score, warnings


# =========================================================
# ПРОВЕРКА ВОЗРАСТА ДОМЕНА
# =========================================================

def check_domain_age(domain):

    warnings = []
    score = 0
    registration_date = None

    try:

        clean_domain = domain.lower()

        if clean_domain.startswith("www."):
            clean_domain = clean_domain[4:]

        data = whois.whois(clean_domain)

        creation = data.creation_date

        # Иногда WHOIS возвращает несколько дат
        if isinstance(creation, list):

            creation = next(
                (
                    date
                    for date in creation
                    if isinstance(date, datetime)
                ),
                None
            )

        if creation:

            # Сохраняем дату для отображения
            registration_date = creation.strftime(
                "%Y-%m-%d"
            )

            now = datetime.now(timezone.utc)

            # Если дата без timezone
            if creation.tzinfo is None:

                creation = creation.replace(
                    tzinfo=timezone.utc
                )

            age_days = (
                now - creation
            ).days

            # Некорректная дата
            if age_days < 0:

                return (
                    0,
                    [],
                    registration_date
                )

            # -------------------------------------------------
            # Домен младше 7 дней
            # -------------------------------------------------

            if age_days < 7:

                score += 40

                warnings.append(
                    f"Домен зарегистрирован недавно: "
                    f"{age_days} дн."
                )

            # -------------------------------------------------
            # Домен младше месяца
            # -------------------------------------------------

            elif age_days < 30:

                score += 25

                warnings.append(
                    f"Домену меньше месяца: "
                    f"{age_days} дн."
                )

            # -------------------------------------------------
            # Домен младше 180 дней
            # -------------------------------------------------

            elif age_days < 180:

                score += 10

                warnings.append(
                    f"Молодой домен: "
                    f"{age_days} дн."
                )

    except Exception:
        # WHOIS не должен ломать приложение
        pass

    return (
        score,
        warnings,
        registration_date
    )


# =========================================================
# ПРОВЕРКА IP-АДРЕСА
# =========================================================

def check_ip_address(domain):

    warnings = []
    score = 0

    try:

        ipaddress.ip_address(domain)

        score += 30

        warnings.append(
            "Вместо доменного имени используется IP-адрес"
        )

    except ValueError:

        pass

    return score, warnings


# =========================================================
# ОСНОВНОЙ АНАЛИЗ URL
# =========================================================

def analyze_url(url):

    warnings = []
    score = 0

    # =====================================================
    # НОРМАЛИЗАЦИЯ
    # =====================================================

    url = url.strip()

    if not url:

        return {
            "url": "",
            "domain": "",
            "score": 100,
            "risk_level": "Высокий риск",
            "risk": "Высокий риск",
            "risks": [
                "Пустая ссылка"
            ],
            "registration_date": None
        }

    # Если протокол не указан
    if "://" not in url:

        url = "https://" + url

    # =====================================================
    # PARSE URL
    # =====================================================

    try:

        parsed = urlparse(url)

    except Exception:

        return {
            "url": url,
            "domain": "",
            "score": 100,
            "risk_level": "Высокий риск",
            "risk": "Высокий риск",
            "risks": [
                "Некорректный URL"
            ],
            "registration_date": None
        }

    if parsed.scheme.lower() not in {"http", "https"}:
        return {
            "url": url,
            "domain": "",
            "score": 100,
            "risk_level": "Высокий риск",
            "risk": "Высокий риск",
            "risks": ["Поддерживаются только ссылки HTTP и HTTPS"],
            "registration_date": None,
        }

    # =====================================================
    # ДОМЕН
    # =====================================================

    domain = parsed.hostname

    if not domain:

        return {
            "url": url,
            "domain": "",
            "score": 100,
            "risk_level": "Высокий риск",
            "risk": "Высокий риск",
            "risks": [
                "Не удалось определить домен"
            ],
            "registration_date": None
        }

    domain = domain.lower()

    # The analyzer performs DNS and WHOIS enrichment later. Never allow those
    # server-side requests to be directed at private or local infrastructure.
    public_host = is_public_host(domain)
    if not public_host:
        score += 50
        warnings.append(
            "Адрес относится к локальной, частной или недоступной сети; "
            "серверная проверка заблокирована"
        )

    # =====================================================
    # HTTPS
    # =====================================================

    if parsed.scheme != "https":

        score += 10

        warnings.append(
            "Соединение не использует HTTPS"
        )

    # =====================================================
    # @ В URL
    # =====================================================

    if "@" in url:

        score += 25

        warnings.append(
            "URL содержит символ @, который может "
            "скрывать настоящий домен"
        )

    # =====================================================
    # PUNYCODE
    # =====================================================

    if "xn--" in domain:

        score += 30

        warnings.append(
            "Обнаружен Punycode: возможна подмена "
            "символов в домене"
        )

    # =====================================================
    # IP
    # =====================================================

    ip_score, ip_warnings = check_ip_address(
        domain
    )

    score += ip_score

    warnings.extend(
        ip_warnings
    )

    # =====================================================
    # СОКРАЩЁННАЯ ССЫЛКА
    # =====================================================

    short_score, short_warnings = check_short_link(
        domain
    )

    score += short_score

    warnings.extend(
        short_warnings
    )

    # =====================================================
    # ПОДОЗРИТЕЛЬНЫЕ TLD
    # =====================================================

    for tld in SUSPICIOUS_TLDS:

        if domain.endswith(tld):

            score += 20

            warnings.append(
                f"Используется потенциально рискованная "
                f"доменная зона {tld}"
            )

            break

    # =====================================================
    # ПОДОЗРИТЕЛЬНЫЕ СЛОВА
    # =====================================================

    url_lower = url.lower()

    found_words = set()

    for word in SUSPICIOUS_WORDS:

        if word in url_lower:

            found_words.add(word)

    for word in sorted(found_words):

        score += 10

        warnings.append(
            f"Обнаружено подозрительное слово: {word}"
        )

    # =====================================================
    # ОПАСНЫЕ ФАЙЛЫ
    # =====================================================

    file_score, file_warnings = check_file_link(
        url
    )

    score += file_score

    warnings.extend(
        file_warnings
    )

    # =====================================================
    # ДЛИНА URL
    # =====================================================

    if len(url) > 100:

        score += 15

        warnings.append(
            "URL имеет необычно большую длину"
        )

    if len(url) > 200:

        score += 10

        warnings.append(
            "URL имеет критически большую длину"
        )

    # =====================================================
    # КОЛИЧЕСТВО ПОДДОМЕНОВ
    # =====================================================

    domain_parts = domain.split(".")

    if len(domain_parts) >= 4:

        score += 20

        warnings.append(
            "Обнаружено большое количество "
            "уровней домена"
        )

    # =====================================================
    # ДЕФИСЫ
    # =====================================================

    if domain.count("-") >= 3:

        score += 15

        warnings.append(
            "Домен содержит необычно большое "
            "количество дефисов"
        )

    # =====================================================
    # ЦИФРЫ
    # =====================================================

    digit_count = sum(
        char.isdigit()
        for char in domain
    )

    if digit_count >= 4:

        score += 15

        warnings.append(
            "Домен содержит необычно много цифр"
        )

    # =====================================================
    # ПОХОЖЕСТЬ НА ИЗВЕСТНЫЙ ДОМЕН
    # =====================================================

    similar_score, similar_warnings = (
        check_similar_domain(domain)
    )

    score += similar_score

    warnings.extend(
        similar_warnings
    )

    # =====================================================
    # ВОЗРАСТ ДОМЕНА
    # =====================================================

    if public_host:
        age_score, age_warnings, registration_date = check_domain_age(domain)
    else:
        age_score, age_warnings, registration_date = 0, [], None

    score += age_score

    warnings.extend(
        age_warnings
    )

    # =====================================================
    # ОГРАНИЧЕНИЕ SCORE
    # =====================================================

    if score > 100:

        score = 100

    if score < 0:

        score = 0

    # =====================================================
    # УРОВЕНЬ РИСКА
    # =====================================================

    if score >= 70:

        risk = "Высокий риск"

    elif score >= 30:

        risk = "Средний риск"

    else:

        risk = "Низкий риск"

    # =====================================================
    # ЕСЛИ НИЧЕГО НЕ НАЙДЕНО
    # =====================================================

    if not warnings:

        warnings.append(
            "Подозрительных признаков не обнаружено"
        )

    # =====================================================
    # РЕЗУЛЬТАТ
    # =====================================================

    return {

        "url": url,

        "domain": domain,

        "score": score,

        "risk_level": risk,

        "risk": risk,

        "risks": warnings,

        "registration_date": registration_date
    }
