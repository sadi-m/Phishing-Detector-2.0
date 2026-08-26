import os
import re
import secrets
from datetime import timedelta
from pathlib import Path

from flask import Flask, render_template, request, redirect, session, abort, url_for
from ai_assistant import get_ai_analysis
from database import delete_review, delete_user, get_user_profile, get_user_scan_count, make_admin
from flask import send_file
from openpyxl import Workbook
from io import BytesIO
from database import connect



from database import (
    init_database,
    create_admin,
    create_user,
    get_user,
    update_last_login,
    save_scan,
    get_users,
    get_scans,
    save_review,
    get_reviews,
    get_average_rating,
    save_logout,
    create_scans_table,
    delete_user,
    make_admin,
    delete_review
)

from werkzeug.security import check_password_hash
from security import RateLimiter, install_csrf


# =========================================================
# АНАЛИЗАТОР
# =========================================================

try:
    from analyzer import analyze_url

except ImportError:

    from urllib.parse import urlparse

    def analyze_url(url):
        url = url.strip()

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        score = 0
        risk = "Низкий риск"

        risks = []

        suspicious_words = [
            "login",
            "verify",
            "account",
            "password",
            "secure",
            "update",
            "confirm"
        ]

        for word in suspicious_words:
            if word in url.lower():
                score += 10
                risks.append(
                    f"Подозрительное слово в URL: {word}"
                )

        if not domain:
            score = 100
            risk = "Опасный"
            risks.append("Некорректный URL")

        elif score >= 50:
            risk = "Высокий риск"

        elif score >= 20:
            risk = "Средний риск"

        return {
            "url": url,
            "domain": domain,
            "score": score,
            "risk_level": risk,
            "risks": risks
        }


# =========================================================
# ПРИЛОЖЕНИЕ
# =========================================================

app = Flask(__name__)


def load_secret_key():
    """Use deployment configuration when supplied, otherwise create a local key once.

    The fallback keeps direct desktop launches usable without ever falling back
    to a predictable hard-coded key. The file is excluded from version control.
    """
    configured = os.environ.get("FLASK_SECRET_KEY")
    if configured:
        if len(configured) < 32:
            raise RuntimeError("FLASK_SECRET_KEY must contain at least 32 characters.")
        return configured

    instance_dir = Path(app.instance_path)
    instance_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    key_file = instance_dir / "secret_key"
    try:
        existing = key_file.read_text(encoding="utf-8").strip()
        if len(existing) >= 32:
            return existing
    except FileNotFoundError:
        pass

    key = secrets.token_urlsafe(48)
    # O_EXCL prevents a second process from accidentally overwriting the key.
    try:
        descriptor = os.open(str(key_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as secret_file:
            secret_file.write(key)
        return key
    except FileExistsError:
        existing = key_file.read_text(encoding="utf-8").strip()
        if len(existing) >= 32:
            return existing
        raise RuntimeError("Invalid local session-key file; replace it with a random key.")


secret_key = load_secret_key()

app.config.update(
    SECRET_KEY=secret_key,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=32 * 1024,
)
limiter = RateLimiter()
install_csrf(app)


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    )
    if app.config["SESSION_COOKIE_SECURE"]:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def require_admin():
    if session.get("role") != "admin":
        abort(403)


def valid_username(username):
    return bool(re.fullmatch(r"[A-Za-zА-Яа-яЁё0-9_.-]{3,32}", username))


def safe_spreadsheet_value(value):
    """Prevent formulas in admin-exported XLSX files from being executed by Excel."""
    if isinstance(value, str) and value[:1] in {"=", "+", "-", "@"}:
        return "'" + value
    return value


# =========================================================
# БАЗА ДАННЫХ
# =========================================================

init_database()
create_admin()
create_scans_table() # type: ignore

# =========================================================
# ОПРЕДЕЛЕНИЕ УСТРОЙСТВА
# =========================================================

def detect_device(user_agent):

    ua = user_agent.lower()

    if "iphone" in ua:
        return "iPhone"

    if "ipad" in ua:
        return "iPad"

    if "android" in ua:
        return "Android"

    if "windows phone" in ua:
        return "Windows Phone"

    if "windows" in ua:
        return "Компьютер Windows"

    if "macintosh" in ua:
        return "Mac"

    if "linux" in ua:
        return "Linux"

    return "Неизвестное устройство"


# =========================================================
# ОПРЕДЕЛЕНИЕ ОС
# =========================================================

def detect_os(user_agent):

    ua = user_agent.lower()

    if "windows nt 10" in ua:
        return "Windows 10/11"

    if "windows nt 6.3" in ua:
        return "Windows 8.1"

    if "windows nt 6.1" in ua:
        return "Windows 7"

    if "iphone" in ua or "ipad" in ua:
        return "iOS"

    if "android" in ua:
        return "Android"

    if "mac os x" in ua:
        return "macOS"

    if "linux" in ua:
        return "Linux"

    return "Неизвестная ОС"


# =========================================================
# ОПРЕДЕЛЕНИЕ БРАУЗЕРА
# =========================================================

def detect_browser(user_agent):

    ua = user_agent.lower()

    if "edg/" in ua:
        return "Microsoft Edge"

    if "yabrowser" in ua:
        return "Yandex Browser"

    if "opr/" in ua or "opera" in ua:
        return "Opera"

    if "chrome/" in ua and "edg/" not in ua:
        return "Google Chrome"

    if "firefox/" in ua:
        return "Mozilla Firefox"

    if "safari/" in ua and "chrome/" not in ua:
        return "Safari"

    return "Неизвестный браузер"

@app.route("/admin/export/scans")
def export_scans():
    require_admin()

    db = connect()

    scans = db.execute("""
        SELECT
            scans.id,
            users.username,
            scans.url,
            scans.domain,
            scans.score,
            scans.risk,
            scans.created_at
        FROM scans
        LEFT JOIN users
            ON users.id = scans.user_id
        ORDER BY scans.id DESC
    """).fetchall()

    db.close()

    wb = Workbook()
    ws = wb.active
    ws.title = "Проверки URL"

    ws.append([
        "ID",
        "Пользователь",
        "URL",
        "Домен",
        "Баллы",
        "Риск",
        "Дата проверки"
    ])

    for scan in scans:
        ws.append([
            scan["id"],
            safe_spreadsheet_value(scan["username"]),
            safe_spreadsheet_value(scan["url"]),
            safe_spreadsheet_value(scan["domain"]),
            scan["score"],
            safe_spreadsheet_value(scan["risk"]),
            safe_spreadsheet_value(scan["created_at"])
        ])

    for column in ws.columns:
        max_length = 0
        column_letter = column[0].column_letter

        for cell in column:
            if cell.value is not None:
                max_length = max(
                    max_length,
                    len(str(cell.value))
                )

        ws.column_dimensions[column_letter].width = min(
            max_length + 2,
            60
        )

    file = BytesIO()
    wb.save(file)
    file.seek(0)

    return send_file(
        file,
        as_attachment=True,
        download_name="scans.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

# =========================================================
# ГЛАВНАЯ
# =========================================================

@app.route("/", methods=["GET", "POST"])
@limiter.limit(30, 60)
def index():

    if "user_id" not in session:
        return redirect("/login")

    result = None

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if url and len(url) <= 2048:

            # -----------------------------------------
            # ОСНОВНОЙ АНАЛИЗ URL
            # -----------------------------------------



            result = analyze_url(url)
            try:

                result["ai_text"] = get_ai_analysis(
                    result["url"],
                    result["score"],
                    result.get("risk_level", result.get("risk", "Неизвестно")),
                    result.get("risks", [])
                )

            except Exception as e:

                print("AI ERROR:", repr(e))

                result["ai_text"] = (
                    "ИИ-анализ временно недоступен."
                )





            # -----------------------------------------
            # СОХРАНЕНИЕ СКАНИРОВАНИЯ
            # -----------------------------------------

            save_scan(
                session["user_id"],
                result["url"],
                result["domain"],
                result["score"],
                result.get("risk_level", result.get("risk", "Неизвестно"))
            )

    return render_template(
        "index.html",
        username=session["username"],
        role=session["role"],
        result=result,
        reviews=get_reviews(),
        average_rating=get_average_rating()
    )


# =========================================================
# РЕГИСТРАЦИЯ
# =========================================================

@app.route("/register", methods=["GET", "POST"])
@limiter.limit(10, 3600)
def register():

    error = None

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not password:

            error = "Введите имя пользователя и пароль"

            return render_template(
                "register.html",
                error=error
            )

        if not valid_username(username):
            return render_template("register.html", error="Имя: 3–32 символа (буквы, цифры, _, ., -)")

        if len(password) < 12 or len(password) > 128:
            return render_template("register.html", error="Пароль должен содержать от 12 до 128 символов")

        user_agent = request.headers.get(
            "User-Agent",
            ""
        )

        language = request.headers.get(
            "Accept-Language",
            ""
        )

        ip = request.remote_addr

        device = detect_device(user_agent)
        operating_system = detect_os(user_agent)
        browser = detect_browser(user_agent)

        try:

            result = create_user(
                username=username,
                password=password,
                ip=ip,
                device=device,
                os=operating_system,
                browser=browser,
                language=language,
                user_agent=user_agent
            )

            if result:
                return redirect(url_for("login"))

            error = "Такой пользователь уже существует"

        except Exception as e:

            app.logger.exception("Registration failed")
            error = "Не удалось создать аккаунт. Попробуйте позже."

    return render_template(
        "register.html",
        error=error
    )


# =========================================================
# ВХОД
# =========================================================

@app.route("/login", methods=["GET", "POST"])
@limiter.limit(10, 300)
def login():

    error = None

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        user = get_user(username)

        if user:

            try:

                password_correct = check_password_hash(
                    user["password_hash"],
                    password
                )

            except Exception:

                password_correct = False

        else:

            password_correct = False

        if password_correct:
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            update_last_login(
                user["id"]
            )

            return redirect(url_for("index"))

        error = "Неверный логин или пароль"

    return render_template(
        "login.html",
        error=error
    )

@app.route("/admin/delete_user/<int:id>", methods=["POST"])
def admin_delete_user(id):
    require_admin()
    if id == session.get("user_id"):
        abort(400, "Нельзя удалить собственную учётную запись")

    delete_user(id)

    return redirect("/admin")

@app.route("/admin/make_admin/<int:id>", methods=["POST"])
def admin_make_admin(id):
    require_admin()

    make_admin(id)

    return redirect("/admin")

@app.route("/admin/delete_review/<int:id>", methods=["POST"])
def admin_delete_review(id):
    require_admin()

    delete_review(id)

    return redirect("/admin")


# =========================================================
# АДМИН ПАНЕЛЬ
# =========================================================

@app.route("/admin")
def admin():

    if "user_id" not in session:
        return redirect("/login")

    require_admin()

    users = get_users()
    scans = get_scans()

    return render_template(
        "admin.html",
        users=users,
        scans=scans,
        username=session.get("username")
    )
@app.route("/admin/export/users")
def export_users():
    require_admin()

    db = connect()

    users = db.execute("""
        SELECT
            users.id,
            users.username,
            users.role,
            users.created_at,
            user_devices.ip_address,
            user_devices.device,
            user_devices.operating_system,
            user_devices.browser,
            user_devices.language
        FROM users
        LEFT JOIN user_devices
            ON users.id = user_devices.user_id
        ORDER BY users.id DESC
    """).fetchall()

    db.close()

    wb = Workbook()
    ws = wb.active
    ws.title = "Пользователи"

    ws.append([
        "ID",
        "Имя пользователя",
        "Роль",
        "Дата регистрации",
        "IP",
        "Устройство",
        "ОС",
        "Браузер",
        "Язык"
    ])

    for user in users:
        ws.append([
            user["id"],
            safe_spreadsheet_value(user["username"]),
            safe_spreadsheet_value(user["role"]),
            safe_spreadsheet_value(user["created_at"]),
            safe_spreadsheet_value(user["ip_address"]),
            safe_spreadsheet_value(user["device"]),
            safe_spreadsheet_value(user["operating_system"]),
            safe_spreadsheet_value(user["browser"]),
            safe_spreadsheet_value(user["language"])
        ])

    # Автоматическая ширина колонок
    for column in ws.columns:
        max_length = 0
        column_letter = column[0].column_letter

        for cell in column:
            if cell.value is not None:
                max_length = max(
                    max_length,
                    len(str(cell.value))
                )

        ws.column_dimensions[column_letter].width = min(
            max_length + 2,
            40
        )

    file = BytesIO()
    wb.save(file)
    file.seek(0)

    return send_file(
        file,
        as_attachment=True,
        download_name="users.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

# =========================================================
# ВЫХОД
# =========================================================
@app.route("/profile")
def profile():

    if "user_id" not in session:
        return redirect("/login")

    user = get_user_profile(session["username"])

    scans_count = get_user_scan_count(
        session["user_id"]
    )

    return render_template(
        "profile.html",
        user=user,
        scans_count=scans_count
    )

@app.route("/logout", methods=["POST"])
def logout():

    user_id = session.get("user_id")

    if user_id:
        save_logout(user_id)

    session.clear()

    return redirect("/login")


# =========================================================
# ОТЗЫВЫ
# =========================================================

@app.route("/review", methods=["POST"])
def review():

    if "user_id" not in session:
        return redirect("/login")

    rating = request.form.get("rating")
    text = request.form.get("text")

    if rating and text:
        try:
            rating = int(rating)
        except (TypeError, ValueError):
            abort(400)
        text = text.strip()
        if not 1 <= rating <= 5 or not text or len(text) > 1000:
            abort(400)

        save_review(
            session["user_id"],
            session["username"],
            rating,
            text
        )

    return redirect("/")


# =========================================================
# ЗАПУСК
# =========================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print("\nPhishing Detector запущен.")
    print(f"Откройте в браузере: http://127.0.0.1:{port}\n")
    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )

    
