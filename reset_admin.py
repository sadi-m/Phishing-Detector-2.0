"""Local-only administrator password reset utility."""

from getpass import getpass
import re

from database import connect
from werkzeug.security import generate_password_hash


def main():
    username = input("Имя администратора [Sadi]: ").strip() or "Sadi"
    if not re.fullmatch(r"[A-Za-zА-Яа-яЁё0-9_.-]{3,32}", username):
        raise SystemExit("Некорректное имя пользователя.")

    password = getpass("Новый пароль (минимум 12 символов): ")
    repeated = getpass("Повторите новый пароль: ")
    if password != repeated:
        raise SystemExit("Пароли не совпадают.")
    if not 12 <= len(password) <= 128:
        raise SystemExit("Пароль должен быть длиной от 12 до 128 символов.")

    db = connect()
    try:
        user = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if user:
            db.execute(
                "UPDATE users SET password_hash=?, role='admin' WHERE id=?",
                (generate_password_hash(password), user["id"]),
            )
        else:
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
                (username, generate_password_hash(password)),
            )
        db.commit()
    finally:
        db.close()
    print("Пароль обновлён, права администратора назначены.")


if __name__ == "__main__":
    main()
