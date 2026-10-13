"""
Database abstraction layer for DetectLab Phishing Triage.
Supports local MySQL with automatic fallback to SQLite if MySQL is unreachable.
Manages users (bcrypt/pbkdf2 hashed passwords) and analysis history logs.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("detectlab.db")


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Hashes password with PBKDF2-HMAC-SHA256 and salt."""
    if not salt:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100000
    ).hex()
    return pwd_hash, salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verifies password using constant-time comparison."""
    test_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(test_hash, stored_hash)


class Database:
    def __init__(self):
        self.engine_type = "sqlite"
        self.mysql_config = {
            "host": os.getenv("DB_HOST", "127.0.0.1"),
            "port": int(os.getenv("DB_PORT", "3306")),
            "user": os.getenv("DB_USER", "root"),
            "password": os.getenv("DB_PASSWORD", ""),
            "database": os.getenv("DB_NAME", "detectlab_phishing"),
        }
        self.sqlite_path = Path("detectlab.sqlite3")
        self._init_db()

    def _get_mysql_connection(self):
        import pymysql
        # Try connecting with database
        try:
            return pymysql.connect(
                host=self.mysql_config["host"],
                port=self.mysql_config["port"],
                user=self.mysql_config["user"],
                password=self.mysql_config["password"],
                database=self.mysql_config["database"],
                autocommit=True,
                cursorclass=pymysql.cursors.DictCursor
            )
        except pymysql.err.OperationalError as e:
            # If database doesn't exist, try connecting without DB and create it
            if e.args[0] in (1049,):
                conn = pymysql.connect(
                    host=self.mysql_config["host"],
                    port=self.mysql_config["port"],
                    user=self.mysql_config["user"],
                    password=self.mysql_config["password"],
                    autocommit=True
                )
                with conn.cursor() as cur:
                    cur.execute(f"CREATE DATABASE IF NOT EXISTS `{self.mysql_config['database']}`")
                conn.close()
                return pymysql.connect(
                    host=self.mysql_config["host"],
                    port=self.mysql_config["port"],
                    user=self.mysql_config["user"],
                    password=self.mysql_config["password"],
                    database=self.mysql_config["database"],
                    autocommit=True,
                    cursorclass=pymysql.cursors.DictCursor
                )
            raise

    def _init_db(self):
        # Try MySQL first
        try:
            conn = self._get_mysql_connection()
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        password_hash VARCHAR(128) NOT NULL,
                        salt VARCHAR(64) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS triage_history (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        user_id INT,
                        filename VARCHAR(255) NOT NULL,
                        verdict VARCHAR(50) NOT NULL,
                        score INT NOT NULL,
                        reason_codes TEXT NOT NULL,
                        report_json MEDIUMTEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
                    )
                """)
            conn.close()
            self.engine_type = "mysql"
            logger.info("Connected to local MySQL database.")
            return
        except Exception as exc:
            logger.warning(f"MySQL unavailable ({exc}). Using SQLite fallback ({self.sqlite_path}).")
            self.engine_type = "sqlite"

        # SQLite fallback
        conn = sqlite3.connect(str(self.sqlite_path))
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS triage_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                filename TEXT NOT NULL,
                verdict TEXT NOT NULL,
                score INTEGER NOT NULL,
                reason_codes TEXT NOT NULL,
                report_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        conn.commit()
        conn.close()

    def register_user(self, username: str, password: str) -> tuple[bool, str]:
        username = username.strip().lower()
        if len(username) < 3:
            return False, "Username must be at least 3 characters."
        if len(password) < 6:
            return False, "Password must be at least 6 characters."

        pwd_hash, salt = hash_password(password)

        if self.engine_type == "mysql":
            try:
                conn = self._get_mysql_connection()
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO users (username, password_hash, salt) VALUES (%s, %s, %s)",
                        (username, pwd_hash, salt)
                    )
                conn.close()
                return True, "User registered successfully."
            except Exception as e:
                return False, f"Username already exists or database error: {e}"
        else:
            try:
                conn = sqlite3.connect(str(self.sqlite_path))
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                    (username, pwd_hash, salt)
                )
                conn.commit()
                conn.close()
                return True, "User registered successfully."
            except sqlite3.IntegrityError:
                return False, "Username already exists."
            except Exception as e:
                return False, f"Database error: {e}"

    def authenticate_user(self, username: str, password: str) -> dict[str, Any] | None:
        username = username.strip().lower()
        if self.engine_type == "mysql":
            try:
                conn = self._get_mysql_connection()
                with conn.cursor() as cur:
                    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
                    user = cur.fetchone()
                conn.close()
                if user and verify_password(password, user["password_hash"], user["salt"]):
                    return {"id": user["id"], "username": user["username"]}
                return None
            except Exception:
                return None
        else:
            conn = sqlite3.connect(str(self.sqlite_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cur.fetchone()
            conn.close()
            if user and verify_password(password, user["password_hash"], user["salt"]):
                return {"id": user["id"], "username": user["username"]}
            return None

    def save_analysis(self, user_id: int | None, filename: str, verdict: str, score: int, reason_codes: str, report_json: str):
        if self.engine_type == "mysql":
            try:
                conn = self._get_mysql_connection()
                with conn.cursor() as cur:
                    cur.execute(
                        """INSERT INTO triage_history 
                           (user_id, filename, verdict, score, reason_codes, report_json) 
                           VALUES (%s, %s, %s, %s, %s, %s)""",
                        (user_id, filename, verdict, score, reason_codes, report_json)
                    )
                conn.close()
            except Exception as e:
                logger.error(f"Failed to record analysis to MySQL: {e}")
        else:
            try:
                conn = sqlite3.connect(str(self.sqlite_path))
                cur = conn.cursor()
                cur.execute(
                    """INSERT INTO triage_history 
                       (user_id, filename, verdict, score, reason_codes, report_json) 
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (user_id, filename, verdict, score, reason_codes, report_json)
                )
                conn.commit()
                conn.close()
            except Exception as e:
                logger.error(f"Failed to record analysis to SQLite: {e}")

    def get_user_history(self, user_id: int, limit: int = 20) -> list[dict[str, Any]]:
        if self.engine_type == "mysql":
            try:
                conn = self._get_mysql_connection()
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT id, filename, verdict, score, reason_codes, created_at FROM triage_history WHERE user_id = %s ORDER BY id DESC LIMIT %s",
                        (user_id, limit)
                    )
                    history = cur.fetchall()
                conn.close()
                return list(history)
            except Exception:
                return []
        else:
            conn = sqlite3.connect(str(self.sqlite_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                "SELECT id, filename, verdict, score, reason_codes, created_at FROM triage_history WHERE user_id = ? ORDER BY id DESC LIMIT ?",
                (user_id, limit)
            )
            rows = cur.fetchall()
            conn.close()
            return [dict(r) for r in rows]
