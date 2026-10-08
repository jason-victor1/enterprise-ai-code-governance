"""
Tier 2: Domain Services & Cross-Service Data Contracts.
Contains vulnerable data access patterns designed to trigger SAST and AST gates.
"""
import sqlite3
from typing import Optional, Dict, Any


class UserDataService:
    """Simulated business logic service interacting with SQLite database."""

    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path)
        self._init_db()

    def _init_db(self) -> None:
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL
            )
        """)
        cursor.execute("INSERT OR IGNORE INTO users (id, username, email, role) VALUES (1, 'admin', 'admin@corp.internal', 'SuperAdmin')")
        cursor.execute("INSERT OR IGNORE INTO users (id, username, email, role) VALUES (2, 'developer', 'dev@corp.internal', 'Engineer')")
        self.conn.commit()

    def find_user_by_username_insecure(self, username: str) -> Optional[Dict[str, Any]]:
        """
        VULNERABLE (AST/SAST Target):
        Direct string concatenation inside SQL statement.
        """
        cursor = self.conn.cursor()
        query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"
        cursor.execute(query)
        row = cursor.fetchone()
        if row:
            return {"id": row[0], "username": row[1], "email": row[2], "role": row[3]}
        return None

    def find_user_by_username_secure(self, username: str) -> Optional[Dict[str, Any]]:
        """
        REMEDIATED PATTERN (Target output for Fixer Agent):
        Parameterized query binding.
        """
        cursor = self.conn.cursor()
        query = "SELECT id, username, email, role FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        row = cursor.fetchone()
        if row:
            return {"id": row[0], "username": row[1], "email": row[2], "role": row[3]}
        return None
