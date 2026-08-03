import sqlite3
import hashlib
import os

DB_NAME = "vpn_system.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            total_quota_bytes INTEGER DEFAULT 2147483648, 
            used_bytes INTEGER DEFAULT 0,
            download_bytes INTEGER DEFAULT 0,
            upload_bytes INTEGER DEFAULT 0
        )
    ''')
    

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS active_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            virtual_ip TEXT NOT NULL,
            connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def add_user(username, password, quota_gb=2):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    quota_bytes = quota_gb * 1024 * 1024 * 1024
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, total_quota_bytes) VALUES (?, ?, ?)",
            (username, hash_password(password), quota_bytes)
        )
        conn.commit()
        print(f"[+] User '{username}' created successfully with {quota_gb} GB quota.")
    except sqlite3.IntegrityError:
        print(f"[-] User '{username}' already exists.")
    finally:
        conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password_hash, is_active, total_quota_bytes, used_bytes FROM users WHERE username = ?",
        (username,)
    )
    user = cursor.fetchone()
    conn.close()

    if not user:
        return False, "User not found"
    
    stored_hash, is_active, total_quota, used_bytes = user
    
    if stored_hash != hash_password(password):
        return False, "Invalid password"
    
    if is_active == 0:
        return False, "User is banned/disabled"
        
    if used_bytes >= total_quota:
        return False, "Quota exhausted"
        
    return True, "Success"

def update_usage(username, upload_add=0, download_add=0):
    """به‌روزرسانی حجم مصرفی کاربر (Accounting)"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    total_add = upload_add + download_add
    cursor.execute('''
        UPDATE users 
        SET upload_bytes = upload_bytes + ?,
            download_bytes = download_bytes + ?,
            used_bytes = used_bytes + ?
        WHERE username = ?
    ''', (upload_add, download_add, total_add, username))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    add_user("ali", "123456", quota_gb=2)