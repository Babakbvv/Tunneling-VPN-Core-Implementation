import sqlite3
import hashlib

DB_NAME = "vpn_system.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # اضافه شدن فیلد speed_limit_kbps (پیش‌فرض 512 KB/s)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            total_quota_bytes INTEGER DEFAULT 2147483648,
            used_bytes INTEGER DEFAULT 0,
            download_bytes INTEGER DEFAULT 0,
            upload_bytes INTEGER DEFAULT 0,
            speed_limit_kbps INTEGER DEFAULT 512
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL,
            dest_port INTEGER,
            domain_name TEXT,
            protocol TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def add_user(username, password, quota_gb=2, speed_limit_kbps=512):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    quota_bytes = int(quota_gb * 1024 * 1024 * 1024)
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, total_quota_bytes, speed_limit_kbps) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), quota_bytes, speed_limit_kbps)
        )
        conn.commit()
        print(f"[+] User '{username}' created with {quota_gb} GB quota and {speed_limit_kbps} KB/s speed limit.")
    except sqlite3.IntegrityError:
        print(f"[-] User '{username}' already exists.")
    finally:
        conn.close()

def get_user_speed_limit(username):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT speed_limit_kbps FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    
    if row and row[0]:
        # تبدیل KB/s به Bytes/s
        return row[0] * 1024
    return 512 * 1024  # مقدار پیش‌فرض اگر پیدا نشد
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

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



def log_traffic(username, client_ip, dest_ip, dest_port, domain_name, protocol):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO traffic_logs (username, client_ip, dest_ip, dest_port, domain_name, protocol)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (username, str(client_ip), dest_ip, dest_port, domain_name, protocol))
    conn.commit()
    conn.close()   

def check_user_quota(username):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT total_quota_bytes, used_bytes, is_active FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if not row or row[2] == 0:
        return False, "Account disabled or exhausted"
    if row[1] >= row[0]:
        set_user_status(username, 0)
        return False, "Quota exhausted"
    return True, "OK"

def set_user_status(username, is_active=1):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_active = ? WHERE username = ?", (username, is_active))
    conn.commit()
    conn.close()     

if __name__ == "__main__":
    init_db()
    add_user("ali", "123456", quota_gb=2)پ

    

