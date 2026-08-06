import sqlite3
import hashlib

DB_NAME = "vpn_system.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # جدول کاربران (اضافه شدن فیلدهای is_online و needs_kick)
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
            speed_limit_kbps INTEGER DEFAULT 512,
            is_online INTEGER DEFAULT 0,
            needs_kick INTEGER DEFAULT 0
        )
    ''')
    
    # بررسی و اضافه کردن ستون‌های جدید در صورت وجود دیتابیس قدیم

    # جدول لاگ‌های ترافیک
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

    # جدول قوانین فایروال
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS firewall_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_user TEXT DEFAULT 'ALL',
            dst_ip TEXT NOT NULL,
            dst_port INTEGER DEFAULT 0,
            action TEXT DEFAULT 'BLOCK',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')


    cursor.execute('''
    CREATE TABLE IF NOT EXISTS quota_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        added_quota_gb REAL NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
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
        return row[0] * 1024  # تبدیل KB/s به Bytes/s
    return 512 * 1024

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
    cursor.execute("UPDATE users SET is_active = ? WHERE username = ?", (is_active, username))
    conn.commit()
    conn.close()     

# ==================== ONLINE & KICK FUNCTIONS ====================

def set_user_online_status(username, is_online):
    """ثبت وضعیت آنلاین یا آفلاین کاربر در دیتابیس"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET is_online = ?, needs_kick = 0 WHERE username = ?", 
        (1 if is_online else 0, username)
    )
    conn.commit()
    conn.close()

def get_online_users():
    """دریافت لیست کاربران آنلاین برای پنل وب"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT username, upload_bytes, download_bytes FROM users WHERE is_online = 1")
    rows = cursor.fetchall()
    conn.close()
    return [{"username": r[0], "upload": r[1], "download": r[2]} for r in rows]

def mark_user_for_kick(username):
    """ثبت درخواست قطع اتصال (Kick) از پنل وب"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET needs_kick = 1 WHERE username = ?", (username,))
    conn.commit()
    conn.close()

def check_user_needs_kick(username):
    """بررسی دستور Kick توسط هسته سرور VPN"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT needs_kick FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return True if row and row[0] == 1 else False

# ==================== FIREWALL FUNCTIONS ====================

def add_firewall_rule(target_user, dst_ip, dst_port, action):
    """افزودن یک قانون فایروال جدید"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO firewall_rules (target_user, dst_ip, dst_port, action)
        VALUES (?, ?, ?, ?)
    ''', (target_user, dst_ip, dst_port, action))
    conn.commit()
    conn.close()

def delete_firewall_rule(rule_id):
    """حذف قانون فایروال با شناسه"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM firewall_rules WHERE id = ?', (rule_id,))
    conn.commit()
    conn.close()

def get_all_firewall_rules():
    """دریافت تمام قوانین فایروال ثبت شده"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, target_user, dst_ip, dst_port, action, created_at 
        FROM firewall_rules 
        ORDER BY id DESC
    ''')
    rules = cursor.fetchall()
    conn.close()
    return rules

def is_packet_blocked(username, dst_ip, dst_port):
    """بررسی مسدود بودن پکت در هسته سرور"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT action FROM firewall_rules 
        WHERE (target_user = ? OR target_user = 'ALL')
          AND (dst_ip = ? OR dst_ip = '0.0.0.0')
          AND (dst_port = ? OR dst_port = 0)
    ''', (username, dst_ip, dst_port))
    rules = cursor.fetchall()
    conn.close()
    
    for (action,) in rules:
        if action.upper() == 'BLOCK':
            return True
    return False


def add_quota_to_user(username, quota_gb):
    """افزایش حجم کاربر و ثبت تاریخچه خرید"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    additional_bytes = int(quota_gb * 1024 * 1024 * 1024)
    
    # ۱. افزایش حجم کل و فعال‌سازی مجدد حساب در صورت مسدود بودن
    cursor.execute('''
        UPDATE users 
        SET total_quota_bytes = total_quota_bytes + ?,
            is_active = 1
        WHERE username = ?
    ''', (additional_bytes, username))
    
    # ۲. ثبت در تاریخچه خریدها
    cursor.execute('''
        INSERT INTO quota_requests (username, added_quota_gb)
        VALUES (?, ?)
    ''', (username, quota_gb))
    
    conn.commit()
    conn.close()

def get_user_quota_history(username):
    """دریافت تاریخچه شارژهای کاربر"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT added_quota_gb, timestamp 
        FROM quota_requests 
        WHERE username = ? 
        ORDER BY id DESC
    ''', (username,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_user_info(username):
    """دریافت جزئیات کامل حساب کاربر به همراه تبدیل واحدها به گیگابایت"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT total_quota_bytes, used_bytes, download_bytes, upload_bytes, is_active, speed_limit_kbps
        FROM users WHERE username = ?
    ''', (username,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        total_bytes = row[0] if row[0] is not None else 0
        used_bytes = row[1] if row[1] is not None else 0
        remaining_bytes = max(0, total_bytes - used_bytes)
        
        # تبدیل بایت به گیگابایت در سمت پایتون
        gb_factor = 1024 * 1024 * 1024
        
        return {
            "total_quota_gb": round(total_bytes / gb_factor, 2),
            "used_gb": round(used_bytes / gb_factor, 2),
            "remaining_gb": round(remaining_bytes / gb_factor, 2),
            "download_mb": round((row[2] or 0) / (1024 * 1024), 2),
            "upload_mb": round((row[3] or 0) / (1024 * 1024), 2),
            "is_active": bool(row[4]),
            "speed_limit": row[5] if row[5] is not None else 512
        }
    return None

if __name__ == "__main__":
    init_db()
    add_user("ali", "123456", quota_gb=2)