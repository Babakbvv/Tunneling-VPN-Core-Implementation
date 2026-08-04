import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash
import database

app = Flask(__name__)
app.secret_key = 'super_secret_key'

def format_bytes(size_bytes):
    if not size_bytes: return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

app.jinja_env.filters['format_bytes'] = format_bytes

@app.route('/')
def index():
    return redirect(url_for('users_page'))

@app.route('/users')
def users_page():
    database.init_db()

    conn = sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT username, is_active, total_quota_bytes, used_bytes, download_bytes, upload_bytes, speed_limit_kbps FROM users")
    users_raw = cursor.fetchall()
    conn.close()
    
    users = []
    for u in users_raw:
        total = u[2]
        used = u[3]
        percent = round((used / total) * 100, 1) if total > 0 else 0
        users.append({
            'username': u[0], 
            'is_active': u[1], 
            'total_quota_bytes': u[2],
            'quota_gb': round(u[2] / (1024**3), 2),
            'used_bytes': u[3], 
            'download_bytes': u[4], 
            'upload_bytes': u[5],
            'speed_limit_kbps': u[6], 
            'percent': min(percent, 100)
        })

    return render_template('users.html', users=users, active_page='users')

@app.route('/update_user', methods=['POST'])
def update_user():
    """ثبت تغییرات حجم، سرعت و وضعیت فعال/مسدود بودن کاربر"""
    username = request.form.get('username')
    quota_gb = float(request.form.get('quota_gb'))
    speed_kbps = int(request.form.get('speed_limit_kbps'))
    is_active = int(request.form.get('is_active'))  # دریافت وضعیت جدید (0 یا 1)
    
    total_quota_bytes = int(quota_gb * 1024 * 1024 * 1024)
    
    conn = sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users 
        SET total_quota_bytes = ?, speed_limit_kbps = ?, is_active = ? 
        WHERE username = ?
    """, (total_quota_bytes, speed_kbps, is_active, username))
    conn.commit()
    conn.close()
    
    flash(f"اطلاعات کاربر '{username}' با موفقیت به روز شد.", "success")
    return redirect(url_for('users_page'))

if __name__ == '__main__':
    database.init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)