import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash
import database

app = Flask(__name__)
app.secret_key = 'super_secret_key'

def format_bytes(size_bytes):
    """فیلتر تبدیل بایت به واحدهای قابل خواندن (KB, MB, GB و ...)"""
    if not size_bytes: 
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

app.jinja_env.filters['format_bytes'] = format_bytes

# ---------------------------------------------------------
# روت‌های اصلی پنل
# ---------------------------------------------------------

@app.route('/')
def index():
    """هدایت صفحه اصلی به مدیریت کاربران"""
    return redirect(url_for('users_page'))

@app.route('/users')
def users_page():
    """صفحه لیست و مدیریت کاربران"""
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
    """تغییر وضعیت، حجم و سرعت کاربر"""
    username = request.form.get('username')
    quota_gb = float(request.form.get('quota_gb'))
    speed_kbps = int(request.form.get('speed_limit_kbps'))
    is_active = int(request.form.get('is_active'))
    
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

@app.route('/traffic-logs')
def traffic_logs_page():
    """صفحه اختصاصی رصد مقاصد ترافیکی شبکه (خوانش از جدول traffic_logs)"""
    database.init_db()
    
    conn = sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    
    # دریافت ۱۰۰ لاگ جدید ترافیک خروجی کاربران
    cursor.execute("""
        SELECT username, client_ip, dest_ip, dest_port, domain_name, protocol, timestamp 
        FROM traffic_logs 
        ORDER BY id DESC LIMIT 100
    """)
    logs_raw = cursor.fetchall()
    conn.close()
    
    logs = []
    for l in logs_raw:
        logs.append({
            'username': l[0],
            'client_ip': l[1],
            'dest_ip': l[2],
            'dest_port': l[3],
            'domain_name': l[4] if l[4] else "N/A",
            'protocol': l[5] if l[5] else "TCP/UDP",
            'timestamp': l[6]
        })
    
    return render_template('traffic_logs.html', logs=logs, active_page='traffic_logs')




@app.route('/firewall')
def firewall_page():
    rules = database.get_all_firewall_rules()
    return render_template('firewall.html', rules=rules, active_page='firewall')

@app.route('/firewall/add', methods=['POST'])
def add_firewall_rule():
    target_user = request.form.get('target_user', 'ALL').strip()
    dst_ip = request.form.get('dst_ip', '').strip()
    dst_port = request.form.get('dst_port', 0)
    action = request.form.get('action', 'BLOCK')

    try:
        dst_port = int(dst_port)
    except ValueError:
        dst_port = 0

    if dst_ip:
        database.add_firewall_rule(target_user, dst_ip, dst_port, action)
        flash(f'قانون جدید برای IP {dst_ip} با موفقیت ثبت شد.', 'success')
    else:
        flash('لطفاً آدرس IP مقصد را به درستی وارد کنید.', 'danger')

    return redirect(url_for('firewall_page'))

@app.route('/firewall/delete/<int:rule_id>')
def delete_firewall_rule(rule_id):
    database.delete_firewall_rule(rule_id)
    flash('قانون مورد نظر با موفقیت حذف شد.', 'info')
    return redirect(url_for('firewall_page'))




@app.route('/active-clients')
def active_clients_page():
    # دریافت لیست کاربران آنلاین از دیتابیس
    online_users = database.get_online_users()
    return render_template('active_clients.html', clients=online_users, active_page='active_clients')

@app.route('/kick/<username>')
def kick_user(username):
    # علامت‌گذاری کاربر در دیتابیس برای کیک شدن توسط سرور
    database.mark_user_for_kick(username)
    flash(f'دستور قطع اتصال (Kick) برای کاربر {username} صادر شد.', 'warning')
    return redirect(url_for('active_clients_page'))

# ---------------------------------------------------------
# اجرای پروسس فلاسک
# ---------------------------------------------------------
if __name__ == '__main__':
    database.init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)