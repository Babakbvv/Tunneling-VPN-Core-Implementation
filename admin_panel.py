from flask import Flask, render_template, request, redirect, url_for, flash
import database

app = Flask(__name__)
app.secret_key = 'super_secret_admin_key_for_flask'

# راه‌اندازی اولیه دیتابیس در صورت نیاز
database.init_db()

def format_bytes(size_bytes):
    """تبدیل بایت به فرمت خوانا (MB یا GB)"""
    if size_bytes is None:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

# ثبت فیلتر سفارشی برای قالب HTML
app.jinja_env.filters['format_bytes'] = format_bytes


@app.route('/')
def index():
    """صفحه اصلی: نمایش تمام کاربران و آمار مصرف"""
    conn = database.sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, is_active, total_quota_bytes, used_bytes, download_bytes, upload_bytes, speed_limit_kbps FROM users")
    users_raw = cursor.fetchall()
    conn.close()

    users = []
    for u in users_raw:
        total_q = u[3]
        used = u[4]
        percentage = round((used / total_q) * 100, 1) if total_q > 0 else 0
        if percentage > 100: 
            percentage = 100

        users.append({
            'id': u[0],
            'username': u[1],
            'is_active': u[2],
            'total_quota_bytes': u[3],
            'used_bytes': u[4],
            'download_bytes': u[5],
            'upload_bytes': u[6],
            'speed_limit_kbps': u[7],
            'usage_percent': percentage
        })

    return render_template('admin.html', users=users)


@app.route('/add_user', methods=['POST'])
def add_user_route():
    """افزودن کاربر جدید"""
    username = request.form.get('username')
    password = request.form.get('password')
    quota_gb = float(request.form.get('quota_gb', 2))
    speed_kbps = int(request.form.get('speed_limit_kbps', 512))

    if username and password:
        database.add_user(username, password, quota_gb=quota_gb, speed_limit_kbps=speed_kbps)
        flash(f"کاربر '{username}' با موفقیت ساخته شد.", "success")
    else:
        flash("نام کاربری و رمز عبور نمی‌تواند خالی باشد.", "danger")

    return redirect(url_for('index'))


@app.route('/toggle_status/<username>/<int:current_status>')
def toggle_status(username, current_status):
    """فعال/غیرفعال کردن اکانت کاربر"""
    new_status = 0 if current_status == 1 else 1
    database.set_user_status(username, is_active=new_status)
    flash(f"وضعیت کاربر '{username}' تغییر یافت.", "info")
    return redirect(url_for('index'))


if __name__ == '__main__':
    # اجرا روی پورت 5000
    app.run(host='0.0.0.0', port=5000, debug=True)