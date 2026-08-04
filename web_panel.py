from flask import Flask, render_template_string, request, redirect, url_for
import database

app = Flask(__name__)

# قالب ساده HTML برای نمایش پنل ادمین
ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html dir="rtl" lang="fa">
<head>
    <meta charset="UTF-8">
    <title>پنل مدیریت VPN</title>
    <style>
        body { font-family: Tahoma, sans-serif; margin: 30px; background-color: #f4f4f9; }
        h1, h2 { color: #333; }
        table { width: 100%; border-collapse: collapse; background: #fff; margin-bottom: 20px; }
        th, td { border: 1px solid #ccc; padding: 10px; text-align: center; }
        th { background-color: #007bff; color: white; }
        .btn { padding: 5px 10px; background: #dc3545; color: white; text-decoration: none; border-radius: 3px; }
        .card { background: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; border: 1px solid #ddd; }
    </style>
</head>
<body>
    <h1>🛡️ داشبورد مدیریت سرور VPN</h1>
    
    <div class="card">
        <h2>لیست کاربران و آمار مصرف</h2>
        <table>
            <tr>
                <th>شناسه</th>
                <th>نام کاربری</th>
                <th>حجم کل (MB)</th>
                <th>حجم مصرفی (MB)</th>
                <th>وضعیت</th>
            </tr>
            {% for user in users %}
            <tr>
                <td>{{ user[0] }}</td>
                <td><b>{{ user[1] }}</b></td>
                <td>{{ (user[4] / 1024 / 1024) | round(2) }} MB</td>
                <td>{{ (user[5] / 1024 / 1024) | round(2) }} MB</td>
                <td>
                    {% if user[3] == 1 %}
                        <span style="color: green;">فعال</span>
                    {% else %}
                        <span style="color: red;">مسدود</span>
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <div class="card">
        <h2>افزودن کاربر جدید</h2>
        <form action="/add_user" method="POST">
            نام کاربری: <input type="text" name="username" required>
            رمز عبور: <input type="password" name="password" required>
            سهمیه (گیگابایت): <input type="number" name="quota" value="2" required>
            <button type="submit" style="background: #28a745; color: white; border: none; padding: 5px 15px;">افزودن</button>
        </form>
    </div>
</body>
</html>
"""

@app.route('/')
def admin_dashboard():
    # خواندن اطلاعات از دیتابیس
    conn = database.sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    
    return render_template_string(ADMIN_TEMPLATE, users=users)

@app.route('/add_user', methods=['POST'])
def add_user_route():
    username = request.form['username']
    password = request.form['password']
    quota = int(request.form['quota'])
    
    database.add_user(username, password, quota_gb=quota)
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    # ساخت دیتابیس در صورت عدم وجود
    database.init_db()
    # اجرای وب‌سرور روی پورت 5000
    app.run(host='0.0.0.0', port=5000, debug=True)