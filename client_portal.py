from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import timedelta
import database

app = Flask(__name__)
# کلید سرّی برای امنیت Session‌ها
app.secret_key = 'vpn_client_portal_secret_key_123'

# تنظیم انقضای Session دائم به مدت ۳۰ روز (طبق سند پروژه)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') # تیک مرا به خاطر بسپار

        # اعتبارسنجی از دیتابیس مشترک vpn_system.db
        is_valid, reason = database.authenticate_user(username, password)

        # اگر حساب منقضی یا تمام شده باشد هم اجازه لاگین می‌دهیم تا بتواند شارژ بخرد
        if not is_valid and reason not in ["User is banned/disabled", "Quota exhausted"]:
            flash(f"خطا در ورود: {reason}", "danger")
            return redirect(url_for('login'))

        # ست کردن اطلاعات نشست (Session)
        session['user'] = username
        
        # مدیریت نشست و توکن طبق سند پروژه
        if remember:
            session.permanent = True  # ماندگاری ۳۰ روزه
        else:
            session.permanent = False # نشست عادی (بستن مرورگر / ۲۴ ساعته)

        flash("با موفقیت وارد شدید.", "success")
        return redirect(url_for('dashboard'))

    return render_template('client_login.html')

@app.route('/dashboard')
def dashboard():
    username = session.get('user')
    print(f"[DEBUG] Logged in session user: {username}")
    if not username:
        return "Session is empty! Please login again."
    
    user_info = database.get_user_info(username)
    print(f"[DEBUG] User Info fetched: {user_info}")
    
    history = database.get_user_quota_history(username)
    return render_template('client_dashboard.html', user=user_info, username=username, history=history)

@app.route('/buy-quota', methods=['POST'])
def buy_quota():
    username = session.get('user')
    if not username:
        return redirect(url_for('login'))

    try:
        quota_gb = float(request.form.get('quota_gb', 0))
        if quota_gb > 0:
            database.add_quota_to_user(username, quota_gb)
            flash(f"حساب شما با موفقیت به میزان {quota_gb} گیگابایت شارژ شد!", "success")
        else:
            flash("مقدار حجم درخواستی معتبر نیست.", "warning")
    except ValueError:
        flash("خطا در پردازش حجم درخواستی.", "danger")

    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("از حساب کاربری خود خارج شدید.", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    database.init_db()
    # اجرای پورتال کلاینت روی پورت 5001 برای عدم تداخل با پنل ادمین
    app.run(host='0.0.0.0', port=5001, debug=True)