from flask import Flask, request, render_template_string, redirect, session
import time

app = Flask(__name__)
app.secret_key = "mock-router-secret"

# Fake credentials (change these)
CORRECT_USER = "admin"
CORRECT_PASS = "admin123"

# Very basic rate limiting simulation
attempts = {}

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Router Login</title>
    <style>
        body { font-family: Arial; background: #f0f0f0; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .box { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); width: 320px; }
        input { width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #0066cc; color: white; border: none; cursor: pointer; }
        .error { color: red; font-size: 14px; }
    </style>
</head>
<body>
    <div class="box">
        <h2>Router Admin</h2>
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def login():
    ip = request.remote_addr
    now = time.time()

    # Simple rate limit (optional)
    if ip in attempts:
        attempts[ip] = [t for t in attempts[ip] if now - t < 60]
        if len(attempts[ip]) >= 10:
            return "Too many attempts. Try later.", 429
    else:
        attempts[ip] = []

    error = None
    if request.method == "POST":
        attempts[ip].append(now)
        user = request.form.get("username", "")
        pwd = request.form.get("password", "")

        if user == CORRECT_USER and pwd == CORRECT_PASS:
            session["logged_in"] = True
            return redirect("/admin")
        else:
            error = "Incorrect username or password"

    return render_template_string(LOGIN_PAGE, error=error)

@app.route("/admin")
def admin():
    if not session.get("logged_in"):
        return redirect("/")
    return "<h1>Welcome to Router Admin Panel</h1><p>Mock successful login.</p>"

if __name__ == "__main__":
    print("Mock router running on http://127.0.0.1:8080")
    app.run(host="0.0.0.0", port=8080, debug=False)