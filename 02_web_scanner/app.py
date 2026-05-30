"""
Project 2 — Vulnerable Flask App (intentional flaws for learning)
Run: python app.py   →   http://127.0.0.1:5000
NEVER deploy this publicly.
Dependencies: pip install flask
"""

import sqlite3
from flask import Flask, request, render_template_string, session, redirect

app = Flask(__name__)
app.secret_key = "super_insecure_key"
DB = "users.db"


def init_db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS users "
                "(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    con.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','admin123','admin')")
    con.execute("INSERT OR IGNORE INTO users VALUES (2,'alice','password','user')")
    con.commit()
    con.close()


# Flaw 1: SQL Injection
@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        con = sqlite3.connect(DB)
        # VULNERABLE: raw string formatting
        row = con.execute(
            f"SELECT * FROM users WHERE username='{u}' AND password='{p}'"
        ).fetchone()
        con.close()
        if row:
            session["user"] = row[1]
            session["role"] = row[3]
            return redirect("/dashboard")
        error = "Invalid credentials"
    return render_template_string(LOGIN_TMPL, error=error)


# Flaw 2: Reflected XSS
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULNERABLE: unsanitised output
    return render_template_string(f"<p>Results for: {q}</p>")


# Flaw 3: IDOR (no authorisation check)
@app.route("/profile/<int:user_id>")
def profile(user_id):
    con = sqlite3.connect(DB)
    row = con.execute("SELECT id,username,role FROM users WHERE id=?",
                      (user_id,)).fetchone()
    con.close()
    return (f"ID:{row[0]}  User:{row[1]}  Role:{row[2]}" if row else ("Not found", 404))


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return f"<h2>Welcome {session['user']} ({session['role']})</h2>"


LOGIN_TMPL = """
<form method=post>
  <input name=username placeholder=Username><br>
  <input name=password type=password placeholder=Password><br>
  <button type=submit>Login</button>
  <p style=color:red>{{ error }}</p>
</form>"""


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
