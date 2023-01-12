import sqlite3
from flask import Flask, request
from flask import render_template, redirect
from flask_login import LoginManager, UserMixin
from flask_login import login_user, logout_user
from flask_login import  login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from passlib.hash import argon2
from passlib.utils import getrandbytes, rng

app = Flask(__name__)
app.secret_key = getrandbytes(rng, 32)

login_manager = LoginManager()
login_manager.init_app(app)

limiter = Limiter(get_remote_address)
limiter.init_app(app)

class User(UserMixin):
    def __init__(self, username, password):
        self.id = username
        self.password = password

def database():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/home")
@login_required
def home():
    return render_template("home.html")

@login_manager.user_loader
def load_user(username):
    if username is None:
        return None

    with database() as db:
        try:
            res = db.execute("SELECT username, password FROM user WHERE username = ?", (username,) )
            row = res.fetchone()
            usr = row[0]
            pwd = row[1]
            return User(usr, pwd)
        except:
            return None
    return User(username, password)

@app.route("/register", methods=["GET"])
def register_form():
    return render_template("register.html")

@app.route("/register", methods=["POST"])
@limiter.limit("1/second")
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return "Username and password are required", 400

    user = load_user(username)
    if user is not None:
        return "User already registered", 401

    hashed = argon2.hash(password)
    with database() as db:
        db.execute("INSERT INTO user (username, password) VALUES (?, ?);", (username, hashed))

    return redirect("/login")

@app.route("/login", methods=["GET"])
def login_form():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
@limiter.limit("1/second")
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    user = load_user(username)
    if user is None:
        return "Nieprawidłowy login lub hasło", 401

    if argon2.verify(password, user.password):
        login_user(user)
        return redirect("/home")
    else:
        return "Nieprawidłowy login lub hasło", 401

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")

if __name__ == "__main__":
    print("[*] Init database!")
    with database() as db:
        db.execute("DROP TABLE IF EXISTS user;")
        db.execute("CREATE TABLE user (username VARCHAR(32), password VARCHAR(128));")
        db.execute("DELETE FROM user;")
        db.execute("INSERT INTO user (username, password) VALUES ('bach', '$argon2id$v=19$m=65536,t=3,p=4$ZKz13hvj/P+/17oX4tybMw$AJO64oLyzXt1D4v+2pOZMYeKGxNJ/lMz6EXUxlCDQjw');")
        db.commit()
    app.run("0.0.0.0", 5050)
