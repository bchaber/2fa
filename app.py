import sqlite3, os, pyqrcode
from dotenv import load_dotenv
from binascii import unhexlify
from flask import Flask, request, session
from flask import render_template, redirect
from flask_login import LoginManager, UserMixin
from flask_login import login_user, logout_user
from flask_login import  login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from passlib.hash import argon2
from passlib.utils import getrandbytes, rng
from passlib.totp import TOTP

# Application secrets
load_dotenv(".app-secrets")
APP_DOMAIN = os.getenv("APP_DOMAIN")
SECRET_KEY = os.getenv("SECRET_KEY")
# Time-based One-Time Passwords
factory = TOTP.using(secrets_path=".totp-secrets",
                     issuer=APP_DOMAIN)
# Application definition
app = Flask(__name__)
app.secret_key = unhexlify(SECRET_KEY)
# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
# Rate limiter
limiter = Limiter(get_remote_address)
limiter.init_app(app)

class User(UserMixin):
    def __init__(self, username, password, totp):
        self.id = username
        self.password = password
        self.totp = totp

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
            res = db.execute("SELECT username, password, totp FROM user WHERE username = ?",
                            (username,) )
            row = res.fetchone()
            return User(*row)
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

    totp = factory.new()
    uri = totp.to_uri(label=username)
    pw = argon2.hash(password)

    with database() as db:
        db.execute("INSERT INTO user (username, password, totp) " + 
                   "VALUES (?, ?, ?);", (username, pw, totp.to_json()))

    print(pyqrcode.create(uri).terminal(quiet_zone=1))

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
        session["username-2fa"] = username
        return redirect("/login/2fa")
    else:
        return "Nieprawidłowy login lub hasło", 401

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")

@app.route("/login/2fa", methods=["GET"])
def login_2fa_form():
    return render_template("token.html")

@app.route("/login/2fa", methods=["POST"])
#@limiter.limit("1 per day", key_func = lambda : current_user.username)
def login_2fa():
    if "username-2fa" not in session:
        return "Problem z autentykacją", 401
    
    username = session["username-2fa"]
    user = load_user(username)
    if user is None:
        return "Problem z autentykacją", 401

    token = request.form.get("token")
    try:
        totp = factory.from_json(user.totp)
        match = TOTP.verify(token, totp)
        if match:
            session.pop("username-2fa")
            login_user(user)
            return redirect("/home")
    except Exception as ex:
        pass
        
    return "Problem z autentykacją", 401

if __name__ == "__main__":
    print("[*] Init database!")
    with database() as db:
        db.execute("DROP TABLE IF EXISTS user;")
        db.execute("CREATE TABLE user (" +
                   "username VARCHAR(32), " +
                   "password VARCHAR(128), " + 
                   "totp VARCHAR(256)" + 
                   ");")
        db.execute("DELETE FROM user;")
        db.execute("INSERT INTO user (username, password, totp) VALUES ('admin', '$argon2id$v=19$m=65536,t=3,p=4$ZKz13hvj/P+/17oX4tybMw$AJO64oLyzXt1D4v+2pOZMYeKGxNJ/lMz6EXUxlCDQjw', '{\"enckey\":{\"c\":14,\"k\":\"CHZ5IOWCNULULPKV7NLSBG6RNK25M3EF\",\"s\":\"3CN5GWVLKWVFL2Q5UOKA\",\"t\":\"2023-01-12\",\"v\":1},\"type\":\"totp\",\"v\":1}');")
        db.commit()
    app.run("0.0.0.0", 5050)
