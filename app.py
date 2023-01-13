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
from yubico_client import Yubico
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
# Yubico One-Time Password
load_dotenv(".yubi-secrets")
YUBI_CLIENT = os.getenv("YUBI_CLIENT")
YUBI_SECRET = os.getenv("YUBI_SECRET")
yubico = Yubico(YUBI_CLIENT, YUBI_SECRET)
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
    def __init__(self, username, password,
        fido2, yubi, totp):
        self.id = username
        self.password = password
        self.fido2 = fido2
        self.yubi = yubi
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
            res = db.execute("SELECT username, password, fido2, yubi, totp " +
                             "FROM user WHERE username = ?", (username,) )
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
        second_factor = None
        if user.totp != "":
            second_factor = "totp"
        if user.yubi != "":
            second_factor = "yubi"
        if user.fido2 != "":
            second_factor = "fido2"
        if second_factor:
            return redirect("/login/2fa/" + second_factor)
        login_user(user)
        return redirect("/home")
    else:
        return "Nieprawidłowy login lub hasło", 401

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")

@app.route("/login/2fa/yubi", methods=["GET"])
def login_2fa_yubi():
    return render_template("token.html", second_factor="Yubikey OTP")

@app.route("/login/2fa/totp", methods=["GET"])
def login_2fa_totp():
    return render_template("token.html", second_factor="TOTP")

@app.route("/login/2fa/fido2", methods=["GET"])
def login_2fa_fido2():
    return render_template("token.html", second_factor="FIDO2")

def verify(user, token):
    try:
        if user.fido2 != "":
            print("2FA: WebAuthn")
            return False

        if user.yubi != "":
            print("2FA: Yubikey OTP")
            return yubico.verify(token) and token[1:12] == user.yubi

        if user.totp != "":
            print("2FA: TOTP")
            totp = factory.from_json(user.totp)
            return TOTP.verify(token, totp)
    except Exception as ex:
        print("Exception during 2FA verification: " + str(ex))
    return False
    
@app.route("/login/2fa", methods=["POST"])
@limiter.limit("10/minute", key_func = lambda : session.get("username-2fa"))
def login_2fa():
    if "username-2fa" not in session:
        return "Problem z autentykacją", 401
    
    username = session["username-2fa"]
    user = load_user(username)
    if user is None:
        return "Problem z autentykacją", 401

    token = request.form.get("token")
    if verify(user, token):
        session.pop("username-2fa")
        login_user(user)
        return redirect("/home")
        
    return "Problem z autentykacją", 401

if __name__ == "__main__":
    print("[*] Init database!")
    with database() as db:
        db.execute("DROP TABLE IF EXISTS user;")
        db.execute("CREATE TABLE user (" +
                   "username VARCHAR(32), " +
                   "password VARCHAR(128), " + 
                   "fido2 VARCHAR(256)," + 
                   "yubi  VARCHAR(12),"  + 
                   "totp  VARCHAR(256)" + 
                   ");")
        db.execute("DELETE FROM user;")
        db.execute("INSERT INTO user (username, password, fido2, yubi, totp) VALUES ('admin', '$argon2id$v=19$m=65536,t=3,p=4$ZKz13hvj/P+/17oX4tybMw$AJO64oLyzXt1D4v+2pOZMYeKGxNJ/lMz6EXUxlCDQjw', '', '', '{\"enckey\":{\"c\":14,\"k\":\"CHZ5IOWCNULULPKV7NLSBG6RNK25M3EF\",\"s\":\"3CN5GWVLKWVFL2Q5UOKA\",\"t\":\"2023-01-12\",\"v\":1},\"type\":\"totp\",\"v\":1}');")
        db.execute("INSERT INTO user (username, password, fido2, yubi, totp) VALUES ('bach', '$argon2id$v=19$m=65536,t=3,p=4$ZKz13hvj/P+/17oX4tybMw$AJO64oLyzXt1D4v+2pOZMYeKGxNJ/lMz6EXUxlCDQjw', '', 'ccccccvhrlhr', '');")
        db.commit()
    app.run("0.0.0.0", 5050)
