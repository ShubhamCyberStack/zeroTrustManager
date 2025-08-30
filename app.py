from flask import Flask, render_template, request, redirect, session, flash, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from bson import ObjectId
import bcrypt
import pyotp
import time
import secrets
from utils import generate_password, derive_key_from_password
from cryptography.fernet import Fernet
import base64
import hashlib
import datetime

app = Flask(__name__)
app.secret_key = "super-secret-key"
CORS(app, supports_credentials=True)

client = MongoClient(
    "mongodb+srv://admin:shubhamsaini11@zerotrust.dgubcw7.mongodb.net/zerotrust?retryWrites=true&w=majority&appName=zerotrust"
)

db = client["zerotrust"]
users_col = db["users"]
vault_col = db["vault"]
audit_logs_col = db["audit_logs"]

SECURITY_QUESTIONS = {
    "favorite_teacher": "What is your favorite teacher's name?",
    "pet_name": "What is your pet's name?",
    "favorite_person": "What is your favorite person's name?",
    "company_name": "What is your favorite company?",
}

# Delete audit logs older than 1 day when server restarts
def delete_old_audit_logs():
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=1)
    audit_logs_col.delete_many({'timestamp': {'$lt': cutoff}})

delete_old_audit_logs()

def derive_key_from_password(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def log_audit(username, action, details=""):
    ip = request.remote_addr
    timestamp = datetime.datetime.utcnow()
    audit_logs_col.insert_one({
        "username": username,
        "action": action,
        "timestamp": timestamp,
        "ip_address": ip,
        "details": details
    })

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        step = request.form.get("step", "1")
        
        if step == "1":
            username = request.form["username"].strip().lower()
            password = request.form["password"]
            
            if users_col.find_one({"username": username}):
                flash("Username already exists!")
                return render_template("register.html", questions=SECURITY_QUESTIONS)
            
            def is_strong_password(pw, user):
                errors = []
                if len(pw) < 8:
                    errors.append("at least 8 characters")
                if not any(c.isupper() for c in pw):
                    errors.append("one uppercase letter")
                if not any(c.islower() for c in pw):
                    errors.append("one lowercase letter")
                if not any(c.isdigit() for c in pw):
                    errors.append("one number")
                if not any(c in "!@#$%^&*()_+-=[]{}|;:',./<>?/~`" for c in pw):
                    errors.append("one special character")
                if user in pw.lower():
                    errors.append("must not contain username")
                return errors
            
            issues = is_strong_password(password, username)
            if issues:
                flash("Weak password: must include " + ", ".join(issues))
                return render_template("register.html", questions=SECURITY_QUESTIONS)
            
            hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            session["temp_user"] = {"username": username, "password": hashed_pw}
            return render_template("register_question.html", step=2, questions=SECURITY_QUESTIONS)
        
        elif step == "2":
            question = request.form.get("security_question")
            answer = request.form.get("security_answer")
            
            if not question or not answer:
                flash("Please select a security question and enter an answer.")
                return render_template("register_question.html", step=2, questions=SECURITY_QUESTIONS)
            
            temp = session.get("temp_user")
            if not temp:
                flash("Session expired.")
                return render_template("register.html", questions=SECURITY_QUESTIONS)
            
            secret = pyotp.random_base32()
            temp.update({
                "question": question,
                "answer": answer.lower().strip(),
                "secret": secret
            })
            session["temp_user"] = temp
            
            otp_uri = pyotp.TOTP(secret).provisioning_uri(name=temp["username"], issuer_name="ZeroTrustManager")
            return render_template("register_otp.html", otp_uri=otp_uri, secret=secret)
        
        elif step == "3":
            otp_code = request.form["otp"]
            temp = session.get("temp_user")
            
            if not temp:
                flash("Session expired. Try again.")
                return render_template("register.html", questions=SECURITY_QUESTIONS)
            
            totp = pyotp.TOTP(temp["secret"])
            if not totp.verify(otp_code):
                flash("Invalid OTP!")
                return render_template("register.html", questions=SECURITY_QUESTIONS)
            
            super_secret_key = secrets.token_hex(16)
            users_col.insert_one({
                "username": temp["username"],
                "password": temp["password"],
                "mfa": temp["secret"],
                "question": temp["question"],
                "answer": temp["answer"],
                "super_secret_key": super_secret_key,
                "role": "user"
            })
            
            log_audit(temp["username"], "register", "User registered successfully")
            session.pop("temp_user", None)
            return render_template("show_super_secret.html", super_secret_key=super_secret_key)
    
    return render_template("register.html", questions=SECURITY_QUESTIONS)

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]
        otp_code = request.form.get("otp")
        question = request.form.get("security_question")
        answer = request.form.get("security_answer", "").lower().strip()
        
        user = users_col.find_one({"username": username})
        
        if not user or not bcrypt.checkpw(password.encode(), user["password"]):
            flash("Login failed!")
            return render_template("login.html", questions=SECURITY_QUESTIONS)
        
        # Security question/answer check
        if question != user.get("question") or answer != user.get("answer", "").lower().strip():
            flash("Security question or answer is incorrect.")
            return render_template("login.html", questions=SECURITY_QUESTIONS)
        
        totp = pyotp.TOTP(user["mfa"])
        if not totp.verify(otp_code):
            flash("OTP failed!")
            return render_template("login.html", questions=SECURITY_QUESTIONS)
        
        session["username"] = username
        session["role"] = user.get("role", "user")
        session["key"] = derive_key_from_password(password).decode()
        session["unlocked"] = False
        session["unlocked_collections"] = {"banking": False, "social": False, "other": False}
        session["otp_verified"] = False
        session["last_activity"] = time.time()
        
        log_audit(username, "login", "User logged in")
        
        # Redirect admin users to admin choice page
        if user.get("role") == "admin":
            return redirect("/admin/choice")
        else:
            return redirect("/unlock-vault")
    
    return render_template("login.html", questions=SECURITY_QUESTIONS)

@app.route('/unlock-vault', methods=["GET", "POST"])
def unlock_vault():
    if "username" not in session:
        return redirect("/login")
    
    username = session["username"]
    
    if request.method == "POST":
        otp = request.form["otp"]
        user = users_col.find_one({"username": username})
        totp = pyotp.TOTP(user["mfa"])
        
        if totp.verify(otp):
            session["unlocked"] = True
            session["last_activity"] = time.time()
            log_audit(username, "vault_unlock", "Vault unlocked after login")
            flash("Vault unlocked!")
            return redirect("/dashboard")
        else:
            flash("Invalid OTP!")
    
    return render_template("unlock_vault.html")

@app.route('/dashboard', methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        return redirect("/login")
    
    if not session.get("unlocked"):
        return redirect("/unlock-vault")
    
    username = session["username"]
    
    # Auto-lock vault after inactivity
    if session.get("unlocked") and time.time() - session.get("last_activity", 0) > 120:
        session["unlocked"] = False
        session["unlocked_collections"] = {"banking": False, "social": False, "other": False}
        session["otp_verified"] = False
        log_audit(username, "auto_lock", "Vault auto-locked due to inactivity")
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "unlock":
            otp = request.form["otp"]
            user = users_col.find_one({"username": username})
            totp = pyotp.TOTP(user["mfa"])
            
            if totp.verify(otp):
                session["unlocked"] = True
                session["last_activity"] = time.time()
                log_audit(username, "vault_unlock", "Vault unlocked successfully")
                flash("Vault unlocked!")
            else:
                flash("Invalid OTP!")
        
        elif action == "add" and session.get("unlocked"):
            service = request.form["service"]
            account = request.form["account"]
            password = request.form.get("password", "")
            collection = request.form["collection"]
            otp = request.form["otp"]
            
            user = users_col.find_one({"username": username})
            totp = pyotp.TOTP(user["mfa"])
            
            if not totp.verify(otp):
                flash("Invalid OTP!")
                return redirect("/dashboard")
            
            if not password:
                password = generate_password()
            
            if collection == "banking":
                banking_type = request.form.get("banking_type")
                if banking_type in ["debit", "credit"]:
                    card_number = request.form.get("card_number", "")
                    expiry = request.form.get("expiry", "")
                    cvv = request.form.get("cvv", "")
                    password = f"TYPE:{banking_type}|CARD:{card_number}|EXP:{expiry}|CVV:{cvv}"
                elif banking_type == "online":
                    banking_user = request.form.get("account", "")
                    banking_pass = request.form.get("password", "")
                    password = f"TYPE:{banking_type}|USER:{banking_user}|PASS:{banking_pass}"
            
            key = session["key"].encode()
            fernet = Fernet(key)
            encrypted_password = fernet.encrypt(password.encode())
            
            vault_col.insert_one({
                "username": username,
                "service": service,
                "account": account,
                "password": encrypted_password.decode(),
                "collection": collection,
                "timestamp": datetime.datetime.utcnow()
            })
            
            log_audit(username, "add_password", f"Added password for {service}")
            flash(f"Password added for {service}!")
            session["last_activity"] = time.time()
        
        elif action == "edit" and session.get("unlocked"):
            service = request.form["service"]
            account = request.form["account"]
            otp = request.form["otp"]
            password_type = request.form.get("password_type", "regular")
            
            user = users_col.find_one({"username": username})
            totp = pyotp.TOTP(user["mfa"])
            
            if not totp.verify(otp):
                flash("Invalid OTP!")
                return redirect("/dashboard")
            
            if password_type == "regular":
                new_password = request.form["new_password"]
            elif password_type in ("debit", "credit"):
                card_number = request.form["card_number"]
                expiry = request.form["expiry"]
                cvv = request.form["cvv"]
                new_password = f"TYPE:{password_type}|CARD:{card_number}|EXP:{expiry}|CVV:{cvv}"
            elif password_type == "online":
                banking_user = request.form["banking_username"]
                banking_pass = request.form["banking_password"]
                new_password = f"TYPE:online|USER:{banking_user}|PASS:{banking_pass}"
            else:
                new_password = request.form["new_password"]
            
            key = session["key"].encode()
            fernet = Fernet(key)
            encrypted_password = fernet.encrypt(new_password.encode())
            
            vault_col.update_one(
                {"username": username, "service": service, "account": account},
                {"$set": {"password": encrypted_password.decode()}}
            )
            
            log_audit(username, "edit_password", f"Edited password for {service}")
            flash(f"Password updated for {service}!")
            session["last_activity"] = time.time()
        
        elif action == "delete" and session.get("unlocked"):
            service = request.form["service"]
            account = request.form["account"]
            otp = request.form["otp"]
            
            user = users_col.find_one({"username": username})
            totp = pyotp.TOTP(user["mfa"])
            
            if not totp.verify(otp):
                flash("Invalid OTP!")
                return redirect("/dashboard")
            
            vault_col.delete_one({"username": username, "service": service, "account": account})
            log_audit(username, "delete_password", f"Deleted password for {service}")
            flash(f"Password deleted for {service}!")
            session["last_activity"] = time.time()
        
        elif action == "verify_view_otp" and session.get("unlocked"):
            otp = request.form["otp"]
            user = users_col.find_one({"username": username})
            totp = pyotp.TOTP(user["mfa"])
            
            if totp.verify(otp):
                session["otp_verified"] = True
                session["last_activity"] = time.time()
                flash("OTP verified! You can now view passwords.")
            else:
                flash("Invalid OTP!")
    
    vaults = {"banking": [], "social": [], "other": []}
    if session.get("unlocked"):
        key = session["key"].encode()
        fernet = Fernet(key)
        
        for collection in ["banking", "social", "other"]:
            items = vault_col.find({"username": username, "collection": collection})
            for item in items:
                try:
                    decrypted_password = fernet.decrypt(item["password"].encode()).decode()
                    vaults[collection].append({
                        "service": item["service"],
                        "account": item["account"],
                        "password": decrypted_password
                    })
                except Exception:
                    pass
    
    return render_template(
        "dashboard.html",
        unlocked=session.get("unlocked", False),
        unlocked_collections=session.get("unlocked_collections", {}),
        otp_verified=session.get("otp_verified", False),
        vaults=vaults
    )

@app.route('/logout')
def logout():
    log_audit(session.get("username", "unknown"), "logout", "User logged out")
    session.clear()
    return redirect("/")

@app.route('/api/extension-save', methods=['POST'])
def extension_save():
    if "username" not in session or not session.get("unlocked"):
        return jsonify({"error": "Not logged in or vault locked"}), 401
    
    data = request.json
    service = data.get("service", "")
    account = data.get("account", "")
    password = data.get("password", "")
    collection = data.get("collection", "other")
    
    if collection not in ["banking", "social", "other"]:
        collection = "other"
    
    key = session["key"].encode()
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    
    vault_col.insert_one({
        "username": session["username"],
        "service": service,
        "account": account,
        "password": encrypted_password.decode(),
        "collection": collection,
        "timestamp": datetime.datetime.utcnow()
    })
    
    log_audit(session["username"], "extension_save", f"Extension added password for {service} in {collection}")
    return jsonify({"success": True})

@app.route("/collection-search", methods=["POST"])
def collection_search():
    if "username" not in session or not session.get("unlocked"):
        return jsonify({"results": []})
    
    data = request.get_json()
    collection = data.get("collection")
    query = (data.get("query") or "").strip().lower()
    username = session["username"]
    
    if not session.get("unlocked_collections", {}).get(collection, False):
        return jsonify({"results": []})
    
    key = session["key"].encode()
    fernet = Fernet(key)
    results = []
    
    items = vault_col.find({"username": username, "collection": collection})
    for item in items:
        if query in item["service"].lower() or query in item["account"].lower():
            try:
                decrypted = fernet.decrypt(item["password"].encode()).decode()
                results.append({
                    "service": item["service"],
                    "account": item["account"],
                    "password": decrypted,
                    "id": str(item["_id"])
                })
            except Exception:
                pass
    
    session["last_activity"] = time.time()
    return jsonify({"results": results})

@app.route("/global-search-otp", methods=["POST"])
def global_search_otp():
    if "username" not in session:
        return jsonify({"success": False})
    
    data = request.get_json()
    otp = data.get("otp", "")
    
    user = users_col.find_one({"username": session["username"]})
    totp = pyotp.TOTP(user["mfa"])
    
    if totp.verify(otp):
        session["global_search_unlocked"] = True
        session["last_activity"] = time.time()
        return jsonify({"success": True})
    
    return jsonify({"success": False})

@app.route("/global-search", methods=["POST"])
def global_search():
    if not session.get("global_search_unlocked"):
        return jsonify({"results": []})
    
    data = request.get_json()
    query = data.get("query", "").lower()
    username = session["username"]
    
    key = session["key"].encode()
    fernet = Fernet(key)
    results = []
    
    for collection in ["banking", "social", "other"]:
        items = vault_col.find({"username": username, "collection": collection})
        for item in items:
            if query in item["service"].lower() or query in item["account"].lower():
                try:
                    decrypted = fernet.decrypt(item["password"].encode()).decode()
                    results.append({
                        "service": item["service"],
                        "account": item["account"],
                        "password": decrypted,
                        "collection": collection.title(),
                        "id": str(item["_id"])
                    })
                except Exception:
                    pass
    
    session["last_activity"] = time.time()
    return jsonify({"results": results})

@app.route('/unlock_collection', methods=["POST"])
def unlock_collection():
    if not session.get("unlocked"):
        return redirect("/dashboard")
    
    collection = request.form["collection"]
    otp = request.form["otp"]
    username = session["username"]
    
    user = users_col.find_one({"username": username})
    totp = pyotp.TOTP(user["mfa"])
    
    if totp.verify(otp):
        session["unlocked_collections"][collection] = True
        session["last_activity"] = time.time()
        log_audit(username, "unlock_collection", f"Unlocked {collection} collection")
        flash(f"{collection.capitalize()} collection unlocked!")
    else:
        flash("Invalid OTP!")
    
    return redirect("/dashboard")

@app.route('/relock_collection', methods=["POST"])
def relock_collection():
    collection = request.form["collection"]
    username = session.get("username", "unknown")
    
    session["unlocked_collections"][collection] = False
    log_audit(username, "relock_collection", f"Locked {collection} collection")
    flash(f"{collection.capitalize()} collection locked!")
    
    return redirect("/dashboard")

@app.route('/forgot-password', methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        step = request.form.get("step", "1")
        
        if step == "1":
            username = request.form["username"].strip().lower()
            question = request.form["security_question"]
            answer = request.form["security_answer"].lower().strip()
            
            user = users_col.find_one({"username": username})
            
            if not user:
                flash("User not found.")
                return render_template("forgot_password.html", step=1, questions=SECURITY_QUESTIONS)
            
            if user["question"] != question or user["answer"] != answer:
                flash("Security question or answer is incorrect.")
                return render_template("forgot_password.html", step=1, questions=SECURITY_QUESTIONS)
            
            session["reset_user"] = username
            return render_template("forgot_password.html", step=2, questions=SECURITY_QUESTIONS)
        
        elif step == "2":
            username = session.get("reset_user")
            user = users_col.find_one({"username": username})
            otp = request.form["otp"]
            
            totp = pyotp.TOTP(user["mfa"])
            if not totp.verify(otp):
                flash("Invalid OTP.")
                return render_template("forgot_password.html", step=2, questions=SECURITY_QUESTIONS)
            
            return render_template("forgot_password.html", step=3, questions=SECURITY_QUESTIONS)
        
        elif step == "3":
            username = session.get("reset_user")
            user = users_col.find_one({"username": username})
            super_secret_key_input = request.form.get("super_secret_key", "").strip()
            
            if super_secret_key_input != user.get("super_secret_key"):
                flash("Invalid Super Secret Key.")
                return render_template("forgot_password.html", step=3, questions=SECURITY_QUESTIONS)
            
            new_password = request.form["new_password"]
            
            def is_strong_password(pw, usern):
                e = []
                if len(pw) < 8:
                    e.append("at least 8 characters")
                if not any(c.isupper() for c in pw):
                    e.append("one uppercase")
                if not any(c.islower() for c in pw):
                    e.append("one lowercase")
                if not any(c.isdigit() for c in pw):
                    e.append("one number")
                if not any(c in "!@#$%^&*()_+-=[]{}|;:',./<>?/~`" for c in pw):
                    e.append("one special")
                if usern.lower() in pw.lower():
                    e.append("no username in password")
                return e
            
            issues = is_strong_password(new_password, username)
            if issues:
                flash("Weak password: must include " + ", ".join(issues))
                return render_template("forgot_password.html", step=3, questions=SECURITY_QUESTIONS)
            
            hashed_pw = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
            users_col.update_one({"username": username}, {"$set": {"password": hashed_pw}})
            
            log_audit(username, "reset_password", "Password reset successful")
            return render_template("reset_secret_choice.html")
        
        elif step == "4":
            choice = request.form.get("reset_secret")
            username = session.get("reset_user")
            
            if not username:
                flash("Session expired. Please login again.")
                return redirect("/login")
            
            if choice == "no":
                session.clear()
                flash("Password reset complete. You can now login.")
                return redirect("/login")
            
            if choice == "yes":
                new_secret = pyotp.random_base32()
                otp_uri = pyotp.TOTP(new_secret).provisioning_uri(name=username, issuer_name="ZeroTrustManager")
                users_col.update_one({"username": username}, {"$set": {"mfa": new_secret}})
                session["new_mfa_secret"] = new_secret
                return render_template("show_new_secret.html", otp_uri=otp_uri, secret=new_secret)
        
        elif step == "5":
            username = session.get("reset_user")
            new_secret = session.get("new_mfa_secret")
            otp_code = request.form.get("otp", "")
            
            totp = pyotp.TOTP(new_secret)
            if not totp.verify(otp_code):
                flash("Invalid OTP from authenticator. Try again.")
                otp_uri = pyotp.TOTP(new_secret).provisioning_uri(name=username, issuer_name="ZeroTrustManager")
                return render_template("show_new_secret.html", otp_uri=otp_uri, secret=new_secret)
            
            session.clear()
            flash("Password reset and new authenticator setup complete. Please login.")
            return redirect("/login")
    
    return render_template("forgot_password.html", step=1, questions=SECURITY_QUESTIONS)

@app.route('/delete-user', methods=["GET", "POST"])
def delete_user():
    if request.method == "POST":
        step = request.form.get("step", "1")
        
        if step == "1":
            username = request.form["username"].strip().lower()
            password = request.form["password"]
            question = request.form["security_question"]
            answer = request.form["security_answer"].lower().strip()
            
            user = users_col.find_one({"username": username})
            
            if not user:
                flash("User not found.")
                return render_template("delete_user.html", questions=SECURITY_QUESTIONS, step="1")
            
            if not bcrypt.checkpw(password.encode(), user["password"]):
                flash("Invalid password.")
                return render_template("delete_user.html", questions=SECURITY_QUESTIONS, step="1")
            
            if question != user["question"] or answer != user["answer"]:
                flash("Security question or answer is incorrect.")
                return render_template("delete_user.html", questions=SECURITY_QUESTIONS, step="1")
            
            return render_template("delete_user.html", step="2",
                                 username=username, password=password,
                                 security_question=question, security_answer=answer,
                                 questions=SECURITY_QUESTIONS)
        
        elif step == "2":
            username = request.form["username"]
            password = request.form["password"]
            question = request.form["security_question"]
            answer = request.form["security_answer"]
            otp = request.form["otp"]
            
            user = users_col.find_one({"username": username})
            
            if not user or not bcrypt.checkpw(password.encode(), user["password"]) or question != user["question"] or answer != user["answer"]:
                flash("Validation failed.")
                return render_template("delete_user.html", questions=SECURITY_QUESTIONS, step="1")
            
            totp = pyotp.TOTP(user["mfa"])
            if not totp.verify(otp):
                flash("Invalid OTP.")
                return render_template("delete_user.html", step="2",
                                     username=username, password=password,
                                     security_question=question, security_answer=answer,
                                     questions=SECURITY_QUESTIONS)
            
            return render_template("delete_user.html", step="3",
                                 username=username, password=password,
                                 security_question=question, security_answer=answer,
                                 otp=otp,
                                 questions=SECURITY_QUESTIONS)
        
        elif step == "3":
            username = request.form["username"]
            password = request.form["password"]
            question = request.form["security_question"]
            answer = request.form["security_answer"]
            otp = request.form["otp"]
            super_secret_key_input = request.form.get("super_secret_key", "").strip()
            
            user = users_col.find_one({"username": username})
            
            if not user or not bcrypt.checkpw(password.encode(), user["password"]) or question != user["question"] or answer != user["answer"]:
                flash("Validation failed.")
                return render_template("delete_user.html", questions=SECURITY_QUESTIONS, step="1")
            
            totp = pyotp.TOTP(user["mfa"])
            if not totp.verify(otp):
                flash("Invalid OTP.")
                return render_template("delete_user.html", step="2",
                                     username=username, password=password,
                                     security_question=question, security_answer=answer,
                                     questions=SECURITY_QUESTIONS)
            
            if super_secret_key_input != user.get("super_secret_key"):
                flash("Invalid Super Secret Key.")
                return render_template("delete_user.html", step="3",
                                     username=username, password=password,
                                     security_question=question, security_answer=answer,
                                     otp=otp,
                                     questions=SECURITY_QUESTIONS)
            
            vault_col.delete_many({"username": username})
            users_col.delete_one({"username": username})
            
            log_audit(username, "delete_user", "User account and vault deleted")
            flash("Account deleted successfully.")
            return redirect("/register")
    
    return render_template("delete_user.html", questions=SECURITY_QUESTIONS, step="1")

@app.route('/relock', methods=["POST"])
def relock():
    username = session.get("username", "unknown")
    session["unlocked"] = False
    session["unlocked_collections"] = {"banking": False, "social": False, "other": False}
    session["otp_verified"] = False
    log_audit(username, "vault_relock", "Vault was relocked manually")
    return redirect("/dashboard")

# Admin Routes
@app.route('/admin/choice')
def admin_choice():
    if "username" not in session or session.get("role") != "admin":
        return redirect("/login")
    
    return render_template("admin_choice.html")

@app.route('/admin/dashboard')
def admin_dashboard():
    if "username" not in session or session.get("role") != "admin":
        return redirect("/login")
    
    # Get statistics
    total_users = users_col.count_documents({})
    admin_users = users_col.count_documents({"role": "admin"})
    regular_users = users_col.count_documents({"role": {"$ne": "admin"}})
    total_vault_entries = vault_col.count_documents({})
    
    recent_activities = list(audit_logs_col.find({}).sort("timestamp", -1).limit(10))
    
    stats = {
        "total_users": total_users,
        "admin_users": admin_users,
        "regular_users": regular_users,
        "total_vault_entries": total_vault_entries,
        "recent_activities": recent_activities
    }
    
    return render_template("admin_dashboard.html", stats=stats)

@app.route('/admin/users')
def admin_users():
    if "username" not in session or session.get("role") != "admin":
        return redirect("/login")
    
    users = list(users_col.find({}, {"password": 0}))
    for user in users:
        vault_count = vault_col.count_documents({"username": user["username"]})
        user["vault_count"] = vault_count
    
    return render_template("admin_users.html", users=users)

@app.route('/admin/user/<username>')
def admin_user_detail(username):
    if "username" not in session or session.get("role") != "admin":
        return redirect("/login")
    
    user = users_col.find_one({"username": username})
    if not user:
        flash("User not found.")
        return redirect("/admin/users")
    
    vault_entries = list(vault_col.find({"username": username}))
    
    return render_template("admin_user_detail.html", user=user, vault_entries=vault_entries)

@app.route('/admin/delete-user/<username>', methods=["POST"])
def admin_delete_user(username):
    if "username" not in session or session.get("role") != "admin":
        return redirect("/login")
    
    if username == session["username"]:
        flash("You cannot delete your own admin account.")
        return redirect("/admin/users")
    
    user = users_col.find_one({"username": username})
    if not user:
        flash("User not found.")
        return redirect("/admin/users")
    
    if user.get("role") == "admin":
        flash("Cannot delete another admin account.")
        return redirect("/admin/users")
    
    vault_col.delete_many({"username": username})
    users_col.delete_one({"username": username})
    
    log_audit(session["username"], "admin_delete_user", f"Admin deleted user {username}")
    flash(f"User {username} and all their data deleted successfully.")
    
    return redirect("/admin/users")

@app.route('/admin/audit-logs')
def admin_audit_logs():
    if "username" not in session or session.get("role") != "admin":
        return redirect("/login")
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    logs = list(audit_logs_col.find({}).sort("timestamp", -1).skip((page-1)*per_page).limit(per_page))
    total_logs = audit_logs_col.count_documents({})
    
    return render_template("admin_audit_logs.html", logs=logs, page=page, total_logs=total_logs, per_page=per_page)

if __name__ == "__main__":
    app.run(debug=True)
