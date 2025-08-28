from pymongo import MongoClient
import bcrypt
import pyotp
import secrets

# Use your actual MongoDB connection string here:
client = MongoClient("mongodb+srv://admin:shubhamsaini11@zerotrust.dgubcw7.mongodb.net/zerotrust?retryWrites=true&w=majority&appName=zerotrust")
db = client["zerotrust"]
users_col = db["users"]

username = "admin"
password = "AdminStrongPassword123!"

hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
mfa_secret = pyotp.random_base32()
super_secret_key = secrets.token_hex(16)

admin_user = {
    "username": username,
    "password": hashed_pw,
    "mfa": mfa_secret,
    "question": "pet_name",
    "answer": "adminpet",
    "super_secret_key": super_secret_key,
    "role": "admin",
    "failed_attempts": 0,
    "lockout_until": None
}

# Check if admin already exists
if users_col.find_one({"username": username}):
    print("❌ Admin user already exists!")
else:
    users_col.insert_one(admin_user)
    print("✅ Admin user created successfully!")
    print(f"Username: {username}")
    print(f"Password: {password}")
    print(f"MFA secret (use this in your authenticator app): {mfa_secret}")
    print(f"Super Secret Key: {super_secret_key}")
    print("\n🔒 IMPORTANT: Save these credentials securely!")

client.close()
