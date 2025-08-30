import pytest
import pyotp
import bcrypt

def test_forgot_password_flow(client):
    username = "testuser_reset"
    password = "StrongPass123!"
    answer = "fluffy"
    question = "pet_name"
    secret = pyotp.random_base32()
    new_password = "NewPass456!"
    super_secret_key = "test_super_secret_key"

    # Create the test user
    users_col.insert_one({
        "username": username,
        "password": bcrypt.hashpw(password.encode(), bcrypt.gensalt()),
        "mfa": secret,
        "question": question,
        "answer": answer.lower().strip(),
        "super_secret_key": super_secret_key
    })

    # Step 1: Submit username, security question, and answer
    response = client.post('/forgot-password', data={
        "step": "1",
        "username": username,
        "security_question": question,
        "security_answer": answer
    }, follow_redirects=True)
    assert b"step=2" in response.data or b"OTP" in response.data

    # Step 2: Submit OTP
    otp_code = pyotp.TOTP(secret).now()
    response = client.post('/forgot-password', data={
        "step": "2",
        "otp": otp_code
    }, follow_redirects=True)
    assert b"step=3" in response.data or b"super_secret_key" in response.data

    # Step 3: Submit super secret key and new password
    response = client.post('/forgot-password', data={
        "step": "3",
        "super_secret_key": super_secret_key,
        "new_password": new_password
    }, follow_redirects=True)
    assert b"reset_secret_choice" in response.data or b"reset secret" in response.data

    # Step 4: Choose not to reset MFA secret
    response = client.post('/forgot-password', data={
        "step": "4",
        "reset_secret": "no"
    }, follow_redirects=True)
    assert b"login" in response.data.lower()

    # Test login with new password
    response = client.post('/login', data={
        "username": username,
        "password": new_password,
        "security_question": question,
        "security_answer": answer,
        "otp": pyotp.TOTP(secret).now()
    }, follow_redirects=True)
    assert b"unlock" in response.data.lower() or b"vault" in response.data.lower()

    # Cleanup
    users_col.delete_one({"username": username})
