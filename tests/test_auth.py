def test_forgot_password_flow(client):
    username = "testuser_reset"
    password = "StrongPass123!"
    answer = "fluffy"
    question = "pet_name"
    secret = pyotp.random_base32()
    new_password = "NewPass456!"

    # Create the test user
    users_col.insert_one({
        "username": username,
        "password": bcrypt.hashpw(password.encode(), bcrypt.gensalt()),
        "mfa": secret,
        "question": question,
        "answer": answer.lower().strip()
    })

    # Step 1: Submit username, security question, answer, and old password
    response = client.post('/forgot-password', data={
        "step": "1",
        "username": username,
        "security_question": question,
        "security_answer": answer,
        "old_password": password
    }, follow_redirects=True)
    assert b"step=2" in response.data or b"OTP" in response.data

    # Step 2: Submit OTP
    otp_code = pyotp.TOTP(secret).now()
    response = client.post('/forgot-password', data={
        "step": "2",
        "otp": otp_code
    }, follow_redirects=True)
    assert b"step=3" in response.data or b"new_password" in response.data

    # Step 3: Submit new password
    response = client.post('/forgot-password', data={
        "step": "3",
        "new_password": new_password
    }, follow_redirects=True)
    assert b"reset_secret_choice" in response.data or b"reset secret" in response.data

    # If your app requires a final step, add it here

    # Step 4: Login with new password
    response = client.post('/login', data={
        "username": username,
        "password": new_password,
        "otp": pyotp.TOTP(secret).now()
    }, follow_redirects=True)
    assert b"Vault" in response.data

    users_col.delete_one({"username": username})
