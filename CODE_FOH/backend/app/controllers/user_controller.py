import requests
from flask import Blueprint, request, jsonify, session
from werkzeug.security import check_password_hash, generate_password_hash
from ..db import get_db
import os
import base64
from .face_verification import verify_face
import sqlite3
import re
import pytz
import datetime
from datetime import datetime

DATABASE = "database.db"
user_bp = Blueprint('user', __name__)
RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')


@user_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()  # Get JSON data from the request
    username = data.get('username')
    password = data.get('password')
    recaptcha_response = data.get('recaptcha_response')

    # Verify reCAPTCHA response
    recaptcha_payload = {
        'secret': RECAPTCHA_SECRET_KEY,
        'response': recaptcha_response
    }
    recaptcha_verify_url = "https://www.google.com/recaptcha/api/siteverify"
    recaptcha_result = requests.post(
        recaptcha_verify_url, data=recaptcha_payload)
    recaptcha_json = recaptcha_result.json()

    if not recaptcha_json.get('success'):
        return jsonify({"error": "reCAPTCHA verification failed."}), 400

    # Check the credentials against the database
    try:
        db_conn = get_db()
        user = db_conn.execute(
            "SELECT * FROM user WHERE username = ?",
            (username,)
        ).fetchone()
        print(f"User: {user['totalCash']}")

        if user and check_password_hash(user['password'], password):
            session["username"] = username
            session["totalCash"] = user["totalCash"]
            session["user_id"] = user["id"]
            session.permanent = True  # Make session permanent if desired
            try:
                # # Get the local timezone
                # local_timezone = pytz.timezone('America/New_York')
                # current_time = datetime.now(
                #     local_timezone).strftime('%Y-%m-%d %H:%M:%S')

                # Insert with explicit timezone-aware timestamp
                db_conn.execute(
                    "INSERT INTO eventLog (id, totalCash, eventName, stockSold, stockBought) VALUES (?, ?, ?, NULL, NULL)",
                    (user["id"], user["totalCash"], "Logged on")
                )
                db_conn.commit()

            except Exception:
                print("Error adding login to eventLog")
                return jsonify({"error": "Error adding login to eventLog. Please try again."}), 500

            print("Session set: ", session)
            if username == "administration":
                return jsonify({"message": "Admin login successful!", "user": username}), 200
            else:
                return jsonify({"message": "User login successful!", "user": username, "totalCash": user["totalCash"], "user_id": user["id"]}), 200
        else:
            return jsonify({"error": "Invalid username or password!"}), 401

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": "Database connection error"}), 500


@user_bp.route('/logout', methods=['POST'])
def logout():
    try:
        # Retrieve user_id from session before clearing it
        print("Session: ", session)
        user_id = session.get("user_id")
        print(f"Logging out user with ID: {user_id}")
        # Log the logout event
        db_conn = get_db()
        user = db_conn.execute(
            "SELECT * FROM user WHERE id = ?",
            (user_id,)
        ).fetchone()
        if not user_id:
            return jsonify({"error": "No user is currently logged in!"}), 400

        # Get the current timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        try:

            db_conn.execute(
                "INSERT INTO eventLog (id, totalCash, eventName, stockSold, stockBought, date) VALUES (?, ?, ?, NULL, NULL, ?)",
                (user_id, user['totalCash'], "Logged out", timestamp)
            )
            db_conn.commit()
        except Exception as e:
            print(f"Error adding logout to eventLog: {e}")
            return jsonify({"error": "Error adding logout to eventLog. Please try again."}), 500

        # Clear the session
        session.clear()

        return jsonify({"message": "User logged out successfully!"}), 200

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": "An unexpected error occurred. Please try again later."}), 500


@user_bp.route('/register', methods=['POST'])
def register():
    if request.method == "POST":
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        photo_data = data.get('photoData')

        if len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400

        if not any(char.isdigit() for char in password):
            return jsonify({"error": "Password must contain at least one number"}), 400

        if not any(char in "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" for char in password):
            return jsonify({"error": "Password must contain at least one special character"}), 400

        if not username or not password:
            return jsonify({"error": "Username and password are required."}), 400

        db_conn = get_db()
        existing_user = db_conn.execute(
            "SELECT * FROM user WHERE username = ?",
            (username,)
        ).fetchone()
        if existing_user:
            return jsonify({"error": "Username already taken"}), 400

        hashed_password = generate_password_hash(password)

        try:
            if photo_data:
                photo_data = photo_data.split(",")[1]
                photo_bytes = base64.b64decode(photo_data)
                photo_filename = f"{username}.jpg"
                photo_path = os.path.join("uploads", photo_filename)

                os.makedirs("uploads", exist_ok=True)

                with open(photo_path, "wb") as f:
                    f.write(photo_bytes)

            db_conn.execute(
                "INSERT INTO user (username, password, totalCash, photo) VALUES (?, ?, ?, ?)",
                (username, hashed_password, 100000,
                 photo_path if photo_data else None)
            )
            db_conn.commit()
            return jsonify({"message": "User registered successfully!"}), 201

        except Exception as e:
            print(f"Error: {e}")
            return jsonify({"error": "Registration failed. Please try again."}), 500


@user_bp.route('/index', methods=['POST'])
def index():
    print("Session at index:", session)  # Check current session state
    # Get the username from the request body
    data = request.get_json()
    username = data.get("username")
    print("Check Username", username)

    if not username:
        return jsonify({"error": "User not authenticated"}), 403
    else:
        try:
            # Get the user's balance from the database
            db_conn = get_db()
            cursor = db_conn.execute(
                "SELECT totalCash FROM user WHERE username = ?", (username,))
            user = cursor.fetchone()
            if user:
                return jsonify({"totalCash": user["totalCash"]}), 200
            else:
                return jsonify({"error": "User not found"}), 404
        except Exception as e:
            print(f"Error: {e}")
            return jsonify({"error": "User not authenticated"}), 403


@user_bp.route('/admin', methods=['GET'])
def admin():
    username = session.get("username")
    return jsonify({"message": "Login successful!", 'username': username}), 200


@user_bp.route('/create_user', methods=['POST'])
def create_user():

    username = request.json.get("username")
    password = request.json.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # Validate length of username and password
    if len(username) < 3 or len(username) > 15:
        return jsonify({"error": "Username should be 1-15 characters in length"}), 400

    if len(password) < 8 or len(password) > 20:
        return jsonify({"error": "Password should be 8-20 characters in length"}), 400

    # Validate password requirements
    if not any(char.isdigit() for char in password):
        return jsonify({"error": "Password must contain at least one number"}), 400

    if not any(char in "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" for char in password):
        return jsonify({"error": "Password must contain at least one special character"}), 400

    db_conn = get_db()
    existing_user = db_conn.execute(
        "SELECT * FROM user WHERE username = ?",
        (username,)
    ).fetchone()

    if existing_user:
        return jsonify({"error": "Username already taken"}), 409

    hashed_password = generate_password_hash(
        password)  # Hash the password for security
    db_conn.execute(
        "INSERT INTO user (username, password, totalCash) VALUES (?, ?, ?)",
        (username, hashed_password, 100000),
    )
    db_conn.commit()

    return jsonify({"message": "User created successfully"}), 201


@user_bp.route('/delete_user', methods=['DELETE'])
def delete_user():
    username_to_delete = request.json.get("username")

    if not username_to_delete or username_to_delete == 'administration':
        return jsonify({"error": "Invalid operation"}), 400

    db_conn = get_db()
    db_conn.execute(
        "DELETE FROM user WHERE username = ?", (username_to_delete,)
    )
    db_conn.commit()

    return jsonify({"message": f"User '{username_to_delete}' deleted successfully"}), 200


@user_bp.route('/list', methods=['GET'])
def list_users():
    print("Listing users...")  # Debugging print
    db_conn = get_db()
    cursor = db_conn.execute(
        "SELECT username FROM user WHERE username != ?", ('administration',))
    users = [{"username": row["username"]} for row in cursor.fetchall()]
    return jsonify(users), 200


@user_bp.route('/face_recognition_login', methods=['POST'])
def face_recognition_login():
    data = request.get_json()
    username = data.get('username')
    photo_data = data.get('photoData')
    password = data.get('password')

    if not username or not photo_data:
        return jsonify({"error": "Username and photo data are required."}), 400

    try:
        db_conn = get_db()
        user = db_conn.execute(
            "SELECT * FROM user WHERE username = ?",
            (username,)
        ).fetchone()

        if not user:
            return jsonify({"error": "User not found."}), 404

        user_photo_path = user['photo']
        if not user_photo_path or not os.path.exists(user_photo_path):
            return jsonify({"error": "No photo found for this user."}), 404

        try:
            photo_data_decoded = base64.b64decode(photo_data.split(",")[1])
            with open("temp_user_photo.jpg", "wb") as temp_file:
                temp_file.write(photo_data_decoded)

            match = verify_face(user_photo_path, "temp_user_photo.jpg")

            if match:
                session["username"] = username
                session["totalCash"] = user["totalCash"]
                session["user_id"] = user["id"]
                session.permanent = True

                try:
                    db_conn.execute(
                        "INSERT INTO eventLog (id, totalCash, eventName, stockSold, stockBought) VALUES (?, ?, ?, NULL, NULL)",
                        (user["id"], user['totalCash'], "Logged on")
                    )
                    db_conn.commit()

                except Exception:
                    print("Error adding login to eventLog")
                    return jsonify({"error": "Error adding login to eventLog. Please try again."}), 500

                print("Session set: ", session)
                if username == "administration":

                    return jsonify({"message": "Admin login successful!", "success": True, "user": username}), 200

                else:
                    # return jsonify({"success": True, "message": "Face recognition successful!"}), 200
                    return jsonify({"user": username, "totalCash": user["totalCash"], "user_id": user["id"], "message": "Face recognition successful", "success": True}), 200

            else:
                return jsonify({"error": "Face recognition failed. Try again."}), 401

        except Exception as e:
            print(f"Error during face recognition: {e}")
            return jsonify({"error": "Error processing photo data."}), 500

    except Exception as e:
        print(f"Database error: {e}")
        return jsonify({"error": "An error occurred while fetching user data."}), 500
