from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    set_access_cookies,
)
from bson import ObjectId
import certifi
import os
from dotenv import load_dotenv
from flask_jwt_extended import unset_jwt_cookies
import json

app = Flask(__name__)
CORS(
    app,
    supports_credentials=True,
    origins=["http://localhost:5173"]
)

# CONFIG
app.config["JWT_SECRET_KEY"] = "super-secret-key"
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
app.config["JWT_COOKIE_SAMESITE"] = "Lax"

jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# MONGODB SETUP

load_dotenv()
mongo_connection = os.environ.get("mongo_connection")
mongodb = MongoClient(mongo_connection, tlsCAFile=certifi.where())

db = mongodb["FormBuilderDB"]
messages = db["messages"]
users = db["users"]
forms = db["forms"]

# ROUTES


@app.route("/")
def home():
    return "API running"


# REGISTER ENDPOINT
@app.route("/register", methods=["POST"])
def register():
    data = request.json

    if not data or "email" not in data or "password" not in data or "organization" not in data:
        return jsonify({"error": "Email, password, and organization required"}), 400
    email = data["email"].strip().lower()
    password = data["password"]
    organization = data["organization"].strip().lower()

    # Check if user already exists
    if users.find_one({"email": email}):
        return jsonify({"error": "User already exists"}), 400

    if users.find_one({"organization": organization}):
        return jsonify({"error": "Organization already has an admin"}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")

    users.insert_one({
        "email": email,
        "password": hashed_pw,
        "organization": organization,
        "role": "admin"
    })

    return jsonify({
        "msg": "User created",
        "email": email,
        "Organization": organization
    }), 201


# LOGIN ENDPOINT
@app.route("/login", methods=["POST"])
def login():
    data = request.json

    if not data or "email" not in data or "password" not in data:
        return jsonify({"error": "Email and password required"}), 400
    email = data["email"].strip().lower()

    user = users.find_one({"email": email})

    if not user or not bcrypt.check_password_hash(user["password"], data["password"]):
        return jsonify({"msg": "Bad credentials"}), 401

    access_token = create_access_token(identity=json.dumps({
        "user_id": str(user["_id"]),
        "organization": user["organization"]
    }))

    response = jsonify({"msg": "Login successful"})
    set_access_cookies(response, access_token)

    return response


# PROTECTED ROUTE
@app.route("/dashboard")
@jwt_required()
def dashboard():
    identity = get_jwt_identity()

    user = users.find_one({"_id": ObjectId(identity["user_id"])})

    if not user:
        return jsonify({"msg": "User not found"}), 404

    return jsonify({
        "msg": f"Welcome {user['email']}",
        "organization": identity["organization"]
    })


# EXISTING/TEST ROUTES
@app.route("/submit", methods=["POST"])
@jwt_required()
def submit_text():
    data = request.json
    identity = get_jwt_identity()

    if not data or "text" not in data:
        return jsonify({"error": "No text provided"}), 400

    messages.insert_one({
        "text": data["text"],
        "organization": identity["organization"]
    })

    return jsonify({"message": "Saved successfully!"})


@app.route("/test-db")
def test_db():
    try:
        mongodb.admin.command("ping")
        return jsonify({"status": "Connected to MongoDB"})
    except Exception as e:
        return jsonify({"status": "Connection failed", "error": str(e)})


@app.route("/submit-form", methods=["POST"])
@jwt_required()
def submit_form():
    try:
        data = request.json
        identity = get_jwt_identity()

        if not data or "answers" not in data:
            return jsonify({"error": "Invalid form submission"}), 400

        document = {
            "formId": data.get("formId", "unknown"),
            "answers": data["answers"],
            "organization": identity["organization"]
        }

        forms.insert_one(document)

        return jsonify({"message": "Form submitted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/forms", methods=["GET"])
@jwt_required()
def get_forms():
    try:
        identity = json.loads(get_jwt_identity())  # parse the JSON string back to dict
        org_name = identity["organization"]

        org_forms = list(forms.find({
            "organization": org_name
        }))

        for form in org_forms:
            form["_id"] = str(form["_id"])

        return jsonify(org_forms), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/check-auth", methods=["GET"])
@jwt_required()
def check_auth():
    user_id = get_jwt_identity()
    return jsonify({"logged_in": True, "user_id": user_id}), 200

@app.route("/logout", methods=["POST"])
def logout():
    response = jsonify({"msg": "Logout successful"})
    unset_jwt_cookies(response)
    return response

if __name__ == "__main__":
    app.run(debug=True)
