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

app = Flask(__name__)
CORS(app, supports_credentials=True)

# CONFIG
app.config["JWT_SECRET_KEY"] = "super-secret-key"
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False
app.config["JWT_COOKIE_CSRF_PROTECT"] = False

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

    if not data or "email" not in data or "password" not in data:
        return jsonify({"error": "Email and password required"}), 400

    # Check if user already exists
    if users.find_one({"email": data["email"]}):
        return jsonify({"error": "User already exists"}), 400

    hashed_pw = bcrypt.generate_password_hash(data["password"]).decode("utf-8")

    users.insert_one({"email": data["email"], "password": hashed_pw})

    return jsonify({"msg": "User created"}), 201


# LOGIN ENDPOINT
@app.route("/login", methods=["POST"])
def login():
    data = request.json

    if not data or "email" not in data or "password" not in data:
        return jsonify({"error": "Email and password required"}), 400

    user = users.find_one({"email": data["email"]})

    if not user or not bcrypt.check_password_hash(user["password"], data["password"]):
        return jsonify({"msg": "Bad credentials"}), 401

    access_token = create_access_token(identity=str(user["_id"]))

    response = jsonify({"msg": "Login successful"})
    set_access_cookies(response, access_token)

    return response


# PROTECTED ROUTE
@app.route("/dashboard")
@jwt_required()
def dashboard():
    user_id = get_jwt_identity()

    user = users.find_one({"_id": ObjectId(user_id)})

    if not user:
        return jsonify({"msg": "User not found"}), 404

    return jsonify({"msg": f"Welcome {user['email']}"})


# EXISTING/TEST ROUTES
@app.route("/submit", methods=["POST"])
@jwt_required()
def submit_text():
    data = request.json

    if not data or "text" not in data:
        return jsonify({"error": "No text provided"}), 400

    messages.insert_one({"text": data["text"]})

    return jsonify({"message": "Saved successfully!"})


@app.route("/test-db")
def test_db():
    try:
        mongodb.admin.command("ping")
        return jsonify({"status": "Connected to MongoDB"})
    except Exception as e:
        return jsonify({"status": "Connection failed", "error": str(e)})


@app.route("/submit-form", methods=["POST"])
# @jwt_required()
def submit_form():
    try:
        data = request.json
        # user_id = get_jwt_identity()

        if not data or "answers" not in data:
            return jsonify({"error": "Invalid form submission"}), 400

        document = {
            "formId": data.get("formId", "unknown"),
            "answers": data["answers"],
        }

        forms.insert_one(document)

        return jsonify({"message": "Form submitted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/forms", methods=["GET"])
@jwt_required()
def get_forms():
    try:
        all_forms = list(forms.find())

        for form in all_forms:
            form["_id"] = str(form["_id"])

        return jsonify(all_forms), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
