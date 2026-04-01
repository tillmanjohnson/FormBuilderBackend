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
    unset_jwt_cookies
)
from bson import ObjectId
import certifi
import os
from dotenv import load_dotenv
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
built_forms = db["built-forms"]

# ---------------- ROUTES ---------------- #

@app.route("/")
def home():
    return "API running"


# REGISTER
@app.route("/register", methods=["POST"])
def register():
    data = request.json

    if not data or "email" not in data or "password" not in data or "organization" not in data:
        return jsonify({"error": "Email, password, and organization required"}), 400

    email = data["email"].strip().lower()
    password = data["password"]
    organization = data["organization"].strip().lower()

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

    return jsonify({"msg": "User created"}), 201


# LOGIN
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

    response = jsonify({
        "msg": "Login successful",
        "organization": user["organization"]})
    set_access_cookies(response, access_token)

    return response


# DASHBOARD
@app.route("/dashboard")
@jwt_required()
def dashboard():
    identity = json.loads(get_jwt_identity())

    user = users.find_one({"_id": ObjectId(identity["user_id"])})

    if not user:
        return jsonify({"msg": "User not found"}), 404

    return jsonify({
        "msg": f"Welcome {user['email']}",
        "organization": identity["organization"]
    })


# SUBMIT FORM
@app.route("/submit-form", methods=["POST"])
@jwt_required()
def submit_form():
    try:
        data = request.json
        identity = json.loads(get_jwt_identity())

        if not data or "answers" not in data:
            return jsonify({"error": "Invalid form submission"}), 400

        document = {
            "formId": data.get("formId", "unknown"),
            "responses": data["responses"],
            "organization": identity["organization"]
        }

        forms.insert_one(document)

        return jsonify({"message": "Form submitted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# GET FORM SUBMISSIONS
@app.route("/forms", methods=["GET"])
@jwt_required()
def get_forms():
    try:
        identity = json.loads(get_jwt_identity())
        org_name = identity["organization"]

        org_forms = list(forms.find({
            "organization": org_name
        }))

        for form in org_forms:
            form["_id"] = str(form["_id"])

        return jsonify(org_forms), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/forms/<id>", methods=["PUT"])
@jwt_required()
def update_form(id):
    try:
        data = request.json
        identity = json.loads(get_jwt_identity())
        org_name = identity["organization"]

        formId = data.get("formId")
        responses = data.get("responses", {})

        result = forms.update_one(
            {"_id": ObjectId(id), "organization": org_name},
            {"$set": {"formId": formId, "responses": responses}}
        )

        if result.matched_count == 0:
            return jsonify({"error": "Form not found"}), 404

        return jsonify({"message": "Updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# CHECK AUTH
@app.route("/check-auth", methods=["GET"])
@jwt_required()
def check_auth():
    identity = json.loads(get_jwt_identity())
    return jsonify({
        "logged_in": True,
        "organization": identity["organization"]
    }), 200


# LOGOUT
@app.route("/logout", methods=["POST"])
def logout():
    response = jsonify({"msg": "Logout successful"})
    unset_jwt_cookies(response)
    return response

# GET BUILT-FORMS
@app.route("/built-forms", methods=["GET"])
@jwt_required()
def get_built_forms():
    try:
        identity = json.loads(get_jwt_identity())
        org_name = identity["organization"]

        org_forms = list(built_forms.find({
            "organization": org_name
        }))

        for form in org_forms:
            form["_id"] = str(form["_id"])

        return jsonify(org_forms), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

#two identical api paths might cause issues
@app.route("/built-forms", methods=["GET"])
def get_built_forms():
    built_forms_collection = db["built-forms"]
    results = []

    for form in built_forms_collection.find():
        form["_id"] = str(form["_id"])  # convert ObjectId to string
        results.append(form)

    return jsonify(results)


@app.route("/forms", methods=["GET"])
###@jwt_required()
def get_forms():
    results = []

    for form in forms.find():
        form["_id"] = str(form["_id"])
        results.append(form)

    return jsonify(results)


if __name__ == "__main__":
    app.run(debug=True)

