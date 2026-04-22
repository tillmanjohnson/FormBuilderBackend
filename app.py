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
    unset_jwt_cookies,
)
from bson import ObjectId
import certifi
import os
from dotenv import load_dotenv
import json

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["https://formbuilderfrontend-j9an.onrender.com", "http://localhost:5173", "http://127.0.0.1:5000"])

# CONFIG
app.config["JWT_SECRET_KEY"] = "super-secret-key"
app.config["JWT_TOKEN_LOCATION"] = ["cookies", "headers"]
# app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
# app.config["JWT_COOKIE_SAMESITE"] = "None"

# Check if we are running on the live server or locally
is_production = os.environ.get("FLASK_ENV") == "production"

app.config["JWT_COOKIE_SECURE"] = is_production
app.config["JWT_COOKIE_SAMESITE"] = "None" if is_production else "Lax"

jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# MONGODB SETUP
load_dotenv()
mongo_connection = os.environ.get("mongo_connection")
mongodb = MongoClient(mongo_connection, tlsCAFile=certifi.where())

db = mongodb["FormBuilderDB"]
messages = db["messages"]
users = db["users"]
form_submissions = db["form-submissions"]
built_forms = db["built-forms"]

# ---------------- ROUTES ---------------- #


@app.route("/")
def home():
    return "API running"


# REGISTER
@app.route("/register", methods=["POST"])
def register():
    data = request.json

    if (
        not data
        or "email" not in data
        or "password" not in data
        or "organization" not in data
    ):
        return jsonify({"error": "Email, password, and organization required"}), 400

    email = data["email"].strip().lower()
    password = data["password"]
    organization = data["organization"].strip().lower()

    if users.find_one({"email": email}):
        return jsonify({"error": "User already exists"}), 400

    if users.find_one({"organization": organization}):
        return jsonify({"error": "Organization already has an admin"}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")

    users.insert_one(
        {
            "email": email,
            "password": hashed_pw,
            "organization": organization,
            "role": "admin",
        }
    )

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

    access_token = create_access_token(
        identity=json.dumps(
            {"user_id": str(user["_id"]), "organization": user["organization"]}
        )
    )

    response = jsonify(
        {"msg": "Login successful",
         "organization": user["organization"],
         "access_token": access_token } # ← ADD THIS}
    )
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

    return jsonify(
        {"msg": f"Welcome {user['email']}", "organization": identity["organization"]}
    )


# route for creating a built form, this is where the frontend will send the form data to be stored in the db
@app.route("/built-forms", methods=["POST"])
@jwt_required()
def create_built_form():
    try:
        data = request.json
        if not data or "id" not in data or "fields" not in data:
            return jsonify({"error": "Invalid form data"}), 400

        # 2. GET IDENTITY FROM SECURE TOKEN
        identity = json.loads(get_jwt_identity())

        # 3. FORCE THE ORGANIZATION TO MATCH THE LOGGED-IN ADMIN
        data["organization"] = identity["organization"]

        # --- NEW: UNIQUENESS CHECK ---
        # Check if a form with this exact generated ID already exists
        existing_form = built_forms.find_one({"id": data["id"]})
        if existing_form:
            return jsonify({"error": "A form with this title already exists. Please choose a different title."}), 409

        built_forms.insert_one(data)
        return jsonify({"message": "Form created successfully"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# SUBMIT FORM
@app.route("/submit-form", methods=["POST"])
def submit_form():
    try:
        data = request.json

        # Expect the frontend to include organization
        if not data or "responses" not in data or "organization" not in data:
            return jsonify({"error": "Invalid form submission"}), 400

        document = {
            "formId": data.get("formId", "unknown"),
            "responses": data["responses"],
            "organization": data["organization"],  # from frontend
        }

        form_submissions.insert_one(document)

        return jsonify({"message": "Form submitted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# GET FORM SUBMISSIONS
@app.route("/form-submissions", methods=["GET"])
@jwt_required()
def get_form_submissions():
    try:
        identity = json.loads(get_jwt_identity())
        org_name = identity["organization"]

        org_forms = list(form_submissions.find({"organization": org_name}))

        for form in org_forms:
            form["_id"] = str(form["_id"])

        return jsonify(org_forms), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/form-submissions/<id>", methods=["PUT"])
@jwt_required()
def update_form_submission(id):
    try:
        data = request.json
        identity = json.loads(get_jwt_identity())
        org_name = identity["organization"]

        formId = data.get("formId")
        responses = data.get("responses", {})

        result = form_submissions.update_one(
            {"_id": ObjectId(id), "organization": org_name},
            {"$set": {"formId": formId, "responses": responses}},
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
    return jsonify({"logged_in": True, "organization": identity["organization"]}), 200


# LOGOUT
@app.route("/logout", methods=["POST"])
def logout():
    response = jsonify({"msg": "Logout successful"})
    unset_jwt_cookies(response)
    return response


# GET BUILT-FORMS LIST (for forms list on landing page upon login)
@app.route("/built-forms-list", methods=["GET"])
@jwt_required()
def get_built_forms_list():
    try:
        identity = json.loads(get_jwt_identity())
        org_name = identity["organization"]

        org_forms = list(built_forms.find({"organization": org_name}))

        for form in org_forms:
            form["_id"] = str(form["_id"])

        return jsonify(org_forms), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# two identical api paths might cause issues
# okay changed previous /built-forms to /built-forms-list
@app.route("/built-forms", methods=["GET"])
def get_built_forms():
    built_forms_collection = db["built-forms"]
    results = []

    for form in built_forms_collection.find():
        form["_id"] = str(form["_id"])  # convert ObjectId to string
        results.append(form)

    return jsonify(results)


if __name__ == "__main__":
    app.run(debug=True)
