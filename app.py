from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import certifi
import os
from dotenv import load_dotenv

app = Flask(__name__)
CORS(app)

load_dotenv()
mongo_connection = os.environ.get("mongo_connection")
mongodb = MongoClient(mongo_connection,
                     tlsCAFile=certifi.where()
                     )

db = mongodb["FormBuilderDB"]
messages = db["messages"]

@app.route("/")
def home():
    return "API running"

@app.route("/submit", methods=["POST"])
def submit_text():
    data = request.json

    if not data or "text" not in data:
        return jsonify({"error": "No text provided"}), 400


    messages.insert_one({"text": data["text"]})

    return jsonify({"message": "Saved successfully!"})

@app.route("/test-db")
def test_db():
    try:
        mongodb.admin.command('ping')
        return jsonify({"status": "Connected to MongoDB"})
    except Exception as e:
        return jsonify({"status": "Connection failed", "error": str(e)})


if __name__ == "__main__":
    app.run(debug=True)


