from flask import Flask
from flask_pymongo import PyMongo
from flask_cors import CORS
from .config import MONGO_URI
from .routes import routes

mongo = PyMongo()

def create_app():
    print("Starting Flask App...")  # Debug

    app = Flask(__name__)
    app.config["MONGO_URI"] = MONGO_URI

    try:
        mongo.init_app(app)
        print("MongoDB initialized successfully.")
    except Exception as e:
        print("❌ MongoDB initialization failed:", e)

    CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})  # Allow all routes from localhost:3000

    try:
        app.register_blueprint(routes)
        print("Blueprint registered successfully.")
    except Exception as e:
        print("❌ Blueprint registration failed:", e)

    return app