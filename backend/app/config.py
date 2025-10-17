from dotenv import load_dotenv
import os

load_dotenv()  # This loads the .env file into environment variables

from urllib.parse import quote_plus

username = quote_plus(os.environ.get("MONGO_USER"))
password = quote_plus(os.environ.get("MONGO_PASS"))

MONGO_URI = f"mongodb+srv://{username}:{password}@cluster0.hbe1q74.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"