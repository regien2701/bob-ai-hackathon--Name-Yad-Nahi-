"""Application configuration — all values read from environment variables."""

import os


class DevelopmentConfig:
    # Flask core
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")
    DEBUG = True

    # SQLite database stored under src/instance/
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "instance"))
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(BASE_DIR, "threats.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # IBM watsonx.ai (optional)
    WATSONX_API_KEY = os.environ.get("WATSONX_API_KEY", "")
    WATSONX_PROJECT_ID = os.environ.get("WATSONX_PROJECT_ID", "")
    WATSONX_URL = os.environ.get("WATSONX_URL", "https://us-south.ml.cloud.ibm.com")
    WATSONX_MODEL_ID = os.environ.get("WATSONX_MODEL_ID", "ibm/granite-13b-instruct-v2")

    # Scoring thresholds
    SCORE_HIGH_THRESHOLD = int(os.environ.get("SCORE_HIGH_THRESHOLD", 70))
    SCORE_MEDIUM_THRESHOLD = int(os.environ.get("SCORE_MEDIUM_THRESHOLD", 40))

    # Correlation engine
    CORRELATION_WINDOW_HOURS = int(os.environ.get("CORRELATION_WINDOW_HOURS", 2))

    # False-positive allowlist (comma-separated IPs / CIDRs)
    FP_WHITELIST_IPS = os.environ.get("FP_WHITELIST_IPS", "127.0.0.1,10.0.0.1")

    # Internal scanner CIDR (alerts from these IPs are soft-flagged)
    INTERNAL_SCANNER_CIDR = os.environ.get("INTERNAL_SCANNER_CIDR", "10.0.0.0/8")

    # Upload folder (temp storage before ingest)
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "..", "uploads")


class TestConfig:
    """Configuration for the pytest test suite — uses an in-memory SQLite database."""

    SECRET_KEY = "test-secret"
    TESTING = True
    DEBUG = False
    WTF_CSRF_ENABLED = False

    # In-memory SQLite — no file created, wiped when connection closes
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "instance"))
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # watsonx — disabled in tests (template fallback is used)
    WATSONX_API_KEY = ""
    WATSONX_PROJECT_ID = ""
    WATSONX_URL = "https://us-south.ml.cloud.ibm.com"
    WATSONX_MODEL_ID = "ibm/granite-13b-instruct-v2"

    # Scoring thresholds
    SCORE_HIGH_THRESHOLD = 70
    SCORE_MEDIUM_THRESHOLD = 40

    # Correlation engine
    CORRELATION_WINDOW_HOURS = 2

    # False-positive detection
    FP_WHITELIST_IPS = "127.0.0.1,10.0.0.1"
    INTERNAL_SCANNER_CIDR = "10.0.0.0/8"

    # Upload folder
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "..", "uploads")
