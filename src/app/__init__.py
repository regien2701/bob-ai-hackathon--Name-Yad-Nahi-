"""Flask application factory."""

import os
from flask import Flask
from dotenv import load_dotenv

from app.config import DevelopmentConfig
from app.extensions import db, migrate


def create_app(config_object=None):
    """Create and configure the Flask application."""
    # Load .env file if present (harmless if absent)
    load_dotenv()

    app = Flask(__name__, instance_relative_config=False)

    # Load configuration
    if config_object is None:
        config_object = DevelopmentConfig
    app.config.from_object(config_object)

    # Ensure the instance folder exists so SQLite has a place to live
    os.makedirs(config_object.BASE_DIR, exist_ok=True)

    # Ensure the uploads folder exists
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    # Initialise extensions
    db.init_app(app)
    migrate.init_app(app, db)

    # Import models so Flask-Migrate / SQLAlchemy can discover them
    with app.app_context():
        import app.models as _models  # noqa: F401  — registers all ORM models
        db.create_all()    # creates tables if they do not exist yet

    # Register blueprints (stubs; populated in later sub-tasks)
    _register_blueprints(app)

    return app


def _register_blueprints(flask_app: Flask) -> None:
    """Register route blueprints.  Each blueprint is defined in its own module."""
    try:
        from app.routes.dashboard import dashboard_bp
        flask_app.register_blueprint(dashboard_bp)
    except ImportError:
        pass  # dashboard routes not yet implemented

    try:
        from app.routes.api import api_bp
        flask_app.register_blueprint(api_bp)
    except ImportError:
        pass  # API routes not yet implemented
