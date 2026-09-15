"""Entry point — run with: python run.py"""

import os
import sys

# Make sure `src/` is on the path so `app` is importable when running from repo root
sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv

load_dotenv()

from app import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("APP_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
