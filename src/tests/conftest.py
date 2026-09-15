"""pytest configuration — ensures the ``src/`` directory is on sys.path so that
``app.*`` modules can be imported without installing the package.
"""

import os
import sys

_SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)
