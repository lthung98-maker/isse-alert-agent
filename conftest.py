"""Put ``src`` on the path so the suite runs without an editable install."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent / "src"))
