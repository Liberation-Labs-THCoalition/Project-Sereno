"""Where Sereno keeps its state: $SENTINEL_HOME, else ~/.sentinel. Read at call time, never at import."""
import os
from pathlib import Path


def sentinel_home() -> Path:
    return Path(os.environ.get("SENTINEL_HOME") or Path.home() / ".sentinel")
