import sys
from pathlib import Path

import pytest

# Make the src/ package importable without installation.
SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from honeynet.database import Database  # noqa: E402
from honeynet.detection.engine import DetectionEngine  # noqa: E402
from honeynet.pipeline import Pipeline  # noqa: E402


@pytest.fixture
def db():
    database = Database(":memory:")
    yield database
    database.close()


@pytest.fixture
def engine():
    return DetectionEngine()


@pytest.fixture
def pipeline(db, engine):
    return Pipeline(db=db, engine=engine)
