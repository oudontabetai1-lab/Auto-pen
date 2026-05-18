"""Project-wide logging setup.

CLI / API entry points call :func:`configure_logging` once. Everything else
in the codebase uses ``logging.getLogger(__name__)`` and inherits the chosen
handler / level. Rich console output stays separate (it's the user-facing
UI), but everything that's currently a ``print`` or ``console.print`` of
diagnostic value should migrate to a logger.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime


class JsonFormatter(logging.Formatter):
    """Minimal newline-delimited JSON formatter (no external deps)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str = "INFO", fmt: str = "text") -> None:
    """Initialise the root logger.

    Args:
        level: any name accepted by :py:meth:`logging.Logger.setLevel`.
        fmt:   ``"text"`` (default) or ``"json"``.
    """
    root = logging.getLogger()
    # Replace any prior handlers — important when uvicorn pre-installs one.
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(sys.stderr)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
    root.addHandler(handler)
    root.setLevel(level.upper())
