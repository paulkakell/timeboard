from __future__ import annotations

import uvicorn

from .config import get_settings


def main() -> None:
    s = get_settings()
    uvicorn.run("app.main:app", host=s.app.host, port=int(s.app.port), log_level=s.logging.level.lower())


if __name__ == "__main__":
    main()
