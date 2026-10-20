"""English entry point. The GUI itself lives in gui_app and is shared by both languages."""

from __future__ import annotations

from . import gui_app
from .gui_app import (  # noqa: F401  (re-exported for callers and tests)
    SUPPORTED_EXTENSIONS,
    AppRatingDialog,
    DropArea,
    extract_supported_drop_path,
    mark_app_rating_prompted,
    should_prompt_for_app_rating,
    submit_app_rating_cloud,
    submit_scan_feedback_cloud,
)


class MainWindow(gui_app.MainWindow):
    def __init__(self) -> None:
        super().__init__("en")


def main() -> int:
    return gui_app.main("en")


if __name__ == "__main__":
    raise SystemExit(main())
