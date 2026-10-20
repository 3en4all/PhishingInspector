"""PyInstaller entry point for the PL build."""

from phishing_inspector.gui_app import main

if __name__ == "__main__":
    raise SystemExit(main("pl"))
