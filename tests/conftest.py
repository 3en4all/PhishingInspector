import pytest


@pytest.fixture(autouse=True)
def _no_rating_dialog(monkeypatch):
    """GUI closeEvent opens a modal rating dialog; never block unattended test runs."""
    for modname in ("phishing_inspector.gui_app", "phishing_inspector.gui_app_en"):
        try:
            mod = __import__(modname, fromlist=["x"])
        except Exception:
            continue
        monkeypatch.setattr(mod, "should_prompt_for_app_rating", lambda *a, **k: False, raising=False)
