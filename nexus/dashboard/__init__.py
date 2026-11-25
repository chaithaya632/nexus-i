"""NEXUS Dashboard — FastAPI web interface (optional dependency)."""

try:
    from nexus.dashboard.app import DashboardApp, create_app, run_dashboard
    __all__ = ["DashboardApp", "create_app", "run_dashboard"]
except ImportError:
    # FastAPI not installed — dashboard unavailable
    __all__ = []
