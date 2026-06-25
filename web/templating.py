from pathlib import Path

from starlette.templating import Jinja2Templates

from web.utils import _days_ago, _ensure_utc, timeago, normalize_risk_signal

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _timeago_class(dt) -> str:
    if dt is None:
        return "never"
    days = _days_ago(dt)
    if days < 30:
        return "good"
    if days < 90:
        return "warn"
    return "bad"


# Custom filters
templates.env.filters["timeago"] = timeago
templates.env.filters["timeago_class"] = _timeago_class
templates.env.filters["normalize_risk"] = normalize_risk_signal
