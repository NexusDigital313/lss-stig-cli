"""Send lss-stig events to the system log (syslog/journald).

Best-effort: if the syslog socket isn't available, log calls become no-ops so
lss-stig still works on minimal environments (containers, chroots).
"""

from __future__ import annotations

import syslog as _syslog


_OPENED = False


def _open() -> None:
    global _OPENED
    if _OPENED:
        return
    try:
        _syslog.openlog(ident="lss-stig", logoption=_syslog.LOG_PID, facility=_syslog.LOG_AUTHPRIV)
        _OPENED = True
    except Exception:
        pass


def info(msg: str) -> None:
    _open()
    try:
        _syslog.syslog(_syslog.LOG_NOTICE, msg)
    except Exception:
        pass


def warn(msg: str) -> None:
    _open()
    try:
        _syslog.syslog(_syslog.LOG_WARNING, msg)
    except Exception:
        pass


def err(msg: str) -> None:
    _open()
    try:
        _syslog.syslog(_syslog.LOG_ERR, msg)
    except Exception:
        pass
