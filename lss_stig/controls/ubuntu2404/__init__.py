"""Control implementations for the Canonical Ubuntu 24.04 LTS STIG."""

from lss_stig.controls.ubuntu2404 import (  # noqa: F401
    aide, audit, auth, boot, filesystem, gnome, packages, services, ssh, system, timesync,
)
