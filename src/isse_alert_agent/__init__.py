"""ISSE Alert Agent: Azure Monitor alert intake as ServiceDesk requests.

Reads the alerts Azure is already holding and files one ServiceDesk request per new
one, carrying the alert's common alert schema payload so the ISSE pipeline can confirm
the machine and work the incident unchanged. The agent takes no action on any machine;
its only side effect is creating a request.
"""

from .agent import AlertAgent, RaisedIncident

__all__ = ["AlertAgent", "RaisedIncident"]
__version__ = "0.1.0"
