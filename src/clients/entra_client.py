"""
Entra Client

Responsible for retrieving data from Microsoft Entra (Graph API).

Currently:
- Uses sample/mock data for testing

Future:
- Replace with real Graph API calls
"""

from utils.sample_data import sample_signins, sample_audits


class EntraClient:
    """Client for interacting with Entra data sources"""

    def get_signins(self):
        """Return sign-in events (mock data for now)"""
        return sample_signins()

    def get_audits(self):
        """Return audit events (mock data for now)"""
        return sample_audits()
