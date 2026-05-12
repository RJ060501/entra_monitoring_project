"""
Entra Client

This file is responsible for connecting to Microsoft Graph and pulling
Microsoft Entra data into the monitoring project.

It currently retrieves:
- Entra sign-in logs
- Entra directory audit logs

The rest of the application should not need to know how Microsoft Graph works.
This file handles authentication, API requests, and normalizing raw Graph data
into simpler dictionaries that the detector modules can understand.
"""

from datetime import datetime, timedelta, timezone
import requests
from azure.identity import ClientSecretCredential
import json


class EntraClient:
    """
    Client used to authenticate to Microsoft Graph and retrieve Entra logs.

    The client uses app-only authentication, meaning it authenticates as the
    registered application rather than as a signed-in user.

    Required .env values:
    - TENANT_ID
    - CLIENT_ID
    - CLIENT_SECRET

    Required API permission:
    - Microsoft Graph -> Application permission -> AuditLog.Read.All
    """

    def __init__(self, settings):
        # Store external configuration values and validate required secrets.
        self.settings = settings

        self.tenant_id = settings["tenant_id"]
        self.client_id = settings["client_id"]
        self.client_secret = settings["client_secret"]

        if not self.tenant_id or not self.client_id or not self.client_secret:
            raise ValueError(
                "Missing TENANT_ID, CLIENT_ID, or CLIENT_SECRET in environment."
            )

        # Create an Azure credential for app-only authentication.
        self.credential = ClientSecretCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )

        self.graph_scope = "https://graph.microsoft.com/.default"
        self.base_url = "https://graph.microsoft.com/v1.0"

    def _get_access_token(self):
        # Acquire a short-lived bearer token for Microsoft Graph.
        token = self.credential.get_token(self.graph_scope)
        return token.token

    def _get_headers(self):
        # Build the headers required for Graph API requests.
        return {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Content-Type": "application/json",
        }

    def _iso_utc_minutes_ago(self, minutes):
        # Convert a lookback interval into an ISO-formatted UTC timestamp.
        dt = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def get_signins(self, lookback_minutes=60):
        """
        Fetch sign-in audit logs from Graph and normalize them for detector use.

        Parameters:
            lookback_minutes: how far back to retrieve events.

        Returns:
            A list of simplified sign-in event dictionaries.
        """
        start_time = self._iso_utc_minutes_ago(lookback_minutes)

        # Build the Graph query to return sign-in records newer than start_time.
        url = (
            f"{self.base_url}/auditLogs/signIns"
            f"?$filter=createdDateTime ge {start_time}"
        )

        response = requests.get(url, headers=self._get_headers(), timeout=30)
        response.raise_for_status()

        data = response.json().get("value", [])
        normalized = []

        print(f"Fetched {len(data)} sign-in event(s) from Graph.")

        for event in data:
            # Normalize missing values and format fields consistently.
            user = event.get("userPrincipalName") or "Unknown"
            created = event.get("createdDateTime")

            status_obj = event.get("status", {}) or {}
            error_code = status_obj.get("errorCode")
            failure_reason = status_obj.get("failureReason") or ""

            # Determine whether the sign-in was successful.
            if error_code == 0:
                signin_status = "success"
            else:
                signin_status = "failure"

            location_obj = event.get("location", {}) or {}
            city = location_obj.get("city") or ""
            state = location_obj.get("state") or ""
            country = location_obj.get("countryOrRegion") or ""
            location = ", ".join([x for x in [city, state, country] if x]) or "Unknown"

            # Extract the event hour for rolling group or bucket analysis.
            hour = 12
            if created and "T" in created:
                try:
                    hour = int(created.split("T")[1][:2])
                except Exception:
                    # Keep default if the timestamp is malformed.
                    pass

            normalized.append(
                {
                    "id": event.get("id"),
                    "user": user,
                    "created_datetime": created,
                    "status": signin_status,
                    "status_error_code": error_code,
                    "failure_reason": failure_reason,
                    "hour": hour,
                    "location": location,
                    "ip_address": event.get("ipAddress") or "Unknown",
                    "app_display_name": event.get("appDisplayName") or "Unknown",
                    "conditional_access_status": event.get("conditionalAccessStatus"),
                    "risk_level_aggregated": event.get("riskLevelAggregated"),
                    "risk_detail": event.get("riskDetail"),
                    "new_location": False,
                    "raw": event,
                }
            )
            
        success_count = sum(1 for e in normalized if e.get("status") == "success")
        failure_count = sum(1 for e in normalized if e.get("status") == "failure")

        print(f"Normalized {len(normalized)} sign-in event(s).")
        print(f"Successful sign-ins: {success_count}")
        print(f"Failed sign-ins: {failure_count}")

        return normalized

    # Change to 15 later
    def get_audits(self, lookback_minutes=1440):
        """
        Fetch directory audit logs from Graph and normalize them for detector use.

        Parameters:
            lookback_minutes: how far back to retrieve events.

        Returns:
            A list of simplified audit event dictionaries.
        """
        start_time = self._iso_utc_minutes_ago(lookback_minutes)

        # Build the Graph query to return directory audit records newer than start_time.
        url = (
            f"{self.base_url}/auditLogs/directoryAudits"
            f"?$filter=activityDateTime ge {start_time}"
        )

        response = requests.get(url, headers=self._get_headers(), timeout=30)
        response.raise_for_status()

        data = response.json().get("value", [])
        print(f"Fetched {len(data)} audit event(s) from Graph.")
        normalized = []

        for event in data:
            # Some audit events store the initiator under initiatedBy.user.
            initiated_by = event.get("initiatedBy", {}) or {}
            user_obj = initiated_by.get("user", {}) or {}
            user = user_obj.get("userPrincipalName") or "Unknown"

            action = event.get("activityDisplayName") or "Unknown action"

            normalized.append(
                {
                    "id": event.get("id"),
                    "user": user,
                    "action": action,
                    "location": "Unknown",
                    "raw": event,
                }
            )

        return normalized