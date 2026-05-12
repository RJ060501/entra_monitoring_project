"""
Microsoft 365 Audit Client

Retrieves Microsoft 365 unified audit events from the Office 365
Management Activity API.

Used for Exchange/mailbox activity such as:
- New-InboxRule
- Set-InboxRule
- Remove-InboxRule
- Set-Mailbox
"""

from datetime import datetime, timedelta, timezone
import requests
from azure.identity import ClientSecretCredential


class M365AuditClient:
    """
    Client for talking to the Office 365 Management Activity API.

    This client authenticates using app-only Azure credentials and retrieves
    Exchange audit data in the form of content blob URLs. It also normalizes
    raw audit records into simpler dictionaries used by the rest of the app.
    """

    def __init__(self, settings):
        # Store configuration settings and validate required M365 secrets.
        self.settings = settings

        self.tenant_id = settings["m365_tenant_id"]
        self.client_id = settings["m365_client_id"]
        self.client_secret = settings["m365_client_secret"]

        if not self.tenant_id or not self.client_id or not self.client_secret:
            raise ValueError(
                "Missing M365_TENANT_ID, M365_CLIENT_ID, or M365_CLIENT_SECRET."
            )

        # Create Azure credentials for app-only authentication.
        self.credential = ClientSecretCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )

        self.scope = "https://manage.office.com/.default"
        self.base_url = (
            f"https://manage.office.com/api/v1.0/{self.tenant_id}/activity/feed"
        )

    def _get_access_token(self):
        # Acquire a bearer token for the Office 365 Management Activity API.
        token = self.credential.get_token(self.scope)
        return token.token

    def _get_headers(self):
        # Return the standard headers for all API requests.
        return {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Content-Type": "application/json",
        }

    def _iso_utc_minutes_ago(self, minutes):
        # Convert a lookback interval into an ISO-formatted UTC timestamp.
        dt = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _raise_for_api_error(self, response):
        # Print diagnostics and raise any HTTP error returned by the API.
        if response.status_code >= 400:
            print("Microsoft 365 Management Activity API request failed.")
            print(f"Status code: {response.status_code}")
            print(f"URL: {response.url}")
            print(f"Response body: {response.text}")
            response.raise_for_status()

    def start_exchange_subscription(self):
        """
        Start the Exchange audit subscription.

        The Office 365 Management Activity API requires a subscription to begin
        publishing Exchange audit content. This method sends the start request
        and returns True when the subscription is active.
        """
        url = f"{self.base_url}/subscriptions/start?contentType=Audit.Exchange"

        response = requests.post(url, headers=self._get_headers(), timeout=30)

        if response.status_code in (200, 201, 202):
            print("Audit.Exchange subscription started or already active.")
            return True

        self._raise_for_api_error(response)
        return False

    def list_exchange_content(self, lookback_minutes=60):
        """
        List available Exchange audit content blobs.

        The API returns a list of content URIs for the requested time range.
        These blobs must be downloaded separately to retrieve actual audit records.
        """
        start_time = self._iso_utc_minutes_ago(lookback_minutes)
        end_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        url = (
            f"{self.base_url}/subscriptions/content"
            f"?contentType=Audit.Exchange"
            f"&startTime={start_time}"
            f"&endTime={end_time}"
        )

        response = requests.get(url, headers=self._get_headers(), timeout=30)
        self._raise_for_api_error(response)

        content = response.json()
        print(f"Fetched {len(content)} Exchange audit content blob(s).")
        return content

    def download_content_blob(self, content_uri):
        """
        Download one audit content blob.

        Each content URI points to a JSON payload containing one or more audit
        records for a time slice. The raw JSON is returned for later parsing.
        """
        response = requests.get(content_uri, headers=self._get_headers(), timeout=30)
        self._raise_for_api_error(response)

        return response.json()

    def get_email_audit_events(self, lookback_minutes=60):
        """
        Retrieve and normalize Exchange audit events.

        This method lists available content blobs for the given lookback window,
        downloads each blob, and converts raw audit records into a simplified
        format consumed by detectors.
        """
        blobs = self.list_exchange_content(lookback_minutes=lookback_minutes)

        normalized = []

        for blob in blobs:
            content_uri = blob.get("contentUri")

            if not content_uri:
                continue

            records = self.download_content_blob(content_uri)

            for record in records:
                # Use the most descriptive operation field available.
                operation = record.get("Operation") or "Unknown"

                # Attempt several fields for the actor/user who performed the action.
                user = (
                    record.get("UserId")
                    or record.get("MailboxOwnerUPN")
                    or record.get("Actor")
                    or "Unknown"
                )

                # Create a stable event ID using available fields.
                record_id = (
                    record.get("Id")
                    or record.get("RecordId")
                    or f"{operation}:{user}:{record.get('CreationTime')}"
                )

                # Determine the target object for the audit event.
                target = (
                    record.get("ObjectId")
                    or record.get("MailboxOwnerUPN")
                    or record.get("ItemName")
                    or "Unknown"
                )

                normalized.append(
                    {
                        "id": record_id,
                        "created_datetime": record.get("CreationTime"),
                        "user": user,
                        "operation": operation,
                        "target": target,
                        "location": "Unknown",
                        "raw": record,
                    }
                )

        print(f"Normalized {len(normalized)} Exchange audit event(s).")
        return normalized