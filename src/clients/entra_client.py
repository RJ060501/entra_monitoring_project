"""
Entra Client

This file is responsible for connecting to Microsoft Graph and pulling
Microsoft Entra data into the monitoring project.

It currently retrieves:
- Entra sign-in logs
- Entra directory audit logs

The rest of the application should not need to know how Microsoft Graph works.
This file handles authentication, API requests, retry handling, and normalizing
raw Graph data into simpler dictionaries that detector modules can understand.
"""

from datetime import datetime, timedelta, timezone
import logging
import time

import requests
from azure.core.exceptions import AzureError
from azure.identity import ClientSecretCredential


logger = logging.getLogger(__name__)


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
        """
        Store configuration and create the Azure credential object.

        Args:
            settings:
                Dictionary returned by your project settings/config loader.
        """
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
        """
        Acquire a short-lived bearer token for Microsoft Graph.

        This can fail if Microsoft login is temporarily unreachable, DNS fails,
        or the network path from Docker/WSL to Microsoft is interrupted.
        """
        try:
            token = self.credential.get_token(self.graph_scope)
            return token.token

        except AzureError as exception:
            logger.error(
                "Failed to acquire Microsoft Graph access token: %s",
                exception,
            )
            raise

    def _get_headers(self):
        """
        Build the headers required for Graph API requests.
        """
        return {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Content-Type": "application/json",
        }

    def _iso_utc_minutes_ago(self, minutes):
        """
        Convert a lookback interval into an ISO-formatted UTC timestamp.
        """
        dt = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _graph_get_with_retries(
        self,
        url,
        timeout_seconds=60,
        max_attempts=3,
        retry_sleep_seconds=5,
    ):
        """
        Perform a Microsoft Graph GET request with retry handling.

        Microsoft Graph can occasionally timeout or return transient errors.
        A single timeout should not crash the entire monitoring run.

        Args:
            url:
                Full Microsoft Graph URL to request.

            timeout_seconds:
                Per-request timeout.

            max_attempts:
                Number of attempts before giving up.

            retry_sleep_seconds:
                Base sleep delay between attempts. The delay increases slightly
                per attempt.

        Returns:
            requests.Response object.

        Raises:
            requests.exceptions.RequestException after all attempts fail.
        """
        last_exception = None

        for attempt_number in range(1, max_attempts + 1):
            try:
                response = requests.get(
                    url,
                    headers=self._get_headers(),
                    timeout=timeout_seconds,
                )

                # Handle Microsoft Graph throttling or temporary service errors.
                # These are worth retrying before giving up.
                if response.status_code in {429, 500, 502, 503, 504}:
                    logger.warning(
                        "Microsoft Graph returned retryable status %s. "
                        "Attempt %s of %s. URL: %s",
                        response.status_code,
                        attempt_number,
                        max_attempts,
                        url,
                    )

                    if attempt_number < max_attempts:
                        retry_after = response.headers.get("Retry-After")
                        sleep_seconds = self._get_retry_sleep_seconds(
                            retry_after=retry_after,
                            fallback_seconds=retry_sleep_seconds * attempt_number,
                        )
                        time.sleep(sleep_seconds)
                        continue

                return response

            except requests.exceptions.Timeout as exception:
                last_exception = exception

                logger.warning(
                    "Microsoft Graph request timed out. "
                    "Attempt %s of %s. Timeout=%s seconds. URL: %s",
                    attempt_number,
                    max_attempts,
                    timeout_seconds,
                    url,
                )

            except requests.exceptions.RequestException as exception:
                last_exception = exception

                logger.warning(
                    "Microsoft Graph request failed. "
                    "Attempt %s of %s. URL: %s. Error: %s",
                    attempt_number,
                    max_attempts,
                    url,
                    exception,
                )
                
            except AzureError as exception:
                last_exception = exception

                logger.warning(
                    "Microsoft Graph authentication failed. "
                    "Attempt %s of %s. URL: %s. Error: %s",
                    attempt_number,
                    max_attempts,
                    url,
                    exception,
                )

            if attempt_number < max_attempts:
                time.sleep(retry_sleep_seconds * attempt_number)

        if last_exception:
            raise last_exception

        raise requests.exceptions.RequestException(
            f"Microsoft Graph request failed after {max_attempts} attempts: {url}"
        )

    def _get_retry_sleep_seconds(self, retry_after, fallback_seconds):
        """
        Convert a Retry-After header into a sleep duration.

        Microsoft Graph may return Retry-After when throttling requests.

        Args:
            retry_after:
                Retry-After header value from Graph.

            fallback_seconds:
                Sleep duration to use if Retry-After is missing or invalid.

        Returns:
            Integer sleep duration in seconds.
        """
        if not retry_after:
            return fallback_seconds

        try:
            return int(retry_after)
        except ValueError:
            return fallback_seconds

    def _get_graph_collection(self, url, source_name):
        """
        Retrieve a Graph collection safely.

        This helper centralizes:
        - retry behavior
        - response status handling
        - JSON parsing
        - final failure handling

        If Graph fails after retries, this returns an empty list so the overall
        monitor run can continue.

        Args:
            url:
                Full Graph collection URL.

            source_name:
                Friendly name used in logs.

        Returns:
            List of raw Graph event dictionaries.
        """
        try:
            response = self._graph_get_with_retries(url)
            response.raise_for_status()

            return response.json().get("value", [])

        except (requests.exceptions.RequestException, AzureError) as exception:
            logger.error(
                "Failed to retrieve %s from Microsoft Graph after retries: %s",
                source_name,
                exception,
            )
            return []

        except ValueError as exception:
            logger.error(
                "Failed to parse %s Microsoft Graph JSON response: %s",
                source_name,
                exception,
            )
            return []

    def get_signins(self, lookback_minutes=120):
        """
        Fetch sign-in audit logs from Graph and normalize them for detector use.

        Args:
            lookback_minutes:
                How far back to retrieve events.

        Returns:
            A list of simplified sign-in event dictionaries.

        Failure behavior:
            If Microsoft Graph times out or fails after retries, this returns an
            empty list instead of crashing the monitor run.
        """
        start_time = self._iso_utc_minutes_ago(lookback_minutes)

        # Build the Graph query to return sign-in records newer than start_time.
        url = (
            f"{self.base_url}/auditLogs/signIns"
            f"?$filter=createdDateTime ge {start_time}"
            f"&$orderby=createdDateTime desc"
            f"&$top=200"
        )

        data = self._get_graph_collection(
            url=url,
            source_name="Entra sign-in logs",
        )

        normalized = []

        logger.info("Fetched %s sign-in event(s) from Graph.", len(data))

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
            location = ", ".join(
                [x for x in [city, state, country] if x]
            ) or "Unknown"

            # Extract the event hour for rolling group or bucket analysis.
            # This remains UTC unless signin_detector.py later converts to
            # Mountain Time for specific detections.
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
                    "conditional_access_status": event.get(
                        "conditionalAccessStatus"
                    ),
                    "risk_level_aggregated": event.get("riskLevelAggregated"),
                    "risk_detail": event.get("riskDetail"),
                    "new_location": False,
                    "raw": event,
                }
            )

        success_count = sum(
            1 for event in normalized if event.get("status") == "success"
        )
        failure_count = sum(
            1 for event in normalized if event.get("status") == "failure"
        )

        logger.info("Normalized %s sign-in event(s).", len(normalized))
        logger.info("Successful sign-ins: %s", success_count)
        logger.info("Failed sign-ins: %s", failure_count)

        return normalized

    def get_audits(self, lookback_minutes=240):
        """
        Fetch directory audit logs from Graph and normalize them for detector use.

        Args:
            lookback_minutes:
                How far back to retrieve events.

        Returns:
            A list of simplified audit event dictionaries.

        Failure behavior:
            If Microsoft Graph times out or fails after retries, this returns an
            empty list instead of crashing the monitor run.
        """
        start_time = self._iso_utc_minutes_ago(lookback_minutes)

        # Build the Graph query to return directory audit records newer than
        # start_time.
        url = (
            f"{self.base_url}/auditLogs/directoryAudits"
            f"?$filter=activityDateTime ge {start_time}"
            f"&$orderby=activityDateTime desc"
            f"&$top=100"
        )

        data = self._get_graph_collection(
            url=url,
            source_name="Entra directory audit logs",
        )

        logger.info("Fetched %s audit event(s) from Graph.", len(data))

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

        logger.info("Normalized %s audit event(s).", len(normalized))

        return normalized