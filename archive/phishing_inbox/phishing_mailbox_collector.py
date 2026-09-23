"""
Phishing mailbox collector for the Entra Monitoring Project.

This collector reads messages from the phishing-report mailbox, parses Microsoft
reported-message wrapper content, normalizes Outlook categories, and stores the
result in SQLite.

Current V1 purpose:
- Read phishing-report mailbox messages from Microsoft Graph.
- Parse the report wrapper subject/body.
- Preserve Outlook categories.
- Normalize Outlook categories into review labels.
- Download/read the original reported-email attachment when available.
- Store structured report metadata in SQLite.

Important:
This file is intentionally written as a collector module, not as a detector.
It does not generate security alerts yet. Its job is to build the phishing
dataset that can later support reporting, dashboards, scoring, and ML.
"""

import base64
import logging

from core.phishing_category_map import normalize_phishing_categories
from parsers.phishing_report_parser import parse_phishing_report_message
from storage.sqlite_store import insert_phishing_report


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Graph message fields
# ---------------------------------------------------------------------------
# These are the fields we want from Microsoft Graph when reading the phishing
# report mailbox.
#
# body:
#   Contains the Microsoft reported-message wrapper text/header details.
#
# categories:
#   Contains Outlook categories such as:
#   - Confirmed Phish
#   - Junk / Marketing
#   - Legitimate
#   - Reviewing - Ryan
#
# hasAttachments:
#   Tells us whether we need to call Graph again to retrieve attachments.
GRAPH_MESSAGE_SELECT_FIELDS = [
    "id",
    "subject",
    "receivedDateTime",
    "from",
    "sender",
    "toRecipients",
    "internetMessageId",
    "body",
    "bodyPreview",
    "categories",
    "hasAttachments",
]


def build_graph_select_query():
    """
    Build the Microsoft Graph $select query string for phishing messages.

    Returns:
        Comma-separated Graph field list.
    """
    return ",".join(GRAPH_MESSAGE_SELECT_FIELDS)


def get_message_body_text(message):
    """
    Extract readable body content from a Graph message object.

    Microsoft Graph usually returns body like:

        {
            "contentType": "html",
            "content": "<html>...</html>"
        }

    For now, we return the content as-is. The parser can still extract headers
    from it if the message body is mostly plain text. If Graph returns HTML, we
    may later add cleaner HTML-to-text conversion here.
    """
    body = message.get("body") or {}

    return body.get("content") or message.get("bodyPreview") or ""


def get_reporting_user_from_message(message):
    """
    Best-effort extraction of the employee who submitted the report.

    In many report mailbox messages, the message is from the employee who
    reported or forwarded the suspicious email.

    Example:
        From Brandon Briggs <bbriggs@resolutgroup.com>

    Returns:
        Email address if available, otherwise None.
    """
    from_value = message.get("from") or {}
    email_address = from_value.get("emailAddress") or {}

    return email_address.get("address")


def decode_file_attachment_content(attachment):
    """
    Decode a Graph fileAttachment contentBytes value.

    Graph fileAttachment objects often include:

        contentBytes: base64-encoded attachment bytes

    Returns:
        Raw bytes, or None if unavailable/invalid.
    """
    content_bytes = attachment.get("contentBytes")

    if not content_bytes:
        return None

    try:
        return base64.b64decode(content_bytes)
    except Exception:
        logger.exception("Failed to decode attachment contentBytes")
        return None


def select_original_report_attachment(attachments):
    """
    Select the attachment most likely to contain the original reported email.

    Microsoft reported-message wrappers often include an attachment that opens
    as the actual reported email.

    For V1, we prioritize:
    - message/rfc822 attachments
    - .eml attachments
    - attachments with contentBytes
    - otherwise the first file attachment

    Args:
        attachments: List of Graph attachment dictionaries.

    Returns:
        Attachment dictionary or None.
    """
    if not attachments:
        return None

    # Prefer message/rfc822 because that usually means an attached email.
    for attachment in attachments:
        content_type = (attachment.get("contentType") or "").lower()

        if content_type == "message/rfc822":
            return attachment

    # Prefer .eml files if present.
    for attachment in attachments:
        name = (attachment.get("name") or "").lower()

        if name.endswith(".eml"):
            return attachment

    # Prefer anything with raw contentBytes.
    for attachment in attachments:
        if attachment.get("contentBytes"):
            return attachment

    # Fall back to first attachment.
    return attachments[0]


def attachment_to_parser_inputs(attachment):
    """
    Convert a Graph attachment object into parser inputs.

    Returns:
        Dictionary containing:
        - original_attachment_bytes
        - original_attachment_text
        - original_attachment_name
        - original_attachment_content_type
    """
    if not attachment:
        return {
            "original_attachment_bytes": None,
            "original_attachment_text": None,
            "original_attachment_name": None,
            "original_attachment_content_type": None,
        }

    attachment_name = attachment.get("name")
    content_type = attachment.get("contentType")

    attachment_bytes = decode_file_attachment_content(attachment)
    attachment_text = None

    # If bytes appear to be UTF-8 text, provide a text version too.
    # This helps parser fallback logic.
    if attachment_bytes:
        try:
            attachment_text = attachment_bytes.decode("utf-8", errors="replace")
        except Exception:
            attachment_text = None

    return {
        "original_attachment_bytes": attachment_bytes,
        "original_attachment_text": attachment_text,
        "original_attachment_name": attachment_name,
        "original_attachment_content_type": content_type,
    }


def merge_category_fields(parsed_report, categories):
    """
    Normalize Outlook categories and merge the results into parsed_report.

    This is where Outlook categories become:
    - manual_verdict
    - review_status
    - reviewed_by
    - priority
    - is_trusted_ml_label

    The is_trusted_ml_label field is useful for logic/debugging, but it is not
    currently stored directly in sqlite_store.py.
    """
    normalized_category_fields = normalize_phishing_categories(categories)

    merged_report = dict(parsed_report)
    merged_report.update(normalized_category_fields)

    # SQLite currently does not have an is_trusted_ml_label column. Keep it out
    # of the insert payload so the report dictionary stays aligned with storage.
    merged_report.pop("is_trusted_ml_label", None)

    return merged_report


def parse_graph_message_to_report(message, attachments=None):
    """
    Convert one Graph phishing-mailbox message into a SQLite-ready report dict.

    This combines:
    - Graph message metadata
    - wrapper parser output
    - original attachment parser output
    - Outlook category normalization
    """
    attachments = attachments or []

    selected_attachment = select_original_report_attachment(attachments)
    attachment_inputs = attachment_to_parser_inputs(selected_attachment)

    categories = message.get("categories") or []

    parsed_report = parse_phishing_report_message(
        report_message_id=message.get("id"),
        report_subject=message.get("subject"),
        report_received_time=message.get("receivedDateTime"),
        body_text=get_message_body_text(message),
        internet_message_id=message.get("internetMessageId"),
        graph_categories=categories,
        original_attachment_text=attachment_inputs["original_attachment_text"],
        original_attachment_bytes=attachment_inputs["original_attachment_bytes"],
        original_attachment_name=attachment_inputs["original_attachment_name"],
        original_attachment_content_type=attachment_inputs[
            "original_attachment_content_type"
        ],
    )

    parsed_report["reporting_user"] = get_reporting_user_from_message(message)

    return merge_category_fields(parsed_report, categories)


def collect_phishing_reports(
    graph_client,
    phishing_mailbox_user_id,
    limit=25,
):
    """
    Collect phishing-report messages from the phishing mailbox.

    Args:
        graph_client:
            Project Graph client object. This collector expects the client to
            provide methods for reading user messages and message attachments.

        phishing_mailbox_user_id:
            User ID or email address of the phishing mailbox, for example:
                phish@resolutgroup.com

        limit:
            Maximum number of recent messages to collect.

    Expected graph_client methods:
        get_user_messages(user_id, select=None, top=25)
        get_message_attachments(user_id, message_id)

    Returns:
        Summary dictionary with collection counts.
    """
    select_fields = build_graph_select_query()

    summary = {
        "messages_seen": 0,
        "messages_stored": 0,
        "messages_failed": 0,
        "stored_report_ids": [],
    }

    logger.info(
        "Collecting phishing reports from mailbox %s",
        phishing_mailbox_user_id,
    )

    messages = graph_client.get_user_messages(
        user_id=phishing_mailbox_user_id,
        select=select_fields,
        top=limit,
    )

    for message in messages:
        summary["messages_seen"] += 1

        message_id = message.get("id")

        try:
            attachments = []

            if message.get("hasAttachments"):
                attachments = graph_client.get_message_attachments(
                    user_id=phishing_mailbox_user_id,
                    message_id=message_id,
                )

            report = parse_graph_message_to_report(
                message=message,
                attachments=attachments,
            )

            phishing_report_id = insert_phishing_report(report)

            if phishing_report_id:
                summary["messages_stored"] += 1
                summary["stored_report_ids"].append(phishing_report_id)

        except Exception:
            summary["messages_failed"] += 1
            logger.exception(
                "Failed to collect phishing report message_id=%s",
                message_id,
            )

    logger.info(
        "Phishing report collection complete. Seen=%s Stored=%s Failed=%s",
        summary["messages_seen"],
        summary["messages_stored"],
        summary["messages_failed"],
    )

    return summary