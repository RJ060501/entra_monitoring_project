"""
Parser for Microsoft reported-message phishing mailbox items.

This module extracts structured data from phishing-report mailbox messages.

Why this exists:
- The phishing mailbox does not appear to contain only raw forwarded emails.
- The messages look like Microsoft reported-message wrapper/container messages.
- Useful original-message data is embedded in the subject and body/headers.

Example wrapper subject:

    Not junk:07ef1af3-dda5-4119-4987-08dedc207eb7|bex@nevbex.com|(NVBEX 07-07-26 - M.J. Dean Construction Proposing Hockey Arena in Spring Valley) 07/16/2026 19:19:41

From that subject, we can extract:
- Microsoft/report label: Not junk
- Network message ID: 07ef1af3-dda5-4119-4987-08dedc207eb7
- Original sender: bex@nevbex.com
- Original subject: NVBEX 07-07-26 - M.J. Dean Construction Proposing Hockey Arena in Spring Valley
- Reported/original timestamp: 07/16/2026 19:19:41

This parser intentionally avoids storing full raw email bodies by default. It
only extracts useful metadata for review, reporting, and future ML features.
"""

import re
from email.utils import parseaddr
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Subject parser pattern
# ---------------------------------------------------------------------------
# This pattern parses Microsoft reported-message wrapper subjects that look like:
#
#   Not junk:<network_message_id>|<sender>|(<original_subject>) <timestamp>
#
# The original subject is wrapped in parentheses.
#
# The pattern is intentionally somewhat flexible:
# - The label can contain letters and spaces.
# - The sender is captured up to the next pipe.
# - The original subject is captured inside parentheses.
# - The timestamp is optional because the format may vary.

#[^|]+ means match one or more characters that are not a pipe (|) character.
REPORT_SUBJECT_PATTERN = re.compile(
    r"^(?P<label>[^:]+):"
    r"(?P<network_message_id>[^|]+)\|"
    r"(?P<original_sender>[^|]+)\|"
    r"\((?P<original_subject>.*)\)"
    r"(?:\s+(?P<reported_timestamp>.+))?$"
)


# ---------------------------------------------------------------------------
# Header/body extraction patterns
# ---------------------------------------------------------------------------
# These regex patterns search the reported-message body/header text for fields
# we care about.
#
# They are kept simple for V1 because the Microsoft wrapper already gives us a
# lot of structured data. We can make these more advanced after we see more
# real examples.
FIELD_PATTERNS = {
    "from": re.compile(r"^From:\s*(?P<value>.+)$", re.IGNORECASE | re.MULTILINE),
    "to": re.compile(r"^To:\s*(?P<value>.+)$", re.IGNORECASE | re.MULTILINE),
    "subject": re.compile(r"^Subject:\s*(?P<value>.+)$", re.IGNORECASE | re.MULTILINE),
    "date": re.compile(r"^Date:\s*(?P<value>.+)$", re.IGNORECASE | re.MULTILINE),
    "message_id": re.compile(r"^Message-ID:\s*(?P<value>.+)$", re.IGNORECASE | re.MULTILINE),
    "reply_to": re.compile(r"^Reply-To:\s*(?P<value>.+)$", re.IGNORECASE | re.MULTILINE),
    "content_type": re.compile(r"^Content-Type:\s*(?P<value>.+)$", re.IGNORECASE | re.MULTILINE),
    "scl": re.compile(
        r"^X-MS-Exchange-Organization-SCL:\s*(?P<value>.+)$",
        re.IGNORECASE | re.MULTILINE,
    ),
    "network_message_id": re.compile(
        r"^X-MS-Exchange-Organization-Network-Message-Id:\s*(?P<value>.+)$",
        re.IGNORECASE | re.MULTILINE,
    ),
    "received_spf": re.compile(
        r"^received-spf:\s*(?P<value>.+)$",
        re.IGNORECASE | re.MULTILINE,
    ),
    "authentication_results": re.compile(
        r"^Authentication-Results:\s*(?P<value>.+)$",
        re.IGNORECASE | re.MULTILINE,
    ),
}


# ---------------------------------------------------------------------------
# URL pattern
# ---------------------------------------------------------------------------
# This is a simple URL extractor for report bodies/header text.
#
# It will not be perfect, but it is good enough for early V1 metadata capture.
# We can improve this later if we need safer URL defanging/normalization.
URL_PATTERN = re.compile(
    r"https?://[^\s<>\")]+",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Received header sender IP pattern
# ---------------------------------------------------------------------------
# This pattern looks for the first external-looking IPv4 address in a Received
# header line.
#
# Example from the sample report:
#
#   Received: from s4.csa2.acemsa5.com (52.128.40.100) by ...
#
# The parser should extract:
#
#   52.128.40.100
RECEIVED_HEADER_PATTERN = re.compile(
    r"^Received:\s+from\s+.+?\((?P<ip>\d{1,3}(?:\.\d{1,3}){3})\)",
    re.IGNORECASE | re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Basic attachment/content hints
# ---------------------------------------------------------------------------
# This parser does not download attachments.
#
# It only detects simple attachment-like indicators from headers/body text. The
# mailbox collector may later add richer attachment metadata from Microsoft
# Graph message attachments.
ATTACHMENT_NAME_PATTERN = re.compile(
    r'name="(?P<filename>[^"]+)"',
    re.IGNORECASE,
)


def normalize_report_label(label):
    """
    Normalize the Microsoft/report label from the wrapper subject.

    Examples:
        "Not junk" -> "not_junk"
        "Junk" -> "junk"
        "Phishing" -> "phishing"

    Unknown labels are lowercased and spaces are converted to underscores so
    they remain useful for reporting.
    """
    if not label:
        return None

    normalized = str(label).strip().lower()
    normalized = normalized.replace(" ", "_")
    normalized = normalized.replace("-", "_")

    return normalized


def extract_email_address(value):
    """
    Extract a clean email address from a header value.

    Examples:
        "NVBEX <bex@nevbex.com>" -> "bex@nevbex.com"
        "bex@nevbex.com" -> "bex@nevbex.com"

    If parsing fails, return the original stripped value.
    """
    if not value:
        return None

    display_name, email_address = parseaddr(str(value).strip())

    if email_address:
        return email_address.lower()

    cleaned_value = str(value).strip()

    if cleaned_value:
        return cleaned_value.lower()

    return None


def extract_domain_from_email(email_address):
    """
    Extract the domain from an email address.

    Example:
        "bex@nevbex.com" -> "nevbex.com"
    """
    if not email_address:
        return None

    if "@" not in email_address:
        return None

    return email_address.split("@", 1)[1].strip().lower()


def get_first_regex_value(pattern, text):
    """
    Return the first named group value from a regex pattern.

    The patterns in FIELD_PATTERNS use a named group called "value".
    This helper avoids repeating the same match/extract logic everywhere.
    """
    if not text:
        return None

    match = pattern.search(text)

    if not match:
        return None

    value = match.group("value").strip()

    if not value:
        return None

    return value


def parse_report_subject(subject):
    """
    Parse the Microsoft reported-message wrapper subject.

    Args:
        subject: Subject of the report message from the phishing mailbox.

    Returns:
        Dictionary containing parsed subject fields. Missing fields are returned
        as None.
    """
    result = {
        "microsoft_or_report_label": None,
        "network_message_id": None,
        "original_sender": None,
        "original_sender_domain": None,
        "original_subject": None,
        "reported_timestamp": None,
    }

    if not subject:
        return result

    match = REPORT_SUBJECT_PATTERN.match(str(subject).strip())

    if not match:
        return result

    label = match.group("label")
    original_sender = extract_email_address(match.group("original_sender"))

    result.update(
        {
            "microsoft_or_report_label": normalize_report_label(label),
            "network_message_id": match.group("network_message_id").strip(),
            "original_sender": original_sender,
            "original_sender_domain": extract_domain_from_email(original_sender),
            "original_subject": match.group("original_subject").strip(),
            "reported_timestamp": (
                match.group("reported_timestamp").strip()
                if match.group("reported_timestamp")
                else None
            ),
        }
    )

    return result


def extract_urls(text):
    """
    Extract URLs and URL domains from text.

    Args:
        text: Body/header text from the report message.

    Returns:
        List of dictionaries:
            [
                {"url": "https://example.com/path", "domain": "example.com"}
            ]
    """
    if not text:
        return []

    urls = []
    seen_urls = set()

    for match in URL_PATTERN.finditer(text):
        url = match.group(0).strip().rstrip(".,;")

        if url in seen_urls:
            continue

        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower() if parsed_url.netloc else None

        urls.append(
            {
                "url": url,
                "domain": domain,
            }
        )

        seen_urls.add(url)

    return urls


def extract_attachments_from_text(text):
    """
    Extract simple attachment/content-name hints from the report text.

    This is not a full attachment parser.

    It catches header values such as:
        Content-Type: application/ms-tnef; name="winmail.dat"

    Returns:
        List of attachment metadata dictionaries.
    """
    if not text:
        return []

    attachments = []
    seen_filenames = set()

    for match in ATTACHMENT_NAME_PATTERN.finditer(text):
        filename = match.group("filename").strip()

        if not filename:
            continue

        if filename in seen_filenames:
            continue

        extension = None

        if "." in filename:
            extension = filename.rsplit(".", 1)[1].lower()

        attachments.append(
            {
                "filename": filename,
                "extension": extension,
                "content_type": None,
                "size_bytes": None,
            }
        )

        seen_filenames.add(filename)

    return attachments


def extract_original_sender_ip(text):
    """
    Extract the first original sender IP candidate from Received headers.

    This is a V1 best-effort parser. Received headers can be complex, and not
    every IP in the header chain is necessarily the true sender.

    For your dataset, this still gives useful investigation context.
    """
    if not text:
        return None

    match = RECEIVED_HEADER_PATTERN.search(text)

    if not match:
        return None

    return match.group("ip")


def extract_spf_result(received_spf_value):
    """
    Extract a compact SPF result from the received-spf header.

    Example:
        "Pass (...)" -> "pass"
        "Fail (...)" -> "fail"
    """
    if not received_spf_value:
        return None

    first_token = str(received_spf_value).strip().split(" ", 1)[0]

    if not first_token:
        return None

    return first_token.lower()


def extract_auth_result_token(auth_results, token_name):
    """
    Extract a DKIM/DMARC-style result token from Authentication-Results text.

    Example input:
        "... dkim=pass ... dmarc=fail ..."

    Example:
        token_name = "dkim" -> "pass"
        token_name = "dmarc" -> "fail"
    """
    if not auth_results:
        return None

    pattern = re.compile(
        rf"\b{re.escape(token_name)}=(?P<value>[a-zA-Z0-9_\-]+)",
        re.IGNORECASE,
    )

    match = pattern.search(auth_results)

    if not match:
        return None

    return match.group("value").lower()


def get_body_text_sample(text, max_length=1000):
    """
    Return a safe body/header text sample for storage.

    We do not want to store full email bodies by default.

    This sample is enough for debugging and simple future feature extraction,
    while reducing data retention risk.
    """
    if not text:
        return None

    cleaned_text = str(text).strip()

    if not cleaned_text:
        return None

    return cleaned_text[:max_length]


def parse_phishing_report_message(
    report_message_id,
    report_subject,
    report_received_time=None,
    body_text=None,
    internet_message_id=None,
    graph_categories=None,
):
    """
    Parse a phishing-report mailbox message into a SQLite-ready dictionary.

    Args:
        report_message_id:
            Microsoft Graph message id for the report mailbox message.

        report_subject:
            Subject of the report mailbox message.

        report_received_time:
            Received timestamp of the report mailbox message.

        body_text:
            Plain text or header/body content from the report mailbox message.

        internet_message_id:
            Internet message id of the report wrapper message, if available.

        graph_categories:
            Outlook categories from Microsoft Graph. This parser preserves them
            but does not normalize them. Category normalization is handled by
            core.phishing_category_map.

    Returns:
        Dictionary ready to be merged with normalized category fields and passed
        into storage.sqlite_store.insert_phishing_report().
    """
    body_text = body_text or ""

    subject_fields = parse_report_subject(report_subject)

    # Extract useful header/body fields from the wrapper content.
    from_header = get_first_regex_value(FIELD_PATTERNS["from"], body_text)
    to_header = get_first_regex_value(FIELD_PATTERNS["to"], body_text)
    subject_header = get_first_regex_value(FIELD_PATTERNS["subject"], body_text)
    date_header = get_first_regex_value(FIELD_PATTERNS["date"], body_text)
    message_id_header = get_first_regex_value(FIELD_PATTERNS["message_id"], body_text)
    reply_to_header = get_first_regex_value(FIELD_PATTERNS["reply_to"], body_text)
    content_type_header = get_first_regex_value(FIELD_PATTERNS["content_type"], body_text)
    scl_header = get_first_regex_value(FIELD_PATTERNS["scl"], body_text)
    network_message_id_header = get_first_regex_value(
        FIELD_PATTERNS["network_message_id"],
        body_text,
    )
    received_spf_header = get_first_regex_value(
        FIELD_PATTERNS["received_spf"],
        body_text,
    )
    auth_results_header = get_first_regex_value(
        FIELD_PATTERNS["authentication_results"],
        body_text,
    )

    # Prefer subject-wrapper values when they are available because they are
    # explicitly produced by Microsoft's reported-message format.
    original_sender = (
        subject_fields.get("original_sender")
        or extract_email_address(from_header)
    )

    original_subject = (
        subject_fields.get("original_subject")
        or subject_header
    )

    network_message_id = (
        subject_fields.get("network_message_id")
        or network_message_id_header
    )

    urls = extract_urls(body_text)
    attachments = extract_attachments_from_text(body_text)

    # If Content-Type has a name= value, extract_attachments_from_text() should
    # already catch it. Keep this variable around because it may be useful later
    # if we enrich attachment records.
    _ = content_type_header

    spf_result = extract_spf_result(received_spf_header)

    parsed_report = {
        # Reporting wrapper fields
        "report_message_id": report_message_id,
        "report_subject": report_subject,
        "report_received_time": report_received_time,
        "internet_message_id": internet_message_id,

        # Microsoft/report wrapper fields
        "microsoft_or_report_label": subject_fields.get("microsoft_or_report_label"),
        "network_message_id": network_message_id,

        # Category field preserved exactly as received from Graph.
        # Normalized category labels are added later by phishing_category_map.py.
        "outlook_categories_raw": graph_categories or [],

        # Original message fields
        "original_sender": original_sender,
        "original_sender_domain": extract_domain_from_email(original_sender),
        "reply_to": extract_email_address(reply_to_header),
        "original_recipient": extract_email_address(to_header),
        "original_subject": original_subject,
        "subject": original_subject,
        "received_time": date_header or subject_fields.get("reported_timestamp"),
        "original_sender_ip": extract_original_sender_ip(body_text),

        # Authentication / filtering fields
        "spf_result": spf_result,
        "dkim_result": extract_auth_result_token(auth_results_header, "dkim"),
        "dmarc_result": extract_auth_result_token(auth_results_header, "dmarc"),
        "auth_results": auth_results_header,
        "scl": scl_header,

        # Indicators / content summary
        "has_attachments": bool(attachments),
        "attachment_count": len(attachments),
        "url_count": len(urls),
        "body_text_sample": get_body_text_sample(body_text),

        # Child table data
        "urls": urls,
        "attachments": attachments,

        # Defaults that may be overwritten by category normalization.
        "microsoft_verdict": None,
        "manual_verdict": "unknown",
        "review_status": "new",
        "reviewed_by": None,
        "reviewed_at": None,
        "notes": None,

        # Defender remediation tracking.
        "blocked_in_defender": False,
        "blocked_at": None,
        "block_notes": None,
    }

    return parsed_report