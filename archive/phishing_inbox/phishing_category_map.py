"""
Outlook category normalization for phishing-report review workflow.

This module translates Outlook categories from the phishing-report mailbox into
consistent internal values that can be stored in SQLite.

Why this exists:
- The IT team already reviews reports by applying Outlook categories.
- We do not want reviewers to label reports twice.
- The collector can read Outlook categories through Microsoft Graph.
- This file turns those categories into stable database fields.

Trusted ML labels:
- Confirmed Phish   -> malicious
- Junk / Marketing  -> spam_or_marketing
- Legitimate        -> benign

Workflow/status labels:
- Reviewing - Dan
- Reviewing - Jack
- Reviewing - Ryan
- User Interacted - Urgent

Workflow/status labels are useful for triage, but they should not be treated as
final ML training labels.
"""


# ---------------------------------------------------------------------------
# Known Outlook category names
# ---------------------------------------------------------------------------
# These strings should match the category names used in the phishing-report
# mailbox. Keeping them as constants makes it easier to update the workflow
# later if category names change.
CATEGORY_CONFIRMED_PHISH = "Confirmed Phish"
CATEGORY_JUNK_MARKETING = "Junk / Marketing"
CATEGORY_LEGITIMATE = "Legitimate"

CATEGORY_REVIEWING_DAN = "Reviewing - Dan"
CATEGORY_REVIEWING_JACK = "Reviewing - Jack"
CATEGORY_REVIEWING_RYAN = "Reviewing - Ryan"

CATEGORY_USER_INTERACTED_URGENT = "User Interacted - Urgent"


# ---------------------------------------------------------------------------
# Trusted labels for future ML training
# ---------------------------------------------------------------------------
# These are the only final labels we currently trust for training data.
#
# Do not include "Reviewing - Ryan", "Reviewing - Dan", "Reviewing - Jack",
# "User Interacted - Urgent", or "unknown" here because those are workflow
# states, not clean final classification labels.
TRUSTED_ML_VERDICTS = {
    "malicious",
    "spam_or_marketing",
    "benign",
}


# ---------------------------------------------------------------------------
# Final verdict category map
# ---------------------------------------------------------------------------
# These categories represent completed review outcomes.
#
# If one of these is present, it should usually become the final manual_verdict
# stored in SQLite.
FINAL_VERDICT_CATEGORY_MAP = {
    CATEGORY_CONFIRMED_PHISH: {
        "category_verdict": "malicious",
        "manual_verdict": "malicious",
        "review_status": "reviewed",
        "category_review_status": "reviewed",
        "priority": "high",
    },
    CATEGORY_JUNK_MARKETING: {
        "category_verdict": "spam_or_marketing",
        "manual_verdict": "spam_or_marketing",
        "review_status": "reviewed",
        "category_review_status": "reviewed",
        "priority": "normal",
    },
    CATEGORY_LEGITIMATE: {
        "category_verdict": "benign",
        "manual_verdict": "benign",
        "review_status": "reviewed",
        "category_review_status": "reviewed",
        "priority": "normal",
    },
}


# ---------------------------------------------------------------------------
# Reviewer workflow category map
# ---------------------------------------------------------------------------
# These categories indicate who is reviewing an item.
#
# They do not mean the report has a final verdict yet.
REVIEWING_CATEGORY_MAP = {
    CATEGORY_REVIEWING_DAN: {
        "category_reviewed_by": "Dan",
        "reviewed_by": "Dan",
        "category_review_status": "in_review",
        "review_status": "in_review",
    },
    CATEGORY_REVIEWING_JACK: {
        "category_reviewed_by": "Jack",
        "reviewed_by": "Jack",
        "category_review_status": "in_review",
        "review_status": "in_review",
    },
    CATEGORY_REVIEWING_RYAN: {
        "category_reviewed_by": "Ryan",
        "reviewed_by": "Ryan",
        "category_review_status": "in_review",
        "review_status": "in_review",
    },
}


# ---------------------------------------------------------------------------
# Urgent workflow category map
# ---------------------------------------------------------------------------
# This category means the user may have interacted with the message.
#
# This should be treated as urgent workflow context, but not as a clean ML
# training label by itself.
URGENT_CATEGORY_MAP = {
    CATEGORY_USER_INTERACTED_URGENT: {
        "category_verdict": "needs_escalation",
        "manual_verdict": "needs_escalation",
        "review_status": "urgent",
        "category_review_status": "urgent",
        "priority": "urgent",
    },
}

#Helper Function
def normalize_category_name(category):
    """
    Normalize a single Outlook category string for comparison.

    This does not change the official category names stored in Outlook. It only
    makes matching more forgiving in case Graph returns extra whitespace.

    Args:
        category: A category value from Microsoft Graph.

    Returns:
        A stripped string, or None if the input was empty.
    """
    if not category:
        return None

    return str(category).strip()

#Helper Function
def normalize_category_list(categories):
    """
    Normalize a list of Outlook categories.

    Microsoft Graph usually returns message categories as a list of strings.

    This helper:
    - Handles None safely.
    - Strips extra whitespace.
    - Removes empty values.
    - Deduplicates categories while preserving order.

    Args:
        categories: List of Outlook category strings.

    Returns:
        A cleaned list of category names.
    """
    if not categories:
        return []

    cleaned_categories = []
    seen_categories = set()

    for category in categories:
        normalized_category = normalize_category_name(category)

        if not normalized_category:
            continue

        if normalized_category in seen_categories:
            continue

        cleaned_categories.append(normalized_category)
        seen_categories.add(normalized_category)

    return cleaned_categories


def normalize_phishing_categories(categories):
    """
    Convert Outlook categories into normalized phishing-review fields.

    Category precedence:
    1. User Interacted - Urgent
    2. Confirmed Phish
    3. Junk / Marketing
    4. Legitimate
    5. Reviewing - Dan / Jack / Ryan
    6. No category / unknown

    Important:
    - Final verdict categories should win over reviewing categories.
    - Reviewer names can still be preserved if a reviewing category is also set.
    - "User Interacted - Urgent" should raise priority, but it is not a clean
      ML training label.

    Args:
        categories: List of Outlook category strings from Microsoft Graph.

    Returns:
        A dictionary with normalized fields ready to merge into a phishing
        report record before inserting into SQLite.
    """
    normalized_categories = normalize_category_list(categories)

    result = {
        "outlook_categories_raw": normalized_categories,
        "category_verdict": "unknown",
        "category_review_status": "new",
        "category_reviewed_by": None,
        "manual_verdict": "unknown",
        "review_status": "new",
        "reviewed_by": None,
        "priority": "normal",
        "is_trusted_ml_label": False,
    }

    # -----------------------------------------------------------------------
    # Preserve reviewer assignment if present
    # -----------------------------------------------------------------------
    # A message may have both:
    # - Reviewing - Ryan
    # - Confirmed Phish
    #
    # In that case, the final verdict should be malicious, but reviewed_by can
    # still be Ryan.
    for category in normalized_categories:
        reviewer_fields = REVIEWING_CATEGORY_MAP.get(category)

        if not reviewer_fields:
            continue

        result.update(reviewer_fields)

        # Stop after the first reviewer category. Your workflow should normally
        # only have one reviewer assigned at a time.
        break

    # -----------------------------------------------------------------------
    # Apply final verdict categories
    # -----------------------------------------------------------------------
    # These categories are trusted labels for reporting and later ML training.
    #
    # Final verdict categories override "in_review" status because the report
    # has been classified.
    for category in normalized_categories:
        final_verdict_fields = FINAL_VERDICT_CATEGORY_MAP.get(category)

        if not final_verdict_fields:
            continue

        result.update(final_verdict_fields)
        result["is_trusted_ml_label"] = True

        # Stop after the first final verdict category. Your workflow should
        # normally only have one final verdict category on a message.
        break

    # -----------------------------------------------------------------------
    # Apply urgent interaction category
    # -----------------------------------------------------------------------
    # This is intentionally evaluated after final verdicts because it should
    # raise urgency if present.
    #
    # However, it sets is_trusted_ml_label back to False because "User Interacted
    # - Urgent" is a workflow/escalation state, not a clean final classification.
    #
    # Example:
    # - If only User Interacted - Urgent is present:
    #       manual_verdict = needs_escalation
    #
    # - If Confirmed Phish and User Interacted - Urgent are both present:
    #       manual_verdict = needs_escalation in this V1 design
    #
    # If you later want Confirmed Phish to remain the final verdict while urgent
    # is stored separately, we can add a separate user_interacted flag.
    for category in normalized_categories:
        urgent_fields = URGENT_CATEGORY_MAP.get(category)

        if not urgent_fields:
            continue

        result.update(urgent_fields)
        result["is_trusted_ml_label"] = False
        break

    return result


def is_trusted_ml_verdict(verdict):
    """
    Return True if a verdict is trusted for future ML training.

    Trusted:
    - malicious
    - spam_or_marketing
    - benign

    Not trusted:
    - unknown
    - needs_escalation
    - in_review/workflow-only labels
    """
    return verdict in TRUSTED_ML_VERDICTS


def get_category_summary(categories):
    """
    Return a small human-readable summary of normalized category results.

    This is useful for debug logs or CLI scripts.

    Args:
        categories: List of Outlook category strings.

    Returns:
        A short dictionary with the most important normalized values.
    """
    normalized = normalize_phishing_categories(categories)

    return {
        "categories": normalized["outlook_categories_raw"],
        "manual_verdict": normalized["manual_verdict"],
        "review_status": normalized["review_status"],
        "reviewed_by": normalized["reviewed_by"],
        "priority": normalized["priority"],
        "is_trusted_ml_label": normalized["is_trusted_ml_label"],
    }