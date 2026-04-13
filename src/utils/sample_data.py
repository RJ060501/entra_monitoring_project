"""
Sample Data for Testing

Allows the program to run without live API access.
"""

def sample_signins():
    return [
        {"user": "user1@company.com", "hour": 2, "location": "NY", "new_location": True},
        {"user": "user2@company.com", "hour": 14, "location": "UT", "new_location": False},
    ]


def sample_audits():
    return [
        {"user": "user1@company.com", "action": "Add role"},
        {"user": "user2@company.com", "action": "Login"},
    ]
