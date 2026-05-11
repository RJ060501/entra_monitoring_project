from config.settings import load_settings
from clients.m365_audit_client import M365AuditClient


def main():
    settings = load_settings()
    client = M365AuditClient(settings)
    client.start_exchange_subscription()


if __name__ == "__main__":
    main()