"""b3mageuk — Braintree Magento 2 checker for UK/EU stores (forced GB billing)."""

import requests
from .b3magento import check_b3magento


def check_b3mageuk(session: requests.Session, domain: str, card_tuple: tuple, **kwargs) -> dict:
    """Delegate to check_b3magento with GB billing forced."""
    return check_b3magento(session, domain, card_tuple, force_country="GB", **kwargs)
