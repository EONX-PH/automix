"""b3magus — Braintree Magento 2 checker for US stores (forced US billing)."""

import requests
from .b3magento import check_b3magento


def check_b3magus(session: requests.Session, domain: str, card_tuple: tuple, **kwargs) -> dict:
    """Delegate to check_b3magento with US billing forced."""
    return check_b3magento(session, domain, card_tuple, force_country="US", **kwargs)
