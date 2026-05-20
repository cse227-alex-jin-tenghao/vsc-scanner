"""Parse extension identifiers into (publisher, name) pairs."""

from urllib.parse import parse_qs, urlparse

_MARKETPLACE_HOST = "marketplace.visualstudio.com"


def parse_marketplace_url(url: str) -> tuple[str, str]:
    """Extract (publisher, name) from a VSCode Marketplace URL.

    Raises ValueError if the URL is not a valid marketplace item URL.
    """
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.netloc != _MARKETPLACE_HOST:
        raise ValueError(f"not a marketplace URL: {url!r}")
    if parsed.path.rstrip("/") != "/items":
        raise ValueError(f"marketplace URL must point to /items: {url!r}")

    item_name_values = parse_qs(parsed.query).get("itemName")
    if not item_name_values:
        raise ValueError(f"marketplace URL is missing itemName: {url!r}")

    item_name = item_name_values[0]
    if item_name.count(".") != 1:
        raise ValueError(f"itemName must be 'publisher.name': {item_name!r}")

    publisher, name = item_name.split(".", 1)
    if not publisher or not name:
        raise ValueError(f"empty publisher or name in itemName: {item_name!r}")
    return publisher, name
