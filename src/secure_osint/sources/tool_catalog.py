# Importare i moduli registra le fonti built-in tramite @register_source.
from secure_osint.sources import (  # noqa: F401
    chain_source,
    crt_sh_source,
    dns_source,
    email_source,
    github_source,
    hackertarget_source,
    image_exif_source,
    phone_source,
    rdap_source,
    shodan_internetdb_source,
    username_source,
    wayback_source,
)
from secure_osint.sources.registry import SourceRegistry


def build_catalog(load_plugins: bool = True) -> SourceRegistry:
    """Build the source registry.

    Args:
        load_plugins: If True, also load third-party sources from entry points.

    Returns:
        A SourceRegistry mapping source name to instance.
    """
    catalog = SourceRegistry()
    if load_plugins:
        catalog.load_entry_points()
    return catalog


tool_catalog = build_catalog(load_plugins=False)
