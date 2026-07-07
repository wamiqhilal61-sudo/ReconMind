"""core/utils/http_client.py — Shared HTTP client for wamiqsec/ReconMind."""

from typing import Optional, Dict, Any
import urllib3
import requests
from requests import Response, Session

from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _build_session() -> Session:
    cfg = CONFIG.network
    session = requests.Session()
    session.headers.update(cfg.default_headers)
    if cfg.proxies:
        session.proxies.update(cfg.proxies)
        log.debug("HTTP proxy configured: %s", cfg.proxies)
    session.max_redirects = cfg.max_redirects
    return session


SESSION: Session = _build_session()


def safe_get(
    url: str,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    allow_redirects: bool = True,
) -> Optional[Response]:
    cfg = CONFIG.network
    try:
        response = SESSION.get(
            url, params=params, headers=headers,
            timeout=cfg.request_timeout, verify=cfg.verify_ssl,
            allow_redirects=allow_redirects,
        )
        log.debug("GET %s -> HTTP %d (%d bytes)", url, response.status_code, len(response.content))
        return response
    except requests.exceptions.ConnectionError as exc:
        log.warning("Connection failed for %s: %s", url, exc)
    except requests.exceptions.Timeout:
        log.warning("Request timed out: %s", url)
    except requests.exceptions.TooManyRedirects:
        log.warning("Too many redirects: %s", url)
    except requests.exceptions.RequestException as exc:
        log.error("Unexpected request error for %s: %s", url, exc)
    return None


def safe_post(
    url: str,
    data: Optional[Dict[str, Any]] = None,
    json: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    allow_redirects: bool = True,
) -> Optional[Response]:
    cfg = CONFIG.network
    try:
        response = SESSION.post(
            url, data=data, json=json, headers=headers,
            timeout=cfg.request_timeout, verify=cfg.verify_ssl,
            allow_redirects=allow_redirects,
        )
        log.debug("POST %s -> HTTP %d (%d bytes)", url, response.status_code, len(response.content))
        return response
    except requests.exceptions.ConnectionError as exc:
        log.warning("Connection failed for %s: %s", url, exc)
    except requests.exceptions.Timeout:
        log.warning("Request timed out: %s", url)
    except requests.exceptions.RequestException as exc:
        log.error("Unexpected request error for %s: %s", url, exc)
    return None
