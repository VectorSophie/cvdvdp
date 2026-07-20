import json
import pathlib
import urllib.parse
from . import scope_guard


def extract_urls(har_path: pathlib.Path) -> list:
    """
    Extract all request URLs from a HAR file.

    Returns raw, unsanitized URLs including query strings and fragments.
    WARNING: These URLs may contain sensitive data (tokens, session IDs, etc).
    Do NOT expose directly to CLI output, logs, or reports. Callers must
    sanitize using _sanitize() or use analyze() which handles this internally.
    """
    data = json.loads(har_path.read_text(encoding="utf-8"))
    urls = []
    for entry in data.get("log", {}).get("entries", []):
        url = entry.get("request", {}).get("url")
        if url:
            urls.append(url)
    return urls


def _sanitize(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def analyze(policy_obj, har_path: pathlib.Path) -> dict:
    urls = extract_urls(har_path)
    unique_urls = sorted(set(urls))
    results = []
    for url in unique_urls:
        result = scope_guard.check_url(policy_obj, url)
        # sanitize immediately so no downstream code can accidentally echo a raw URL with query params/tokens
        sanitized_url = _sanitize(url)
        results.append((sanitized_url, result))

    flagged = []
    for sanitized_url, result in results:
        if result.verdict != "ALLOWED":
            flagged.append({"url_sanitized": sanitized_url, "verdict": result.verdict, "reason": result.reason})

    return {
        "total_unique_requests": len(unique_urls),
        "allowed": sum(1 for _, r in results if r.verdict == "ALLOWED"),
        "denied": sum(1 for _, r in results if r.verdict == "DENIED"),
        "needs_clarification": sum(1 for _, r in results if r.verdict == "NEEDS_CLARIFICATION"),
        "not_applicable": sum(1 for _, r in results if r.verdict == "NOT_APPLICABLE"),
        "flagged": flagged,
    }
