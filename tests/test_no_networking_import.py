import ast
import pathlib
import unittest

CVD_DIR = pathlib.Path(__file__).parent.parent / "cvd"

FORBIDDEN_MODULES = {
    "requests",
    "httpx",
    "urllib.request",
    "http.client",
    "socket",
    "aiohttp",
    "urllib3",
}


def _imported_modules(path: pathlib.Path) -> set:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


class TestNoNetworkingImport(unittest.TestCase):
    def test_no_forbidden_networking_modules_anywhere_in_cvd(self):
        offenders = []
        for path in CVD_DIR.rglob("*.py"):
            found = _imported_modules(path) & FORBIDDEN_MODULES
            if found:
                offenders.append((str(path), found))
        self.assertEqual(offenders, [], f"Networking-capable imports found: {offenders}")
