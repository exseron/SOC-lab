"""SOC_Lab.py sunucu testleri: python -m unittest discover -s tests"""

import http.client
import shutil
import subprocess
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import SOC_Lab  # noqa: E402


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = SOC_Lab.create_server(0)  # 0: işletim sistemi boş port seçer
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, path, method="GET", host=None):
        connection = http.client.HTTPConnection(SOC_Lab.HOST, self.port, timeout=5)
        connection.request(method, path, headers={"Host": host or f"127.0.0.1:{self.port}"})
        response = connection.getresponse()
        body = response.read()
        connection.close()
        return response, body

    def test_serves_every_asset_with_content_type(self):
        for name, content_type in SOC_Lab.CONTENT_TYPES.items():
            with self.subTest(name=name):
                response, body = self.request(f"/{name}")
                self.assertEqual(response.status, 200)
                self.assertEqual(response.getheader("Content-Type"), content_type)
                self.assertEqual(int(response.getheader("Content-Length")), len(body))

    def test_root_is_index(self):
        response, body = self.request("/?utm=x")
        self.assertEqual(response.status, 200)
        self.assertIn(b"SOC / LAB", body)

    def test_security_headers_on_success_and_error(self):
        for path in ["/", "/missing"]:
            with self.subTest(path=path):
                response, _ = self.request(path)
                for header, value in SOC_Lab.SECURITY_HEADERS.items():
                    self.assertEqual(response.getheader(header), value)

    def test_unknown_and_traversal_paths_404(self):
        for path in ["/missing", "/../SOC_Lab.py", "/%2e%2e/SOC_Lab.py", "/SOC_Lab.py"]:
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0].status, 404)

    def test_rejects_foreign_host_header(self):
        response, _ = self.request("/", host=f"evil.example:{self.port}")
        self.assertEqual(response.status, 421)

    def test_accepts_localhost_host_header(self):
        response, _ = self.request("/", host=f"localhost:{self.port}")
        self.assertEqual(response.status, 200)

    def test_head_has_no_body(self):
        response, body = self.request("/app.js", method="HEAD")
        self.assertEqual(response.status, 200)
        self.assertEqual(body, b"")

    def test_post_not_supported(self):
        self.assertEqual(self.request("/", method="POST")[0].status, 501)


class BuildTests(unittest.TestCase):
    def test_embedded_assets_match_web_sources(self):
        result = subprocess.run([sys.executable, str(ROOT / "tools" / "build.py"), "--check"],
                                capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_embedded_archive_contains_all_assets(self):
        self.assertEqual(set(SOC_Lab.load_assets()), set(SOC_Lab.CONTENT_TYPES))


@unittest.skipUnless(shutil.which("node"), "Node.js kurulu değil")
class FrontendTests(unittest.TestCase):
    def run_node(self, *args):
        return subprocess.run(["node", *args], cwd=ROOT, capture_output=True, text=True,
                              encoding="utf-8", errors="replace")

    def test_scripts_parse(self):
        for name in ["data.js", "exercises.js", "app.js"]:
            with self.subTest(name=name):
                result = self.run_node("--check", str(ROOT / "web" / name))
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_alarm_data_is_valid(self):
        result = self.run_node(str(ROOT / "tests" / "validate_data.mjs"))
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
