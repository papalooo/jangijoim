import os
import sys
import tempfile
import textwrap
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)

from core.schemas import DastSastResult, MappingConfidenceBand, MappingMethod
from mapping.ast_parser import map_vulnerability_to_code


class Stage3MappingContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_ast_exact_match_contract(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            app_path = os.path.join(temp_dir, "app.py")
            with open(app_path, "w", encoding="utf-8") as f:
                f.write(textwrap.dedent("""
                    from fastapi import FastAPI, Form

                    app = FastAPI()

                    @app.post("/api/login")
                    async def login_sqli(username: str = Form(...), password: str = Form(...)):
                        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
                        return query
                """).strip())

            dast = DastSastResult(
                target_endpoint="/api/login",
                http_method="POST",
                vuln_type="SQL Injection",
                severity="High",
                payload="' OR 1=1 --",
                sliced_response="sqlite error",
            )

            mapped = await map_vulnerability_to_code(dast, temp_dir)

            self.assertTrue(mapped.is_mapped)
            self.assertEqual(mapped.mapping_method, MappingMethod.AST_LIGHT)
            self.assertGreaterEqual(mapped.mapping_confidence, 0.6)
            self.assertIn(mapped.mapping_confidence_band, {MappingConfidenceBand.HIGH, MappingConfidenceBand.MEDIUM})
            self.assertIsNotNone(mapped.mapped_file_path)
            self.assertIsNotNone(mapped.mapped_symbol)
            self.assertTrue(len(mapped.mapping_evidence) > 0)
            self.assertIsNone(mapped.mapping_failure_reason)

    async def test_full_scan_fallback_contract(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            app_path = os.path.join(temp_dir, "handlers.py")
            with open(app_path, "w", encoding="utf-8") as f:
                f.write(textwrap.dedent("""
                    def login_handler(username, password):
                        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
                        return query
                """).strip())

            dast = DastSastResult(
                target_endpoint="/login",
                http_method="POST",
                vuln_type="SQL Injection",
                severity="High",
                payload="username admin password",
                sliced_response="syntax error",
            )

            mapped = await map_vulnerability_to_code(dast, temp_dir)

            self.assertTrue(mapped.is_mapped)
            self.assertEqual(mapped.mapping_method, MappingMethod.FULL_SCAN)
            self.assertGreater(mapped.mapping_confidence, 0.0)
            self.assertTrue(len(mapped.mapping_evidence) > 0)
            self.assertIsNone(mapped.mapping_failure_reason)

    async def test_unmapped_contract_fields(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            app_path = os.path.join(temp_dir, "safe.py")
            with open(app_path, "w", encoding="utf-8") as f:
                f.write("def healthcheck():\n    return {'status': 'ok'}\n")

            dast = DastSastResult(
                target_endpoint="/api/does-not-exist",
                http_method="GET",
                vuln_type="Unknown Vulnerability",
                severity="Low",
                payload="noop",
                sliced_response="n/a",
            )

            mapped = await map_vulnerability_to_code(dast, temp_dir)

            self.assertFalse(mapped.is_mapped)
            self.assertEqual(mapped.mapping_method, MappingMethod.NONE)
            self.assertEqual(mapped.mapping_confidence, 0.0)
            self.assertEqual(mapped.mapping_confidence_band, MappingConfidenceBand.NONE)
            self.assertIsNotNone(mapped.mapping_failure_reason)
            self.assertTrue(len(mapped.mapping_evidence) > 0)


if __name__ == "__main__":
    unittest.main()
