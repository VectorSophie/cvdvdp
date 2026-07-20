import unittest
from cvd import masking


class TestMasking(unittest.TestCase):
    def test_redacts_email(self):
        out = masking.redact("contact me at researcher@example.com please")
        self.assertNotIn("researcher@example.com", out)
        self.assertIn("[REDACTED:email]", out)

    def test_redacts_cookie_header(self):
        out = masking.redact("Cookie: session=abc123xyz; other=1")
        self.assertNotIn("session=abc123xyz", out)

    def test_redacts_multivalue_cookie_header(self):
        out = masking.redact("Cookie: session=abc123; token=SUPERSECRETKEY99")
        self.assertNotIn("SUPERSECRETKEY99", out)
        self.assertIn("[REDACTED:cookie_header]", out)

    def test_redacts_bearer_token(self):
        out = masking.redact("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", out)

    def test_redacts_korean_phone_number(self):
        out = masking.redact("call 010-1234-5678 for details")
        self.assertNotIn("010-1234-5678", out)

    def test_redacts_korean_rrn_shaped_string(self):
        out = masking.redact("id number 901231-1234567 on file")
        self.assertNotIn("901231-1234567", out)

    def test_leaves_plain_text_alone(self):
        out = masking.redact("logged in as admin, checked the dashboard")
        self.assertEqual(out, "logged in as admin, checked the dashboard")

    def test_contains_sensitive_true_for_email(self):
        self.assertTrue(masking.contains_sensitive("reach me at a@b.com"))

    def test_contains_sensitive_false_for_plain_text(self):
        self.assertFalse(masking.contains_sensitive("nothing sensitive here"))
