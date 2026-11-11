"""
Unit tests for EmailReportNotifier and Web Server Email API endpoints.
"""

import email
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import web_server
from orchestrator.email_notifier import EmailReportNotifier
from web_server import MultiAgentAPIHandler


class TestEmailReportNotifier(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_email_notifier_"))
        self._saved_env = dict(os.environ)
        for key in list(os.environ.keys()):
            if key.startswith("EMAIL_") or key.startswith("SMTP_"):
                os.environ.pop(key, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._saved_env)
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_dotenv_loading_and_password_masking(self):
        dotenv = self.temp_dir / ".env"
        dotenv.write_text(
            "EMAIL_FROM=sender@gmail.com\n"
            "EMAIL_TO=alice@example.com, bob@example.com\n"
            "SMTP_HOST=smtp.gmail.com\n"
            "SMTP_PORT=587\n"
            "SMTP_USERNAME=sender@gmail.com\n"
            "SMTP_PASSWORD=abcd efgh ijkl mnop\n",
            encoding="utf-8",
        )
        notifier = EmailReportNotifier(app_root_dir=self.temp_dir)
        pub = notifier.get_public_config()

        self.assertEqual(pub["sender_email"], "sender@gmail.com")
        self.assertEqual(pub["recipient_emails"], ["alice@example.com", "bob@example.com"])
        self.assertEqual(pub["smtp_host"], "smtp.gmail.com")
        self.assertTrue(pub["has_smtp_password"])
        self.assertEqual(pub["smtp_password"], "********")

    def test_outbox_archive_and_attachments(self):
        notifier = EmailReportNotifier(app_root_dir=self.temp_dir)
        notifier.update_config({
            "recipient_emails": "secops@example.com",
            "smtp_host": "",
            "attach_remediation_html": True,
            "attach_scan_html": True,
            "attach_remediation_json": True,
        })

        res = notifier.send_remediation_report_email(
            repo_name="CustomerApi",
            workspace_path="/tmp/CustomerApi",
            branch="remediation/airgap-api-compliance",
            base_branch="main",
            remediation_result={
                "all_threats": [
                    {"finding_id": "SQLI-001", "severity": "CRITICAL", "rule_id": "sql-injection", "file_path": "UsersController.cs"}
                ],
                "files_modified": ["Controllers/UsersController.cs"],
                "iterations_run": 1,
            },
            post_scan_result={"findings": [], "posture": {"score": 100, "grade": "A+"}},
            remediation_html="<html><body>Remediation Report</body></html>",
            scan_html="<html><body>Scan Report</body></html>",
            remediation_json='{"status": "compliant"}',
            custom_note="Automated verification passed.",
        )

        self.assertEqual(res["status"], "saved_to_outbox")
        self.assertEqual(len(res["attachments"]), 3)
        eml_path = Path(res["outbox_file"])
        self.assertTrue(eml_path.exists())

        parsed = email.message_from_bytes(eml_path.read_bytes())
        self.assertIn("CustomerApi", parsed["Subject"])
        self.assertEqual(parsed["To"], "secops@example.com")

    @patch("orchestrator.email_notifier.smtplib.SMTP")
    def test_smtp_starttls_delivery_strips_gmail_app_password_spaces(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__.return_value = mock_server

        notifier = EmailReportNotifier(app_root_dir=self.temp_dir)
        notifier.update_config({
            "sender_email": "bot@gmail.com",
            "recipient_emails": "lead@example.com",
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "smtp_username": "bot@gmail.com",
            "smtp_password": "abcd efgh ijkl mnop",
            "use_tls": True,
            "use_ssl": False,
        })

        res = notifier.send_remediation_report_email(
            repo_name="DemoRepo",
            remediation_html="<html><body>OK</body></html>",
        )

        self.assertEqual(res["status"], "sent")
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("bot@gmail.com", "abcdefghijklmnop")
        mock_server.send_message.assert_called_once()

    def test_web_server_email_endpoints(self):
        orig_notifier = web_server.EMAIL_NOTIFIER
        try:
            web_server.EMAIL_NOTIFIER = EmailReportNotifier(app_root_dir=self.temp_dir)

            # POST /api/email/config
            body = json.dumps({"recipient_emails": "team@example.com", "smtp_host": ""}).encode("utf-8")
            handler = MultiAgentAPIHandler.__new__(MultiAgentAPIHandler)
            handler.rfile = io.BytesIO(body)
            handler.wfile = io.BytesIO()
            handler.headers = {"Content-Length": str(len(body))}
            handler.path = "/api/email/config"
            handler.send_response = MagicMock()
            handler.send_header = MagicMock()
            handler.end_headers = MagicMock()
            handler.do_POST()
            cfg_resp = json.loads(handler.wfile.getvalue().decode("utf-8"))
            self.assertEqual(cfg_resp["config"]["recipient_emails"], ["team@example.com"])

            # POST /api/email/send-report
            send_body = b"{}"
            handler2 = MultiAgentAPIHandler.__new__(MultiAgentAPIHandler)
            handler2.rfile = io.BytesIO(send_body)
            handler2.wfile = io.BytesIO()
            handler2.headers = {"Content-Length": str(len(send_body))}
            handler2.path = "/api/email/send-report"
            handler2.send_response = MagicMock()
            handler2.send_header = MagicMock()
            handler2.end_headers = MagicMock()
            handler2.do_POST()
            send_resp = json.loads(handler2.wfile.getvalue().decode("utf-8"))
            self.assertEqual(send_resp["status"], "saved_to_outbox")
            self.assertEqual(send_resp["recipients"], ["team@example.com"])
        finally:
            web_server.EMAIL_NOTIFIER = orig_notifier


if __name__ == "__main__":
    unittest.main()
