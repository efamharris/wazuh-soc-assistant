"""Smoke tests for the Flask API with Claude and persistence isolated."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as assistant


class AssistantApiTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.original_db = assistant.DB
        assistant.DB = str(Path(self.tempdir.name) / "history.db")
        assistant.init()
        self.client = assistant.app.test_client()
        self.purge_patch = patch.object(assistant, "purge")
        self.purge_patch.start()

    def tearDown(self):
        self.purge_patch.stop()
        assistant.DB = self.original_db
        self.tempdir.cleanup()

    def test_homepage_serves_chat_ui(self):
        response = self.client.get("/")
        try:
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"SOC Assistant", response.data)
        finally:
            response.close()

    def test_empty_chat_is_rejected(self):
        response = self.client.post("/api/chat", json={"message": "  "})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Empty message")

    def test_chat_saves_user_and_assistant_messages(self):
        with (
            patch.object(assistant.privacy, "tokenise_text", side_effect=lambda value: value),
            patch.object(assistant.privacy, "detokenise_text", side_effect=lambda value: value),
            patch.object(assistant, "run_claude", return_value=("Two recent alerts found.", "session-1", None)),
            patch.object(assistant.privacy_notes, "summary", return_value=None),
        ):
            response = self.client.post("/api/chat", json={"message": "Show recent alerts"})

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["answer"], "Two recent alerts found.")
        self.assertFalse(payload["error"])

        history = self.client.get(f"/api/chats/{payload['chat_id']}")
        messages = history.get_json()
        self.assertEqual([message["role"] for message in messages], ["user", "assistant"])
        self.assertEqual(messages[0]["content"], "Show recent alerts")
        self.assertEqual(messages[1]["content"], "Two recent alerts found.")


if __name__ == "__main__":
    unittest.main()
