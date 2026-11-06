import json
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from agent_security_lab.agents import (
    AgentError, MAX_RESPONSE_BYTES, NoRedirect, request_message,
)


class TransportTests(unittest.TestCase):
    @patch("agent_security_lab.agents.build_opener")
    def test_chat_request_uses_documented_tools_and_nonstreaming(self, build):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({
            "message": {"role": "assistant", "content": "done"}
        }).encode()
        build.return_value.open.return_value = response
        result = request_message("http://127.0.0.1:11434/api/chat", "test-model", [])
        request = build.return_value.open.call_args.args[0]
        body = json.loads(request.data)
        self.assertFalse(body["stream"])
        self.assertEqual(body["model"], "test-model")
        self.assertEqual(len(body["tools"]), 4)
        self.assertEqual(result["content"], "done")
        self.assertEqual(build.return_value.open.call_args.kwargs["timeout"], 30)
        response.__enter__.return_value.read.assert_called_once_with(MAX_RESPONSE_BYTES + 1)

    @patch("agent_security_lab.agents.build_opener")
    def test_invalid_response_json_fails(self, build):
        build.return_value.open.return_value.__enter__.return_value.read.return_value = b"not-json"
        with self.assertRaises(AgentError):
            request_message("http://127.0.0.1:11434/api/chat", "test", [])

    @patch("agent_security_lab.agents.build_opener")
    def test_missing_message_fails(self, build):
        build.return_value.open.return_value.__enter__.return_value.read.return_value = b'{"error":"missing model"}'
        with self.assertRaises(AgentError):
            request_message("http://127.0.0.1:11434/api/chat", "test", [])

    @patch("agent_security_lab.agents.build_opener")
    def test_oversized_response_fails(self, build):
        build.return_value.open.return_value.__enter__.return_value.read.return_value = b"x" * (MAX_RESPONSE_BYTES + 1)
        with self.assertRaises(AgentError):
            request_message("http://127.0.0.1:11434/api/chat", "test", [])

    @patch("agent_security_lab.agents.build_opener")
    def test_unreachable_local_model_fails(self, build):
        build.return_value.open.side_effect = URLError("not listening")
        with self.assertRaises(AgentError):
            request_message("http://127.0.0.1:11434/api/chat", "test", [])

    def test_redirects_are_refused(self):
        with self.assertRaises(AgentError):
            NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://example.com")


if __name__ == "__main__":
    unittest.main()
