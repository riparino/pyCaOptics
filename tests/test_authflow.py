import unittest
from unittest.mock import patch
from azure.identity import InteractiveBrowserCredential

class TestAuthentication(unittest.TestCase):
    @patch('azure.identity.InteractiveBrowserCredential.get_token')
    def test_valid_token(self, mock_get_token):
        mock_get_token.return_value.token = "mock-token"
        credential = InteractiveBrowserCredential()
        token = credential.get_token("https://graph.microsoft.com/.default")
        self.assertEqual(token.token, "mock-token")

    @patch('azure.identity.InteractiveBrowserCredential.get_token')
    def test_invalid_token(self, mock_get_token):
        mock_get_token.side_effect = Exception("Authentication failed")
        credential = InteractiveBrowserCredential()
        with self.assertRaises(Exception) as context:
            credential.get_token("https://graph.microsoft.com/.default")
        self.assertIn("Authentication failed", str(context.exception))

if __name__ == '__main__':
    unittest.main()
