import unittest
from unittest.mock import patch
import requests

class TestDataRetrieval(unittest.TestCase):
    @patch('requests.get')
    def test_single_page_data(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'value': [{'id': '1', 'name': 'Policy1'}],
            '@odata.nextLink': None
        }
        from src.pyCaOptics_app import fetch_paginated_data
        data = fetch_paginated_data('https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies', headers={})
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['id'], '1')

    @patch('requests.get')
    def test_pagination(self, mock_get):
        # Simulate two pages of data
        mock_get.side_effect = [
            unittest.mock.Mock(status_code=200, json=lambda: {
                'value': [{'id': '1', 'name': 'Policy1'}],
                '@odata.nextLink': 'https://next-page'
            }),
            unittest.mock.Mock(status_code=200, json=lambda: {
                'value': [{'id': '2', 'name': 'Policy2'}],
                '@odata.nextLink': None
            }),
        ]
        from src.pyCaOptics_app import fetch_paginated_data
        data = fetch_paginated_data('https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies', headers={})
        self.assertEqual(len(data), 2)
        self.assertEqual(data[1]['id'], '2')

    @patch('requests.get')
    def test_api_error(self, mock_get):
        mock_get.return_value.status_code = 403
        mock_get.return_value.json.return_value = {}
        from src.pyCaOptics_app import fetch_paginated_data
        with self.assertRaises(SystemExit):
            fetch_paginated_data('https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies', headers={})

if __name__ == '__main__':
    unittest.main()
