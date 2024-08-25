import unittest
import os
from unittest.mock import patch
import pandas as pd

class TestSaveResults(unittest.TestCase):
    @patch('pandas.DataFrame.to_csv')
    def test_save_results(self, mock_to_csv):
        from src.pyCaOptics_app import save_results
        df = pd.DataFrame([{'Policy Name': 'Test Policy', 'State': 'enabled', 'Gaps Identified': []}])
        save_results(df)
        self.assertTrue(mock_to_csv.called)
        args, kwargs = mock_to_csv.call_args
        self.assertIn('output', args[0])  # Check that the path includes 'output' directory

    def test_save_results_with_timestamp(self):
        from src.pyCaOptics_app import save_results
        df = pd.DataFrame([{'Policy Name': 'Test Policy', 'State': 'enabled', 'Gaps Identified': []}])
        output_dir = os.path.join(os.path.dirname(__file__), '..', 'output')
        os.makedirs(output_dir, exist_ok=True)
        output_filename = os.path.join(output_dir, 'ca_optics_analysis_results.csv')
        with open(output_filename, 'w') as f:
            f.write('Dummy content')

        save_results(df)
        files = os.listdir(output_dir)
        self.assertTrue(any('ca_optics_analysis_results_' in f for f in files))

if __name__ == '__main__':
    unittest.main()
