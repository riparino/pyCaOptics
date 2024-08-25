import unittest

class TestPolicyAnalysis(unittest.TestCase):
    def test_analysis_with_complete_data(self):
        from src.pyCaOptics_app import ca_optics_like_analysis
        policies = [{
            'displayName': 'Test Policy',
            'state': 'enabled',
            'conditions': {
                'users': {'includeUsers': ['All'], 'excludeUsers': ['User1']},
                'applications': {'includeApplications': ['All'], 'excludeApplications': ['App1']}
            },
            'grantControls': {'builtInControls': ['mfa']}
        }]
        users = [{'id': 'User1'}, {'id': 'User2'}]
        groups = []
        applications = [{'appId': 'App1'}, {'appId': 'App2'}]

        result = ca_optics_like_analysis(policies, users, groups, applications)
        self.assertIn('Uncovered users: {\'User2\'}', str(result))
        self.assertIn('Uncovered applications: {\'App2\'}', str(result))

    def test_analysis_with_missing_keys(self):
        from src.pyCaOptics_app import ca_optics_like_analysis
        policies = [{
            'displayName': 'Incomplete Policy',
            'state': 'enabled',
            # Missing 'conditions'
        }]
        users = [{'id': 'User1'}]
        groups = []
        applications = [{'appId': 'App1'}]

        result = ca_optics_like_analysis(policies, users, groups, applications)
        self.assertIn('Unnamed Policy', str(result))

if __name__ == '__main__':
    unittest.main()
