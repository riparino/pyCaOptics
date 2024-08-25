import os
import sys
import requests
import pandas as pd
from datetime import datetime
from itertools import product
from azure.identity import InteractiveBrowserCredential

def fetch_policies(tenant_id, client_id):
    """
    Fetches all Conditional Access policies from Microsoft Graph API.
    """
    token_credential = InteractiveBrowserCredential(client_id=client_id)
    token = token_credential.get_token('https://graph.microsoft.com/.default')
    headers = {
        'Authorization': f'Bearer {token.token}',
        'Content-Type': 'application/json'
    }
    url = f'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print(f"Error fetching data from {url}: {response.status_code} {response.reason}")
        return []

    return response.json().get('value', [])

def generate_permutations(policies):
    """
    Generates permutations for each policy based on users, apps, platforms, locations, and client apps.
    """
    all_permutations = []
    
    for policy in policies:
        users = policy['conditions'].get('users', {}).get('includeUsers', []) + \
                policy['conditions'].get('users', {}).get('excludeUsers', [])
        
        groups = policy['conditions'].get('users', {}).get('includeGroups', []) + \
                 policy['conditions'].get('users', {}).get('excludeGroups', [])
        
        apps = policy['conditions'].get('applications', {}).get('includeApplications', []) + \
               policy['conditions'].get('applications', {}).get('excludeApplications', [])
        
        # Ensure platforms is not None before accessing its keys
        platforms_data = policy['conditions'].get('platforms')
        if platforms_data is None:
            platforms = []
        else:
            platforms = platforms_data.get('includePlatforms', []) + platforms_data.get('excludePlatforms', [])
        
        # Ensure locations is not None before accessing its keys
        locations_data = policy['conditions'].get('locations')
        if locations_data is None:
            locations = []
        else:
            locations = locations_data.get('includeLocations', []) + locations_data.get('excludeLocations', [])
        
        client_apps = policy['conditions'].get('clientAppTypes', [])

        permutations = list(product(users, groups, apps, platforms, locations, client_apps))
        all_permutations.extend(permutations)
    
    return all_permutations

def analyze_permutations(policies):
    """
    Analyzes all permutations to check if there are any gaps or conflicts in the policy settings.
    """
    all_permutations = generate_permutations(policies)
    gaps = []
    conflicts = []

    for policy in policies:
        for permutation in all_permutations:
            user, group, app, platform, location, client_app = permutation

            # Check if this permutation is covered by the policy
            if not is_permutation_covered(policy, user, group, app, platform, location, client_app):
                gaps.append({
                    'policy': policy['displayName'],
                    'permutation': permutation,
                    'issue': 'Uncovered permutation'
                })

            # Check for conflicts
            if is_conflicting_policy(policy, user, group, app, platform, location, client_app):
                conflicts.append({
                    'policy': policy['displayName'],
                    'permutation': permutation,
                    'issue': 'Conflicting policy settings'
                })
    
    return gaps, conflicts

def is_permutation_covered(policy, user, group, app, platform, location, client_app):
    """
    Checks if a given permutation is covered by the policy.
    """
    conditions = policy.get('conditions', {})

    # Check users and groups
    if user in conditions.get('users', {}).get('excludeUsers', []) or \
       group in conditions.get('users', {}).get('excludeGroups', []):
        return False
    
    if user not in conditions.get('users', {}).get('includeUsers', []) and \
       group not in conditions.get('users', {}).get('includeGroups', []):
        return False
    
    # Check apps
    if app in conditions.get('applications', {}).get('excludeApplications', []):
        return False
    
    if app not in conditions.get('applications', {}).get('includeApplications', []):
        return False
    
    # Check platforms
    if platform in conditions.get('platforms', {}).get('excludePlatforms', []):
        return False
    
    if platform not in conditions.get('platforms', {}).get('includePlatforms', []):
        return False
    
    # Check locations
    if location in conditions.get('locations', {}).get('excludeLocations', []):
        return False
    
    if location not in conditions.get('locations', {}).get('includeLocations', []):
        return False
    
    # Check client apps
    if client_app not in conditions.get('clientAppTypes', []):
        return False

    return True

def is_conflicting_policy(policy, user, group, app, platform, location, client_app):
    """
    Checks if the policy has conflicting settings for the given permutation.
    """
    # Implement logic to detect conflicts between multiple policies or within the same policy
    # Example: One policy grants access while another denies it for the same permutation
    return False

def save_results(gaps, conflicts):
    """
    Saves the analysis results to a CSV file.
    """
    try:
        # Define the output directory relative to the current script location
        output_dir = os.path.join(os.path.dirname(__file__), '..', 'outputs')
        os.makedirs(output_dir, exist_ok=True)
        
        # Prepare file names with timestamps
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        gaps_filename = os.path.join(output_dir, 'gaps_results.csv')
        conflicts_filename = os.path.join(output_dir, 'conflicts_results.csv')

        # Check if files already exist and add timestamp if they do
        if os.path.exists(gaps_filename):
            gaps_filename = os.path.join(output_dir, f'gaps_results_{timestamp}.csv')
        
        if os.path.exists(conflicts_filename):
            conflicts_filename = os.path.join(output_dir, f'conflicts_results_{timestamp}.csv')

        # Convert lists to DataFrames
        df_gaps = pd.DataFrame(gaps)
        df_conflicts = pd.DataFrame(conflicts)

        # Save DataFrames to CSV files
        df_gaps.to_csv(gaps_filename, index=False)
        df_conflicts.to_csv(conflicts_filename, index=False)

        print(f"Analysis complete. Gaps saved to '{gaps_filename}'. Conflicts saved to '{conflicts_filename}'.")
    
    except Exception as e:
        print(f"Error saving the results to file: {e}")
        sys.exit(1)

def main(tenant_id, client_id):
    policies = fetch_policies(tenant_id, client_id)
    if not policies:
        print("No policies found or an error occurred during policy retrieval.")
        return

    gaps, conflicts = analyze_permutations(policies)
    save_results(gaps, conflicts)

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print("Usage: python pyCaOptics_app.py <tenant_id> <client_id>")
    else:
        tenant_id = sys.argv[1]
        client_id = sys.argv[2]
        main(tenant_id, client_id)
