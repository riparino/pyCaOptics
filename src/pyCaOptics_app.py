import json
import requests
import pandas as pd
import sys
import os
from datetime import datetime
from azure.identity import InteractiveBrowserCredential

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

def load_tenant_config(config_path):
    """Load tenant configurations from a JSON or YAML file.

    The file should contain a list of objects with 'tenant_id' and 'client_id' keys,
    or a dict with a 'tenants' key containing that list.
    """
    try:
        with open(config_path, 'r') as f:
            if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                if not YAML_AVAILABLE:
                    print("pyyaml is required to load YAML config files. Install it with: pip install pyyaml")
                    sys.exit(1)
                config = yaml.safe_load(f)
            else:
                config = json.load(f)
        if isinstance(config, list):
            return config
        if isinstance(config, dict) and 'tenants' in config:
            return config['tenants']
        print(f"Invalid config format in {config_path}. Expected a list or a dict with a 'tenants' key.")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading config file {config_path}: {e}")
        sys.exit(1)

def main(tenant_id=None, client_id=None, config_path=None):
    tenants = []
    if config_path:
        tenants = load_tenant_config(config_path)
    elif tenant_id and client_id:
        tenants = [{"tenant_id": tenant_id, "client_id": client_id}]
    else:
        print("Must provide either (tenant_id, client_id) or a --config config file path.")
        sys.exit(1)

    for tenant in tenants:
        analyze_tenant(tenant["tenant_id"], tenant["client_id"])

def analyze_tenant(tenant_id, client_id):
    try:
        credentials = InteractiveBrowserCredential(client_id=client_id, tenant_id=tenant_id)
        token = credentials.get_token("https://graph.microsoft.com/.default")

        headers = {
            "Authorization": f"Bearer {token.token}",
            "Content-Type": "application/json"
        }

        endpoints = {
            "policies": "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
            "users": "https://graph.microsoft.com/v1.0/users",
            "groups": "https://graph.microsoft.com/v1.0/groups",
            "applications": "https://graph.microsoft.com/v1.0/applications"
        }

        data = fetch_data(headers, endpoints)
        export_policies_to_json(data['policies'], tenant_id)
        analysis_results = ca_optics_like_analysis(data['policies'], data['users'], data['groups'], data['applications'])
        df_analysis = pd.DataFrame(analysis_results)
        save_results(df_analysis, tenant_id)

    except requests.exceptions.RequestException as e:
        print(f"Error in API request: {e}")
        sys.exit(1)
    except KeyError as e:
        print(f"A key error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

def fetch_data(headers, endpoints):
    data = {}
    for key, url in endpoints.items():
        try:
            data[key] = fetch_paginated_data(url, headers)
        except requests.exceptions.RequestException as e:
            print(f"Error fetching data from {url}: {e}")
            print(f"Response headers: {e.response.headers}")
            print(f"Response content: {e.response.content}")
            sys.exit(1)
    return data

def fetch_paginated_data(url, headers):
    try:
        items = []
        while url:
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                print(f"Error fetching data from {url}: HTTP {response.status_code} {response.reason}")
                sys.exit(1)
            data = response.json()
            items.extend(data.get('value', []))
            url = data.get('@odata.nextLink')
        return items
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from {url}: {e}")
        sys.exit(1)

def export_policies_to_json(policies, tenant_id=None):
    """Export all fetched Conditional Access policies to a JSON file."""
    try:
        output_dir = os.path.join(os.path.dirname(__file__), '..', 'output')
        os.makedirs(output_dir, exist_ok=True)

        suffix = f"_{tenant_id}" if tenant_id else ""
        output_filename = os.path.join(output_dir, f'ca_policies{suffix}.json')
        if os.path.exists(output_filename):
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_filename = os.path.join(output_dir, f'ca_policies{suffix}_{timestamp}.json')

        with open(output_filename, 'w') as f:
            json.dump(policies, f, indent=2)
        print(f"Policies exported to '{output_filename}'.")
    except Exception as e:
        print(f"Error exporting policies to JSON: {e}")

def ca_optics_like_analysis(policies, all_users, all_groups, all_applications):
    analysis_results = []
    all_user_ids = {user.get('id') for user in all_users if user.get('id')}
    all_group_ids = {group.get('id') for group in all_groups if group.get('id')}
    all_application_ids = {app.get('appId') for app in all_applications if app.get('appId')}

    excluded_users, excluded_groups, excluded_applications = set(), set(), set()

    for policy in policies:
        try:
            state = policy.get('state')
            if state is None:
                continue

            conditions = policy.get('conditions')
            if not conditions:
                analysis_results.append({
                    'Policy Name': policy.get('displayName', 'Unnamed Policy'),
                    'State': state,
                    'Gaps Identified': ['Policy is missing a conditions block.']
                })
                continue

            users_included = set(conditions.get('users', {}).get('includeUsers', []))
            users_excluded = set(conditions.get('users', {}).get('excludeUsers', []))
            groups_included = set(conditions.get('users', {}).get('includeGroups', []))
            groups_excluded = set(conditions.get('users', {}).get('excludeGroups', []))
            applications_included = set(conditions.get('applications', {}).get('includeApplications', []))
            applications_excluded = set(conditions.get('applications', {}).get('excludeApplications', []))

            grant_controls = policy.get('grantControls') or {}

            user_risk_levels = conditions.get('userRiskLevels', [])
            sign_in_risk_levels = conditions.get('signInRiskLevels', [])
            session_controls = policy.get('sessionControls', {})
            platforms = conditions.get('platforms', {})
            device_states = conditions.get('deviceStates', {})

            excluded_users.update(users_excluded)
            excluded_groups.update(groups_excluded)
            excluded_applications.update(applications_excluded)

            gaps = []

            if state != 'enabled':
                gaps.append("Policy is not enabled.")
            if not user_risk_levels and not sign_in_risk_levels:
                gaps.append("Policy does not consider user or sign-in risk levels.")
            if not platforms:
                gaps.append("No platforms specified.")
            if not device_states:
                gaps.append("No device state conditions specified.")
            if not session_controls:
                gaps.append("No session controls applied.")

            # Inclusion checks
            if not users_included and not groups_included:
                gaps.append("No users or groups included; policy may not apply to anyone.")
            if not applications_included:
                gaps.append("No applications included; policy may not apply to any application.")

            # Overlap between inclusions and exclusions
            overlapping_users = (users_included & users_excluded) - {'All', 'GuestsOrExternalUsers', 'None'}
            if overlapping_users:
                gaps.append(f"Users appear in both inclusions and exclusions: {overlapping_users}")
            overlapping_apps = (applications_included & applications_excluded) - {'All', 'None', 'Office365'}
            if overlapping_apps:
                gaps.append(f"Applications appear in both inclusions and exclusions: {overlapping_apps}")

            # Check for unknown entities referenced in inclusions
            reserved_user_values = {'All', 'GuestsOrExternalUsers', 'None'}
            unknown_included_users = users_included - reserved_user_values - all_user_ids
            if unknown_included_users:
                gaps.append(f"Included users not found in directory: {unknown_included_users}")

            reserved_app_values = {'All', 'None', 'Office365', 'MicrosoftAdminPortals'}
            unknown_included_apps = applications_included - reserved_app_values - all_application_ids
            if unknown_included_apps:
                gaps.append(f"Included applications not found in directory: {unknown_included_apps}")

            if 'All' in users_included and users_excluded:
                gaps.append("Policy includes all users but has exclusions.")
            if 'All' in applications_included and applications_excluded:
                gaps.append("Policy includes all applications but has exclusions.")
            if users_excluded or groups_excluded:
                gaps.append("Users or groups excluded, potential conflicts with other policies.")

            analysis_results.append({
                'Policy Name': policy.get('displayName', 'Unnamed Policy'),
                'State': state,
                'Gaps Identified': gaps
            })
        except KeyError as e:
            print(f"KeyError processing policy {policy.get('displayName', 'Unnamed Policy')}: Missing key {e}")
            print(f"Policy data: {json.dumps(policy, indent=2)}")
            continue
        except AttributeError as e:
            print(f"Error processing policy {policy.get('displayName', 'Unnamed Policy')}: {e}")
            print(f"Policy data: {json.dumps(policy, indent=2)}")
            continue
        except Exception as e:
            print(f"An unexpected error occurred while processing policy {policy.get('displayName', 'Unnamed Policy')}: {e}")
            continue

    try:
        uncovered_users = all_user_ids - excluded_users
        uncovered_groups = all_group_ids - excluded_groups
        uncovered_applications = all_application_ids - excluded_applications

        if uncovered_users:
            analysis_results.append({'Policy Name': 'Coverage Check', 'State': 'n/a', 'Gaps Identified': [f"Uncovered users: {uncovered_users}"]})
        if uncovered_groups:
            analysis_results.append({'Policy Name': 'Coverage Check', 'State': 'n/a', 'Gaps Identified': [f"Uncovered groups: {uncovered_groups}"]})
        if uncovered_applications:
            analysis_results.append({'Policy Name': 'Coverage Check', 'State': 'n/a', 'Gaps Identified': [f"Uncovered applications: {uncovered_applications}"]})
    except Exception as e:
        print(f"Error during coverage check: {e}")

    return analysis_results

def save_results(df_analysis, tenant_id=None):
    try:
        output_dir = os.path.join(os.path.dirname(__file__), '..', 'output')
        os.makedirs(output_dir, exist_ok=True)

        suffix = f"_{tenant_id}" if tenant_id else ""
        output_filename = os.path.join(output_dir, f'ca_optics_analysis_results{suffix}.csv')
        if os.path.exists(output_filename):
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_filename = os.path.join(output_dir, f'ca_optics_analysis_results{suffix}_{timestamp}.csv')

        df_analysis.to_csv(output_filename, index=False)
        print(f"Analysis complete. Results saved to '{output_filename}'.")
    except Exception as e:
        print(f"Error saving the results to file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Analyze Azure Conditional Access policies.')
    parser.add_argument('--config', help='Path to a JSON or YAML file with tenant configurations.')
    parser.add_argument('tenant_id', nargs='?', help='Azure AD tenant ID.')
    parser.add_argument('client_id', nargs='?', help='Azure App Registration client ID.')
    args = parser.parse_args()

    if args.config:
        main(config_path=args.config)
    elif args.tenant_id and args.client_id:
        main(tenant_id=args.tenant_id, client_id=args.client_id)
    else:
        print("Usage: python pyCaOptics_app.py <tenant_id> <client_id>")
        print("       python pyCaOptics_app.py --config <config.json|config.yaml>")
        sys.exit(1)
