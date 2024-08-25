import json
import requests
import pandas as pd
import sys
import os
from datetime import datetime
from azure.identity import DeviceCodeCredential

def main(tenant_id):
    try:
        credentials = DeviceCodeCredential(tenant_id=tenant_id)
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
        analysis_results = ca_optics_like_analysis(data['policies'], data['users'], data['groups'], data['applications'])
        df_analysis = pd.DataFrame(analysis_results)
        save_results(df_analysis)

    except requests.exceptions.RequestException as e:
        print(f"Error in API request: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

def fetch_data(headers, endpoints):
    data = {}
    for key, url in endpoints.items():
        data[key] = fetch_paginated_data(url, headers)
    return data

def fetch_paginated_data(url, headers):
    try:
        items = []
        while url:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            items.extend(data.get('value', []))
            url = data.get('@odata.nextLink')
        return items
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from {url}: {e}")
        sys.exit(1)

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

            users_included = set(policy.get('conditions', {}).get('users', {}).get('includeUsers', []))
            users_excluded = set(policy.get('conditions', {}).get('users', {}).get('excludeUsers', []))
            groups_included = set(policy.get('conditions', {}).get('users', {}).get('includeGroups', []))
            groups_excluded = set(policy.get('conditions', {}).get('users', {}).get('excludeGroups', []))
            applications_included = set(policy.get('conditions', {}).get('applications', {}).get('includeApplications', []))
            applications_excluded = set(policy.get('conditions', {}).get('applications', {}).get('excludeApplications', []))
            
            # Handle NoneType for grantControls
            grant_controls = policy.get('grantControls') or {}
            built_in_controls = grant_controls.get('builtInControls', [])

            user_risk_levels = policy.get('conditions', {}).get('userRiskLevels', [])
            sign_in_risk_levels = policy.get('conditions', {}).get('signInRiskLevels', [])
            session_controls = policy.get('sessionControls', {})
            platforms = policy.get('conditions', {}).get('platforms', {})
            device_states = policy.get('conditions', {}).get('deviceStates', {})

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
            if 'All' in users_included and users_excluded:
                gaps.append("Policy includes all users but has exclusions.")
            if 'All' in applications_included and applications_excluded:
                gaps.append("Policy includes all applications but has exclusions.")
            if users_excluded or groups_excluded:
                gaps.append("Users or groups excluded, potential conflicts with other policies.")

            analysis_results.append({'Policy Name': policy.get('displayName', 'Unnamed Policy'), 'State': state, 'Gaps Identified': gaps})
        except AttributeError as e:
            print(f"Error processing policy {policy.get('displayName', 'Unnamed Policy')}: {e}")
            print(f"Policy data: {json.dumps(policy, indent=2)}")  # Log the full policy data for debugging
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

def save_results(df_analysis):
    try:
        output_filename = 'ca_optics_analysis_results.csv'
        if os.path.exists(output_filename):
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_filename = f'ca_optics_analysis_results_{timestamp}.csv'

        df_analysis.to_csv(output_filename, index=False)
        print(f"Analysis complete. Results saved to '{output_filename}'.")
    except Exception as e:
        print(f"Error saving the results to file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pycaOptics-usermode.py <tenant_id>")
        sys.exit(1)

    tenant_id = sys.argv[1]
    main(tenant_id)
