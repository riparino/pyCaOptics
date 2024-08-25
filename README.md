# pyCaOptics

**pyCaOptics** is a Python-based script designed to analyze Conditional Access policies in Azure Active Directory. It offers functionality similar to the original `caOptics` tool but is implemented in Python for ease of use and integration in various environments. This script enables users to authenticate via an Azure App Registration or interactively, retrieve Conditional Access policies, and perform an analysis to identify potential gaps or issues within the policies.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Usage](#usage)
  - [Using the Script with App Registration](#using-the-script-with-app-registration)
  - [Using the Script with Interactive Authentication](#using-the-script-with-interactive-authentication)
- [Output](#output)
- [Error Handling](#error-handling)
- [References](#references)
- [Acknowledgements](#acknowledgements)

## Overview
pyCaOptics is a tool to assist security teams in reviewing and auditing Conditional Access policies in Azure Active Directory (AAD). By automating the retrieval and analysis of these policies, the script helps identify gaps, such as users or applications that might not be covered by the policies or conflicts between policies. 

The project was inspired by the original `caOptics` tool and re-implemented in Python to allow broader usage across different environments without needing to rely on Node.js.

## Features
- **Authentication**: Supports both interactive user authentication and client ID-based authentication via Azure App Registration.
- **Conditional Access Policy Retrieval**: Retrieves Conditional Access policies from Microsoft Graph API.
- **Detailed Analysis**: Identifies potential issues such as uncovered users, applications, and policy conflicts.
- **Logging and Error Handling**: Includes robust logging and error handling to assist in troubleshooting and policy review.

## Prerequisites

Before using pyCaOptics, ensure you have the following:

- **Python 3.8 or higher** installed on your system.
- **Azure App Registration** with appropriate Microsoft Graph API permissions (referenced below under Step 3).
- **Azure AD Admin Consent** granted for the app registration.

## Setup

1. Clone the Repository:
   ```sh
   git clone https://github.com/riparino/pyCaOptics.git
   cd pyCaOptics
   ```
2. Install Dependencies: Install the required Python packages using pip:
   ```sh
   pip install -r requirements.txt
   ```
3. Configure Azure App Registration:
    - Go to Azure Portal > Azure Active Directory > App registrations.
    - Register a new application or use an existing one.
    - Assign necessary API permissions:
        - ConditionalAccessPolicy.Read.All
        - Policy.Read.All
        - Application.Read.All
        - Users.Read.All
        - Groups.Read.All
        - Policy.Read.All
    - Add http://localhost:8400 as a redirect URI under "Mobile and desktop applications".
    - Enable Access tokens for Implicit grant and hybrid flows.

## Usage
### Using the Script with App Registration
To run the script using an Azure App Registration, use the following command:
   ```sh
   python pyCaOptics-app.py <tenant_id> <client_id>
   ```
- <tenant_id>: The Azure Active Directory tenant ID.
- <client_id>: The client ID of your Azure App Registration.

### Using the Script with Interactive Authentication
To run the script using interactive browser-based authentication:
   ```sh
   python pyCaOptics-usermode.py <tenant_id>
   ```
This mode will open a browser window for you to sign in with your Azure AD account.

## Output
The script will perform the following actions:

- Retrieve Policies: Fetches Conditional Access policies from Microsoft Graph API.
- Analyze Policies: Identifies gaps such as uncovered users, applications, or conflicting policies.
- Save Results: The analysis results are saved to a CSV file in the current directory. The file name will be of the format `analysis_results_<timestamp>.csv.`

## Error Handling
The script includes detailed error handling to assist in troubleshooting:
- 403 Forbidden: Ensure your App Registration has the necessary permissions.
- Key Errors: The script will log and skip any policies missing expected fields.
- General Exceptions: Any unexpected issues are logged with a descriptive message to aid in debugging.

## Installation Using `setup.py`
If you prefer to install the project using `setup.py`, follow these steps:
1. Ensure you are in the root directory where `setup.py` is located:
   ```sh
   cd pyCaOptics
   ```
2. Install the package using pip:
   ```sh
   pip install .
   ```
   This command will install the pyCaOptics package and its dependencies. After installation, you can run the scripts directly if they are defined as console scripts in the `setup.py`.
3. Run the Scripts:
    ```sh
    pyCaOptics-app <tenant_id> <client_id>
    pyCaOptics-usermode <tenant_id>
    ```
    Otherwise, you can continue to run the scripts as described in the [Usage](#usage) section.

## References
- Microsoft Graph API Documentation: [Conditional Access policies API](https://docs.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0&tabs=http)
- Original caOptics Tool: [caOptics on GitHub](https://github.com/jsa2/caOptics)

## Acknowledgements
This project is inspired by the original caOptics tool developed by jsa2. Special thanks to the original contributors for their work, which laid the foundation for this Python-based implementation.

## To-Do
- Implement Permutation Checks: Extend your analysis to consider how different combinations of users, groups, roles, applications, and conditions interact across multiple policies.
- Handle Edge Cases: Introduce logic to manage and detect more nuanced gaps that could arise from complex CA configurations, such as nested group memberships or overlapping policies.
