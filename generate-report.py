#!/usr/bin/env python3
"""
FortiGate WebFilter Profile Report Generator
Retrieves and formats webfilter profiles from a FortiGate firewall.
Shows which firewall policies reference each profile.
Tested on FortiGate running 7.4.9
"""

import requests
import urllib3
import json
import sys
import argparse
from typing import Dict, List, Optional

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPECIAL_CATEGORIES = {
    0:   "Unrated",
    140: "custom1",
    141: "custom2",
}

class FortiGateAPI:
    def __init__(self, fqdn: str, api_key: str, vdom: str):
        # Parse FQDN and port
        if ':' in fqdn:
            self.host, port = fqdn.rsplit(':', 1)
            self.port = int(port)
        else:
            self.host = fqdn
            self.port = 443

        self.api_key = api_key
        self.vdom = vdom
        self.base_url = f"https://{self.host}:{self.port}/api/v2"
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        # Bypass proxy
        self.proxies = {'http': None, 'https': None}

    def get_webfilter_categories(self) -> Dict[int, str]:
        """Retrieve webfilter categories mapping (ID -> Name)"""
        url = f"{self.base_url}/monitor/webfilter/fortiguard-categories"
        params = {'vdom': self.vdom}

        try:
            response = requests.get(url, headers=self.headers, params=params,
                                  verify=False, timeout=30, proxies=self.proxies)
            response.raise_for_status()
            data = response.json()

            categories = {}
            if 'results' in data:
                for cat in data['results']:
                    categories[cat['id']] = cat['name']

            return categories
        except Exception as e:
            print(f"Error fetching categories: {e}", file=sys.stderr)
            return {}

    def get_webfilter_profiles(self) -> List[Dict]:
        """Retrieve all webfilter profiles"""
        url = f"{self.base_url}/cmdb/webfilter/profile"
        params = {'vdom': self.vdom}

        try:
            response = requests.get(url, headers=self.headers, params=params,
                                  verify=False, timeout=30, proxies=self.proxies)
            response.raise_for_status()
            data = response.json()

            return data.get('results', [])
        except Exception as e:
            print(f"Error fetching profiles: {e}", file=sys.stderr)
            return []

    def get_firewall_policies(self) -> List[Dict]:
        """Retrieve all firewall policies"""
        url = f"{self.base_url}/cmdb/firewall/policy"
        params = {'vdom': self.vdom}

        try:
            response = requests.get(url, headers=self.headers, params=params,
                                  verify=False, timeout=30, proxies=self.proxies)
            response.raise_for_status()
            data = response.json()

            return data.get('results', [])
        except Exception as e:
            print(f"Error fetching firewall policies: {e}", file=sys.stderr)
            return []


def get_profile_policy_mapping(policies: List[Dict]) -> Dict[str, List[Dict[str, any]]]:
    """Create mapping of webfilter profile names to policy info (name and ID) that use them"""
    profile_policies = {}

    for policy in policies:
        # Check if policy has a webfilter profile
        if 'webfilter-profile' in policy:
            profile_name = policy['webfilter-profile']
            policy_id = policy.get('policyid', policy.get('id'))
            policy_name = policy.get('name', 'Unnamed Policy')

            if profile_name not in profile_policies:
                profile_policies[profile_name] = []
            profile_policies[profile_name].append({
                'id': policy_id,
                'name': policy_name
            })

    return profile_policies


def categorise_profile(profile: Dict, categories: Dict[int, str]) -> Dict[str, List[str]]:
    """Parse profile and categorise filters by action"""
    result = {
        'allowed': [],
        'blocked': [],
        'monitored': [],
        'warning': [],
        'authenticate': []
    }

    # Parse ftgd-wf (FortiGuard Web Filter) settings
    if 'ftgd-wf' in profile and 'filters' in profile['ftgd-wf']:
        for filter_entry in profile['ftgd-wf']['filters']:
            cat_id = filter_entry.get('category', 0)
            action = filter_entry.get('action', 'monitor').lower()  # Default to monitor

            cat_name = SPECIAL_CATEGORIES.get(cat_id, categories.get(cat_id, f"Unknown-{cat_id}"))

            if action == 'allow':
                result['allowed'].append(cat_name)
            elif action == 'block':
                result['blocked'].append(cat_name)
            elif action == 'monitor':
                result['monitored'].append(cat_name)
            elif action == 'warning':
                result['warning'].append(cat_name)
            elif action == 'authenticate':
                result['authenticate'].append(cat_name)

    return result


def generate_report(profiles: List[Dict], categories: Dict[int, str],
                   profile_policies: Dict[str, List[Dict[str, any]]]) -> str:
    """Generate formatted text report"""
    report_lines = []
    report_lines.append("=" * 80)
    report_lines.append("FORTIGATE WEBFILTER PROFILE REPORT")
    report_lines.append("=" * 80)
    report_lines.append("")

    # Filter profiles to only include those used in policies
    used_profiles = [p for p in profiles if p.get('name') in profile_policies]

    if not used_profiles:
        report_lines.append("No webfilter profiles are currently used in firewall policies.")
        return "\n".join(report_lines)

    for profile in used_profiles:
        profile_name = profile.get('name', 'Unnamed Profile')
        policy_info = profile_policies.get(profile_name, [])

        # Format policy references as "name" (id: X)
        policy_refs = []
        for pol in sorted(policy_info, key=lambda x: x['id']):
            policy_refs.append(f'"{pol["name"]}" (id: {pol["id"]})')

        report_lines.append(f"Profile: {profile_name}")
        report_lines.append(f"  Used in Policies: {', '.join(policy_refs)}")
        report_lines.append("-" * 80)

        categorised = categorise_profile(profile, categories)

        # Only show allowed if there are any
        if categorised['allowed']:
            report_lines.append(f"  Allowed Categories:")
            for cat in sorted(categorised['allowed']):
                report_lines.append(f"    - {cat}")

        if categorised['blocked']:
            report_lines.append(f"  Blocked Categories:")
            for cat in sorted(categorised['blocked']):
                report_lines.append(f"    - {cat}")
        else:
            report_lines.append(f"  Blocked Categories: None")

        if categorised['monitored']:
            report_lines.append(f"  Monitored Categories:")
            for cat in sorted(categorised['monitored']):
                report_lines.append(f"    - {cat}")
        else:
            report_lines.append(f"  Monitored Categories: None")

        if categorised['warning']:
            report_lines.append(f"  Warning Categories:")
            for cat in sorted(categorised['warning']):
                report_lines.append(f"    - {cat}")
        else:
            report_lines.append(f"  Warning Categories: None")

        if categorised['authenticate']:
            report_lines.append(f"  Authenticate Categories:")
            for cat in sorted(categorised['authenticate']):
                report_lines.append(f"    - {cat}")
        else:
            report_lines.append(f"  Authenticate Categories: None")

        report_lines.append("")

    report_lines.append("=" * 80)
    return "\n".join(report_lines)


def main():
    parser = argparse.ArgumentParser(
        description='Connect to FortiGate API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Example: python generate-report.py dc-abc-fw01.xy.com:8443 FG-traffic YOUR_API_KEY'
    )

    parser.add_argument('fqdn', help='Fully Qualified Domain Name with optional port (FQDN[:PORT])')
    parser.add_argument('vdom', help='Virtual Domain name')
    parser.add_argument('api_key', help='API key for authentication')

    args = parser.parse_args()

    fqdn = args.fqdn
    vdom = args.vdom
    api_key = args.api_key

    print(f"Connecting to {fqdn} (VDOM: {vdom})...")

    fg = FortiGateAPI(fqdn, api_key, vdom)

    print("Fetching webfilter categories...")
    categories = fg.get_webfilter_categories()
    print(f"Retrieved {len(categories)} categories.")

    print("Fetching webfilter profiles...")
    profiles = fg.get_webfilter_profiles()
    print(f"Retrieved {len(profiles)} profiles.")

    print("Fetching firewall policies...")
    policies = fg.get_firewall_policies()
    print(f"Retrieved {len(policies)} policies.")

    print("Mapping profiles to policies...")
    profile_policies = get_profile_policy_mapping(policies)
    print(f"Found {len(profile_policies)} profiles in use.")

    print("\nGenerating report...\n")
    report = generate_report(profiles, categories, profile_policies)
    print(report)


if __name__ == "__main__":
    main()
