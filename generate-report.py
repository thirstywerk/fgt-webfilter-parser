#!/usr/bin/env python3
"""
FortiGate Security Profile Report Generator
Retrieves and formats WebFilter, DNS Filter and Application Control profiles
from a FortiGate firewall. Shows which firewall policies reference each profile,
and flags FortiGuard categories where a policy's web filter and DNS filter
profiles assign different actions.
Tested on FortiGate running 7.4.9
"""

import requests
import urllib3
import json
import sys
import argparse
from typing import Dict, List, Optional, Tuple

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPECIAL_CATEGORIES = {
    0:   "Unrated",
    140: "custom1",
    141: "custom2",
}

# Application Control category IDs have no API source to resolve their names,
# so they are hardcoded here. Verify/extend this map against your FortiOS version.
APP_CATEGORIES = {
    2:  "P2P",
    3:  "VoIP",
    5:  "Video/Audio",
    6:  "Proxy",
    7:  "Remote.Access",
    8:  "Game",
    12: "General.Interest",
    15: "Network.Service",
    17: "Update",
    21: "Email",
    22: "Storage.Backup",
    23: "Social.Media",
    25: "Web.Client",
    26: "Collaboration",
    28: "Business",
    30: "Cloud.IT",
    31: "Mobile",
    32: "Industrial",
    33: "Unknown.Applications",
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

    def _get(self, path: str) -> Dict:
        """Perform a GET against an API path and return the parsed JSON (or {})."""
        url = f"{self.base_url}/{path}"
        params = {'vdom': self.vdom}

        try:
            response = requests.get(url, headers=self.headers, params=params,
                                  verify=False, timeout=30, proxies=self.proxies)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error fetching {path}: {e}", file=sys.stderr)
            return {}

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

    def get_dnsfilter_profiles(self) -> List[Dict]:
        """Retrieve all DNS filter profiles"""
        return self._get("cmdb/dnsfilter/profile").get('results', [])

    def get_dnsfilter_domain_filters(self) -> Dict[int, str]:
        """Retrieve DNS domain-filter tables mapping (ID -> Name)"""
        data = self._get("cmdb/dnsfilter/domain-filter")
        return {item['id']: item['name']
                for item in data.get('results', [])
                if 'id' in item and 'name' in item}

    def get_application_lists(self) -> List[Dict]:
        """Retrieve all application control lists"""
        return self._get("cmdb/application/list").get('results', [])

    def get_application_names(self) -> Dict[int, str]:
        """Retrieve application signature mapping (ID -> Name)"""
        data = self._get("cmdb/application/name")
        return {item['id']: item['name']
                for item in data.get('results', [])
                if 'id' in item and 'name' in item}


def get_profile_policy_mapping(policies: List[Dict], field_name: str) -> Dict[str, List[Dict[str, any]]]:
    """Create mapping of profile names to policy info (name and ID) that reference
    them via the given policy field (e.g. 'webfilter-profile')."""
    profile_policies = {}

    for policy in policies:
        profile_name = policy.get(field_name)
        # Skip policies where the field is unset/empty
        if not profile_name:
            continue

        policy_id = policy.get('policyid', policy.get('id'))
        policy_name = policy.get('name', 'Unnamed Policy')

        profile_policies.setdefault(profile_name, []).append({
            'id': policy_id,
            'name': policy_name
        })

    return profile_policies


def _category_name(cat_id: int, categories: Dict[int, str]) -> str:
    """Resolve a FortiGuard category ID to a name."""
    return SPECIAL_CATEGORIES.get(cat_id, categories.get(cat_id, f"Unknown-{cat_id}"))


def categorise_profile(profile: Dict, categories: Dict[int, str]) -> Dict[str, List[str]]:
    """Parse webfilter profile and categorise filters by action"""
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

            cat_name = _category_name(cat_id, categories)

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


def categorise_dns_profile(profile: Dict, categories: Dict[int, str],
                           domain_filter_names: Dict[int, str]) -> Tuple[Dict[str, List[str]], Dict]:
    """Parse DNS filter profile: categorise ftgd-dns filters by action and
    collect notable settings (domain-filter table, toggles)."""
    result = {
        'allowed': [],
        'blocked': [],
        'monitored': []
    }

    ftgd = profile.get('ftgd-dns', {})
    for filter_entry in ftgd.get('filters', []):
        cat_id = filter_entry.get('category', 0)
        action = filter_entry.get('action', 'monitor').lower()

        cat_name = _category_name(cat_id, categories)

        if action == 'allow':
            result['allowed'].append(cat_name)
        elif action == 'block':
            result['blocked'].append(cat_name)
        elif action == 'monitor':
            result['monitored'].append(cat_name)

    table_id = profile.get('domain-filter', {}).get('domain-filter-table', 0)
    table_name = domain_filter_names.get(table_id) if table_id else None

    ext_list = profile.get('external-ip-blocklist', [])
    ext_names = ", ".join(e.get('name', '') for e in ext_list) if ext_list else None

    settings = {
        'domain_filter_table': table_name,
        'block_botnet': profile.get('block-botnet', 'disable'),
        'safe_search': profile.get('safe-search', 'disable'),
        'external_ip_blocklist': ext_names,
    }

    return result, settings


def categorise_app_list(app_list: Dict, app_names: Dict[int, str]) -> Dict[str, Dict[str, List[str]]]:
    """Parse an application control list: per entry action (pass/block/reset),
    collect the targeted category names and resolved application names."""
    result = {
        'pass':  {'categories': [], 'applications': []},
        'block': {'categories': [], 'applications': []},
        'reset': {'categories': [], 'applications': []},
    }

    for entry in app_list.get('entries', []):
        action = entry.get('action', 'block').lower()
        if action not in result:
            result[action] = {'categories': [], 'applications': []}

        for cat in entry.get('category', []):
            cat_id = cat.get('id') if isinstance(cat, dict) else cat
            result[action]['categories'].append(
                APP_CATEGORIES.get(cat_id, f"Category-{cat_id}"))

        for app in entry.get('application', []):
            app_id = app.get('id') if isinstance(app, dict) else app
            result[action]['applications'].append(
                app_names.get(app_id, f"App-{app_id}"))

    return result


def category_action_map(profile: Dict, section: str) -> Dict[int, str]:
    """Return {category_id: action} from a profile's FortiGuard filter section
    ('ftgd-wf' for web filter, 'ftgd-dns' for DNS filter)."""
    actions = {}
    for filter_entry in profile.get(section, {}).get('filters', []):
        cat_id = filter_entry.get('category')
        if cat_id is None:
            continue
        actions[cat_id] = filter_entry.get('action', 'monitor').lower()
    return actions


def find_webdns_clashes(policies: List[Dict], web_by_name: Dict[str, Dict],
                        dns_by_name: Dict[str, Dict], categories: Dict[int, str]) -> List[Dict]:
    """For policies that reference both a web filter and DNS filter profile, flag
    FortiGuard categories where the two profiles assign different actions. Only
    categories explicitly listed in both profiles are compared."""
    clashes = []

    for policy in policies:
        web_name = policy.get('webfilter-profile')
        dns_name = policy.get('dnsfilter-profile')
        if not web_name or not dns_name:
            continue

        web_profile = web_by_name.get(web_name)
        dns_profile = dns_by_name.get(dns_name)
        if not web_profile or not dns_profile:
            continue

        web_actions = category_action_map(web_profile, 'ftgd-wf')
        dns_actions = category_action_map(dns_profile, 'ftgd-dns')

        diffs = []
        for cat_id in set(web_actions) & set(dns_actions):
            if web_actions[cat_id] != dns_actions[cat_id]:
                diffs.append((_category_name(cat_id, categories),
                              web_actions[cat_id], dns_actions[cat_id]))

        if diffs:
            clashes.append({
                'policy_id': policy.get('policyid', policy.get('id')),
                'policy_name': policy.get('name', 'Unnamed Policy'),
                'web_profile': web_name,
                'dns_profile': dns_name,
                'clashes': sorted(diffs),
            })

    return clashes


def _section_header(title: str) -> List[str]:
    return ["=" * 80, title, "=" * 80, ""]


def _policy_refs_line(policy_info: List[Dict[str, any]]) -> str:
    """Format policy references as '"name" (id: X), ...' sorted by ID."""
    refs = []
    for pol in sorted(policy_info, key=lambda x: x['id']):
        refs.append(f'"{pol["name"]}" (id: {pol["id"]})')
    return ", ".join(refs)


def _category_block(lines: List[str], label: str, items: List[str], show_none: bool = True):
    """Append a sorted bulleted category list (or 'label: None') to lines."""
    if items:
        lines.append(f"  {label}:")
        for item in sorted(items):
            lines.append(f"    - {item}")
    elif show_none:
        lines.append(f"  {label}: None")


def generate_report(profiles: List[Dict], categories: Dict[int, str],
                   profile_policies: Dict[str, List[Dict[str, any]]]) -> str:
    """Generate formatted webfilter text report"""
    lines = _section_header("FORTIGATE WEBFILTER PROFILE REPORT")

    # Filter profiles to only include those used in policies
    used_profiles = [p for p in profiles if p.get('name') in profile_policies]

    if not used_profiles:
        lines.append("No webfilter profiles are currently used in firewall policies.")
        return "\n".join(lines)

    for profile in used_profiles:
        profile_name = profile.get('name', 'Unnamed Profile')

        lines.append(f"Profile: {profile_name}")
        lines.append(f"  Used in Policies: {_policy_refs_line(profile_policies.get(profile_name, []))}")
        lines.append("-" * 80)

        categorised = categorise_profile(profile, categories)

        _category_block(lines, "Allowed Categories", categorised['allowed'], show_none=False)
        _category_block(lines, "Blocked Categories", categorised['blocked'])
        _category_block(lines, "Monitored Categories", categorised['monitored'])
        _category_block(lines, "Warning Categories", categorised['warning'])
        _category_block(lines, "Authenticate Categories", categorised['authenticate'])

        lines.append("")

    lines.append("=" * 80)
    return "\n".join(lines)


def generate_dns_report(profiles: List[Dict], categories: Dict[int, str],
                        profile_policies: Dict[str, List[Dict[str, any]]],
                        domain_filter_names: Dict[int, str]) -> str:
    """Generate formatted DNS filter text report"""
    lines = _section_header("FORTIGATE DNS FILTER PROFILE REPORT")

    used_profiles = [p for p in profiles if p.get('name') in profile_policies]

    if not used_profiles:
        lines.append("No DNS filter profiles are currently used in firewall policies.")
        return "\n".join(lines)

    for profile in used_profiles:
        profile_name = profile.get('name', 'Unnamed Profile')

        lines.append(f"Profile: {profile_name}")
        lines.append(f"  Used in Policies: {_policy_refs_line(profile_policies.get(profile_name, []))}")
        lines.append("-" * 80)

        categorised, settings = categorise_dns_profile(profile, categories, domain_filter_names)

        _category_block(lines, "Allowed Categories", categorised['allowed'], show_none=False)
        _category_block(lines, "Blocked Categories", categorised['blocked'])
        _category_block(lines, "Monitored Categories", categorised['monitored'])

        lines.append("  Settings:")
        lines.append(f"    - Domain Filter Table: {settings['domain_filter_table'] or 'None'}")
        lines.append(f"    - Block Botnet: {settings['block_botnet']}")
        lines.append(f"    - Safe Search: {settings['safe_search']}")
        lines.append(f"    - External IP Blocklist: {settings['external_ip_blocklist'] or 'None'}")

        lines.append("")

    lines.append("=" * 80)
    return "\n".join(lines)


def generate_app_report(app_lists: List[Dict],
                        profile_policies: Dict[str, List[Dict[str, any]]],
                        app_names: Dict[int, str]) -> str:
    """Generate formatted application control text report"""
    lines = _section_header("FORTIGATE APPLICATION CONTROL REPORT")

    used_lists = [a for a in app_lists if a.get('name') in profile_policies]

    if not used_lists:
        lines.append("No application control profiles are currently used in firewall policies.")
        return "\n".join(lines)

    action_order = ['pass', 'block', 'reset']

    for app_list in used_lists:
        list_name = app_list.get('name', 'Unnamed Profile')

        lines.append(f"Profile: {list_name}")
        lines.append(f"  Used in Policies: {_policy_refs_line(profile_policies.get(list_name, []))}")
        lines.append("-" * 80)

        categorised = categorise_app_list(app_list, app_names)
        keys = action_order + [k for k in categorised if k not in action_order]

        for key in keys:
            data = categorised[key]
            if not data['categories'] and not data['applications']:
                continue
            label = key.capitalize()
            _category_block(lines, f"{label} - Categories", data['categories'], show_none=False)
            _category_block(lines, f"{label} - Applications", data['applications'], show_none=False)

        lines.append("")

    lines.append("=" * 80)
    return "\n".join(lines)


def generate_clash_report(clashes: List[Dict]) -> str:
    """Generate formatted web/DNS filter clash report"""
    lines = _section_header("WEB/DNS FILTER CLASH REPORT")

    if not clashes:
        lines.append("No web/DNS category action clashes found.")
        lines.append("")
        lines.append("=" * 80)
        return "\n".join(lines)

    for clash in clashes:
        lines.append(f'Policy: "{clash["policy_name"]}" (id: {clash["policy_id"]})')
        lines.append(f"  Web Filter Profile: {clash['web_profile']}")
        lines.append(f"  DNS Filter Profile: {clash['dns_profile']}")
        lines.append(f"  Clashing Categories ({len(clash['clashes'])}):")
        for cat_name, web_action, dns_action in clash['clashes']:
            lines.append(f"    - {cat_name} — webfilter: {web_action}, dnsfilter: {dns_action}")
        lines.append("")

    lines.append("=" * 80)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Connect to FortiGate API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Example: python generate-report.py dc-abc-fw01.xy.com:8443 FG-traffic YOUR_API_KEY'
    )

    parser.add_argument('fqdn', help='Fully Qualified Domain Name with optional port (FQDN[:PORT])')
    parser.add_argument('vdom', help='Virtual Domain name')
    parser.add_argument('api_key', help='API key for authentication')
    parser.add_argument('--webfilter', action='store_true',
                        help='Include the WebFilter profile report')
    parser.add_argument('--dnsfilter', action='store_true',
                        help='Include the DNS Filter profile report')
    parser.add_argument('--appcontrol', action='store_true',
                        help='Include the Application Control report')
    parser.add_argument('--check-clash', action='store_true',
                        help='Include the Web/DNS filter clash report')

    args = parser.parse_args()

    # Default: with no section flag, run everything.
    do_web = args.webfilter
    do_dns = args.dnsfilter
    do_app = args.appcontrol
    do_clash = args.check_clash
    if not (do_web or do_dns or do_app or do_clash):
        do_web = do_dns = do_app = do_clash = True

    fqdn = args.fqdn
    vdom = args.vdom
    api_key = args.api_key

    print(f"Connecting to {fqdn} (VDOM: {vdom})...")
    fg = FortiGateAPI(fqdn, api_key, vdom)

    print("Fetching firewall policies...")
    policies = fg.get_firewall_policies()
    print(f"Retrieved {len(policies)} policies.")

    # FortiGuard categories are shared by webfilter, DNS filter and the clash check.
    categories = {}
    if do_web or do_dns or do_clash:
        print("Fetching FortiGuard categories...")
        categories = fg.get_webfilter_categories()
        print(f"Retrieved {len(categories)} categories.")

    # The clash check needs both web and DNS profile data regardless of section flags.
    web_profiles = []
    if do_web or do_clash:
        print("Fetching webfilter profiles...")
        web_profiles = fg.get_webfilter_profiles()
        print(f"Retrieved {len(web_profiles)} webfilter profiles.")

    dns_profiles = []
    if do_dns or do_clash:
        print("Fetching DNS filter profiles...")
        dns_profiles = fg.get_dnsfilter_profiles()
        print(f"Retrieved {len(dns_profiles)} DNS filter profiles.")

    domain_filter_names = {}
    if do_dns:
        domain_filter_names = fg.get_dnsfilter_domain_filters()

    app_lists = []
    app_names = {}
    if do_app:
        print("Fetching application control lists...")
        app_lists = fg.get_application_lists()
        print(f"Retrieved {len(app_lists)} application control lists.")
        print("Fetching application signatures...")
        app_names = fg.get_application_names()
        print(f"Retrieved {len(app_names)} application signatures.")

    print("\nGenerating report...\n")

    if do_web:
        web_pol = get_profile_policy_mapping(policies, 'webfilter-profile')
        print(generate_report(web_profiles, categories, web_pol))
        print()

    if do_dns:
        dns_pol = get_profile_policy_mapping(policies, 'dnsfilter-profile')
        print(generate_dns_report(dns_profiles, categories, dns_pol, domain_filter_names))
        print()

    if do_app:
        app_pol = get_profile_policy_mapping(policies, 'application-list')
        print(generate_app_report(app_lists, app_pol, app_names))
        print()

    if do_clash:
        web_by_name = {p['name']: p for p in web_profiles if 'name' in p}
        dns_by_name = {p['name']: p for p in dns_profiles if 'name' in p}
        clashes = find_webdns_clashes(policies, web_by_name, dns_by_name, categories)
        print(generate_clash_report(clashes))


if __name__ == "__main__":
    main()
