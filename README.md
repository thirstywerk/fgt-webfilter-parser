# fgt-webfilter-parser
Generates a VDOM-specific report of **WebFilter**, **DNS Filter** and **Application Control** profiles referenced in firewall policies (Name &amp; ID); unreferenced profiles are skipped by default (see `--include-unused`). Each profile's configured comment, if any, is shown. It can also flag FortiGuard categories where a policy's web filter and DNS filter profiles assign different actions (a "clash"). Requires a super-admin read-only API key. The script explicitly bypasses local proxies.

By default (no section flag) all four reports are produced. Pass one or more of `--webfilter`, `--dnsfilter`, `--appcontrol`, `--check-clash` to limit output to those sections. `--check-clash` always fetches both web and DNS filter data regardless of the other flags. Pass `--include-unused` to additionally list profiles that exist but aren't referenced by any policy; these appear in a `CONFIGURED BUT UNUSED PROFILES` section at the end of each report.

The read-only API key must have read access to the `webfilter`, `dnsfilter`, `application` and `firewall/policy` endpoints.

> Note: Application Control *category* IDs cannot be resolved to names via the API, so they are mapped from the hardcoded `APP_CATEGORIES` table in `generate-report.py`. Any unmapped ID is shown as `Category-<id>`. Run with `--list-app-categories` to print every category ID present on the device alongside example application names — use this to identify and add missing names to `APP_CATEGORIES` for your FortiOS version.

Usage:
```
usage: generate-report.py [-h] [--webfilter] [--dnsfilter] [--appcontrol]
                          [--check-clash] [--include-unused]
                          fqdn vdom api_key

Connect to FortiGate API

positional arguments:
  fqdn           Fully Qualified Domain Name with optional port (FQDN[:PORT])
  vdom           Virtual Domain name
  api_key        API key for authentication

options:
  -h, --help     show this help message and exit
  --webfilter    Include the WebFilter profile report
  --dnsfilter    Include the DNS Filter profile report
  --appcontrol   Include the Application Control report
  --check-clash  Include the Web/DNS filter clash report
  --include-unused
                 Also list profiles that are configured but not referenced by
                 any policy, in a "CONFIGURED BUT UNUSED PROFILES" section at
                 the end of each report
  --list-app-categories
                 List application category IDs with example app names and exit

Examples:
  python generate-report.py dc-abc-fw01.xy.com:8443 FG-traffic YOUR_API_KEY
  python generate-report.py dc-abc-fw02.xy.com FG-traffic YOUR_API_KEY
  python generate-report.py dc-abc-fw02.xy.com FG-traffic YOUR_API_KEY --dnsfilter --check-clash
```

Example Output:
```
================================================================================
FORTIGATE WEBFILTER PROFILE REPORT
================================================================================

Profile: webflt_general
  Used in Policies: "staff_internet" (id: 1), "voice_internet" (id: 4), "staff_to_cloud" (id: 5), "vpn_to_lan" (id: 6)
--------------------------------------------------------------------------------
  Blocked Categories:
    - Child Sexual Abuse
    - Crypto Mining
    - Dating
    - Discrimination
    - Drug Abuse
    - Dynamic DNS
    - Explicit Violence
    - Extremist Groups
    - Freeware and Software Downloads
    - Games
    - Hacking
    - Illegal or Unethical
    - Lingerie and Swimsuit
    - Malicious Websites
    - Marijuana
    - Nudity and Risque
    - Other Adult Materials
    - Peer-to-peer File Sharing
    - Phishing
    - Plagiarism
    - Pornography
    - Potentially Unwanted Program
    - Proxy Avoidance
    - Sex Education
    - Spam URLs
    - Sports Hunting and War Games
    - Terrorism
    - Weapons (Sales)
  Monitored Categories:
    - Abortion
    - Advertising
    - Advocacy Organizations
    - Alcohol
    - Alternative Beliefs
    - Armed Forces
    - Artificial Intelligence Technology
    - Arts and Culture
    - Auction
    - Brokerage and Trading
    - Business
    - Charitable Organizations
    - Child Education
    - Content Servers
    - Cryptocurrency
    - Digital Postcards
    - Domain Parking
    - Dynamic Content
    - Education
    - Entertainment
    - File Sharing and Storage
    - Finance and Banking
    - Folklore
    - Gambling
    - General Organizations
    - Global Religion
    - Government and Legal Organizations
    - Health and Wellness
    - Information Technology
    - Information and Computer Security
    - Instant Messaging
    - Internet Radio and TV
    - Internet Telephony
    - Job Search
    - Meaningless Content
    - Medicine
    - Newly Observed Domain
    - Newly Registered Domain
    - News and Media
    - Newsgroups and Message Boards
    - Online Meeting
    - Personal Privacy
    - Personal Vehicles
    - Personal Websites and Blogs
    - Political Organizations
    - Real Estate
    - Reference
    - Remote Access
    - Restaurant and Dining
    - Search Engines and Portals
    - Secure Websites
    - Shopping
    - Social Networking
    - Society and Lifestyles
    - Sports
    - Streaming Media and Download
    - Tobacco
    - Travel
    - URL Shortening
    - Unrated
    - Web Analytics
    - Web Chat
    - Web Hosting
    - Web-based Applications
    - Web-based Email
    - custom1
    - custom2
  Warning Categories: None
  Authenticate Categories: None

Profile: webflt_guest
  Used in Policies: "guest_internet" (id: 2)
--------------------------------------------------------------------------------
  Blocked Categories:
    - Child Sexual Abuse
    - Crypto Mining
    - Dating
    - Discrimination
    - Drug Abuse
    - Dynamic DNS
    - Explicit Violence
    - Extremist Groups
    - Freeware and Software Downloads
    - Gambling
    - Hacking
    - Illegal or Unethical
    - Lingerie and Swimsuit
    - Malicious Websites
    - Marijuana
    - Nudity and Risque
    - Other Adult Materials
    - Peer-to-peer File Sharing
    - Phishing
    - Plagiarism
    - Pornography
    - Potentially Unwanted Program
    - Sex Education
    - Spam URLs
    - Sports Hunting and War Games
    - Terrorism
    - Weapons (Sales)
  Monitored Categories:
    - Abortion
    - Advertising
    - Advocacy Organizations
    - Alcohol
    - Alternative Beliefs
    - Armed Forces
    - Artificial Intelligence Technology
    - Arts and Culture
    - Auction
    - Brokerage and Trading
    - Business
    - Charitable Organizations
    - Child Education
    - Content Servers
    - Cryptocurrency
    - Digital Postcards
    - Domain Parking
    - Dynamic Content
    - Education
    - Entertainment
    - File Sharing and Storage
    - Finance and Banking
    - Folklore
    - Games
    - General Organizations
    - Global Religion
    - Government and Legal Organizations
    - Health and Wellness
    - Information Technology
    - Information and Computer Security
    - Instant Messaging
    - Internet Radio and TV
    - Internet Telephony
    - Job Search
    - Meaningless Content
    - Medicine
    - Newly Observed Domain
    - Newly Registered Domain
    - News and Media
    - Newsgroups and Message Boards
    - Online Meeting
    - Personal Privacy
    - Personal Vehicles
    - Personal Websites and Blogs
    - Political Organizations
    - Proxy Avoidance
    - Real Estate
    - Reference
    - Remote Access
    - Restaurant and Dining
    - Search Engines and Portals
    - Secure Websites
    - Shopping
    - Social Networking
    - Society and Lifestyles
    - Sports
    - Streaming Media and Download
    - Tobacco
    - Travel
    - URL Shortening
    - Unrated
    - Web Analytics
    - Web Chat
    - Web Hosting
    - Web-based Applications
    - Web-based Email
    - custom1
    - custom2
  Warning Categories: None
  Authenticate Categories: None
```

Example DNS Filter Output:
```
================================================================================
FORTIGATE DNS FILTER PROFILE REPORT
================================================================================

Profile: dnsflt_general
  Used in Policies: "staff_internet" (id: 1), "voice_internet" (id: 4)
--------------------------------------------------------------------------------
  Blocked Categories:
    - Malicious Websites
    - Newly Registered Domain
    - Phishing
  Monitored Categories:
    - Social Networking
    - Streaming Media and Download
  Settings:
    - Domain Filter Table: corp_blocklist
    - Block Botnet: enable
    - Safe Search: disable
    - External IP Blocklist: None
================================================================================
```

Example Application Control Output:

Categories are shown by their effective (GUI-style) action. Categories left at the sensor default appear under **Monitor** (FortiGate stores only categories that differ from the default as entries, so the report fills in the rest). `pass`+log maps to Monitor, `pass` without log to Allow, plus Block/Reset. Individual application overrides are listed under their action. Category IDs without a name in the built-in table are shown as `Category-<id>`.
```
================================================================================
FORTIGATE APPLICATION CONTROL REPORT
================================================================================

Profile: GLG-APPCTL-GENERAL
  Used in Policies: "STAFF-TO-INET" (id: 1), "BREAKGLASS-TO-INET" (id: 3)
--------------------------------------------------------------------------------
  Monitor - Categories:
    - Business
    - Cloud.IT
    - Collaboration
    - Email
    - Game
    - General.Interest
    - Mobile
    - Network.Service
    - Proxy
    - Remote.Access
    - Social.Media
    - Storage.Backup
    - Update
    - Video/Audio
    - VoIP
    - Web.Client
  Block - Categories:
    - P2P
  Block - Applications:
    - BitTorrent
================================================================================
```

Example Web/DNS Clash Output:

The clash report inspects each policy that references both a web filter and a DNS filter profile, and lists any FortiGuard category the two profiles treat differently (any action difference). This helps catch cases where, for example, a category is blocked at the web layer but only monitored at the DNS layer.
```
================================================================================
WEB/DNS FILTER CLASH REPORT
================================================================================

Policy: "staff_internet" (id: 1)
  Web Filter Profile: webflt_general
  DNS Filter Profile: dnsflt_general
  Clashing Categories (1):
    - Streaming Media and Download — webfilter: block, dnsfilter: monitor
================================================================================
```
