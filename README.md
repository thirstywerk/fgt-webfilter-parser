# fgt-webfilter-parser
Generates a VDOM-specific report of **WebFilter**, **DNS Filter** and **Application Control** profiles referenced in firewall policies (Name &amp; ID); unreferenced profiles are skipped by default (see `--include-unused`). Each profile's configured comment, if any, is shown. It can also flag FortiGuard categories where a policy's web filter and DNS filter profiles assign different actions (a "clash"). Requires a super-admin read-only API key. The script explicitly bypasses local proxies.

Every flag has a short and long form (e.g. `-f`/`--fqdn`, `-o`/`--output-file`) — see the usage block below for the full list.

By default TLS certificate verification is skipped, since FortiGate appliances typically ship with a self-signed certificate. If your device's cert is signed by a CA you trust (e.g. an internal CA), pass `--ca-bundle <path>` to verify against it instead.

By default (no section flag) all four reports are produced. Pass one or more of `--webfilter`, `--dnsfilter`, `--appcontrol`, `--check-clash` to limit output to those sections. `--check-clash` always fetches both web and DNS filter data regardless of the other flags. Pass `--include-unused` to additionally list profiles that exist but aren't referenced by any policy; these appear in a `CONFIGURED BUT UNUSED PROFILES` section at the end of each report.

The read-only API key must have read access to the `webfilter`, `dnsfilter`, `application` and `firewall/policy` endpoints. Prefer setting it via the `FGT_API_KEY` environment variable rather than passing `--api-key` directly — passing the key on the command line always leaves it visible to other local users via the process list (`ps`/`/proc/<pid>/cmdline`) while the script runs.

Note that setting `FGT_API_KEY` inline on the same line as the command (`FGT_API_KEY=... python generate-report.py ...`) does **not** keep it out of shell history — bash records the whole line you type regardless of the `VAR=value` prefix. To actually avoid history, prompt for it separately and export it:
```
read -rs FGT_API_KEY && export FGT_API_KEY
```
This never puts the key on a command line, so it can't leak via history or `ps`. (If your shell has `HISTCONTROL` set to `ignorespace`/`ignoreboth` — check with `echo $HISTCONTROL` — a leading space before a command also keeps that one line out of history, e.g. ` export FGT_API_KEY=...`.)

`--vdom` is optional and defaults to `root` (FortiGate's default VDOM on non-VDOM-enabled firewalls). Any omitted argument that has a default is listed in a `Defaults used:` summary printed at the start of a run; pass `--quiet` to suppress it.

Pass `--output-file`/`-o <path>` to also write the report text to a file — only the report sections go there, never the progress/status messages, which always go to stdout only. Combine with `--very-quiet` to suppress all stdout output too (requires `-o`, since otherwise there'd be no output at all).

> Note: Application Control *category* IDs cannot be resolved to names via the API, so they are mapped from the hardcoded `APP_CATEGORIES` table in `generate-report.py`. Any unmapped ID is shown as `Category-<id>`. Run with `--list-app-categories` to print every category ID present on the device alongside example application names — use this to identify and add missing names to `APP_CATEGORIES` for your FortiOS version.

Usage:
```
usage: generate-report.py [-h] -f FQDN [-v VDOM] [-k API_KEY] [-w] [-d] [-a]
                          [-c] [-u] [-l] [-b PATH] [-o PATH] [-q] [-Q]

Connect to FortiGate API

options:
  -h, --help            show this help message and exit
  -f, --fqdn FQDN       Fully Qualified Domain Name with optional port
                        (FQDN[:PORT])
  -v, --vdom VDOM       Virtual Domain name (default: 'root', FortiGate's
                        default VDOM)
  -k, --api-key API_KEY
                        API key for authentication. Passing this leaves it
                        visible in shell history and process listings; prefer
                        setting the FGT_API_KEY environment variable instead
                        (see examples below).
  -w, --webfilter       Include the WebFilter profile report
  -d, --dnsfilter       Include the DNS Filter profile report
  -a, --appcontrol      Include the Application Control report
  -c, --check-clash     Include the Web/DNS filter clash report
  -u, --include-unused  Also list profiles that are configured but not
                        referenced by any policy, in a "CONFIGURED BUT UNUSED
                        PROFILES" section at the end of each report (default:
                        only used profiles are shown)
  -l, --list-app-categories
                        List application category IDs with example app names
                        and exit (helps map/verify the APP_CATEGORIES table)
  -b, --ca-bundle PATH  Verify the FortiGate's TLS certificate against this CA
                        bundle (e.g. the internal CA that issued it). By
                        default TLS verification is skipped, since FortiGate
                        appliances typically ship with a self-signed
                        certificate.
  -o, --output-file PATH
                        Also write report text to this file (progress/status
                        messages are never written to it, only stdout).
  -q, --quiet           Suppress the "Defaults used:" summary printed for any
                        omitted argument.
  -Q, --very-quiet      Suppress all stdout output (progress messages, the
                        "Defaults used:" summary, and report text). Requires
                        --output-file/-o, since otherwise there would be no
                        output at all.

Examples:
  read -rs FGT_API_KEY && export FGT_API_KEY   # prompts silently, never touches
                                                # the command line or shell history
  python generate-report.py --fqdn dc-abc-fw01.xy.com:8443 --vdom FG-traffic
  python generate-report.py --fqdn dc-abc-fw01.xy.com:8443 --vdom FG-traffic --api-key YOUR_API_KEY
  python generate-report.py --fqdn dc-abc-fw01.xy.com:8443 -o report.txt --very-quiet
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
