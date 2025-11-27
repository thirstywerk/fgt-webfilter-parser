# fgt-webfilter-parser
Generates a VDOM-specific report of webfilter profiles referenced in firewall policies (Name &amp; ID); unreferenced profiles are skipped. Requires a super-admin read-only API key. The script explicitly bypasses local proxies.

Usage:
```
usage: generate-report.py [-h] fqdn vdom api_key

Connect to FortiGate API

positional arguments:
  fqdn        Fully Qualified Domain Name with optional port (FQDN[:PORT])
  vdom        Virtual Domain name
  api_key     API key for authentication

options:
  -h, --help  show this help message and exit

Examples:
  python generate-report.py dc-abc-fw01.xy.com:8443 FG-traffic YOUR_API_KEY
  python generate-report.py dc-abc-fw02.xy.com FG-traffic YOUR_API_KEY
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
