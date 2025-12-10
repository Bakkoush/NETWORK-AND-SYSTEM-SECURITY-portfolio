Week 7 — Penetration Testing & Ethical Hacking
1. Overview

In Week 7, I expanded my understanding of penetration testing and ethical hacking by developing a Python-based reconnaissance toolkit. 
Reconnaissance is the first and most critical stage of the penetration testing lifecycle, forming the basis for threat modelling, attack surface mapping, and vulnerability exploitation.

The toolkit I built performs:

Domain information lookup (DNS + IP intelligence API)

HTTP header reconnaissance

Basic TCP port scanning

Nmap service enumeration (if python-nmap is installed)

These capabilities replicate the behaviour of common reconnaissance tools such as whois, curl, nmap, and netcat, but inside a single customisable Python script.

This week strengthened my ability to map a target environment, gather intelligence legally and ethically, and understand how attackers structure the early stages of an engagement.

2. Objectives

The goals of this lab were to:

Implement key reconnaissance techniques using Python

Perform passive and active information gathering

Understand the purpose and risks of port scanning and service enumeration

Integrate external IP intelligence APIs for enriched reporting

Learn ethical and legal constraints of penetration testing activities

Build a modular reconnaissance toolkit for real-world assessments

3. System Architecture
               +----------------------------------+
               |   Penetration Testing Toolkit    |
               +-----------------+----------------+
                                 |
   +-----------------------------+----------------------------+
   |                             |                            |
   v                             v                            v
+----------+              +--------------+             +-----------------+
| Domain   |              | HTTP Header  |             | Port Scanner    |
| Lookup   |              | Enumeration  |             | (TCP Connect)   |
+---+------+              +------+-------+             +--------+--------+
    |                             |                           |
    v                             v                           v
 WHOIS-like Info          Security Headers          Open Ports Identified
 IP Intelligence          Fingerprinting            Service Exposure Map
    |                             |                           |
    +-----------------------------+----------------------------+
                                 |
                                 v
                       +---------------------+
                       |   Nmap Enumeration  |
                       |  (version, service) |
                       +---------------------+


This pipeline mirrors real-world reconnaissance flows found in the PTES, OSSTMM, and OWASP Testing Guide methodologies.

4. Implementation Breakdown

Your Python script (Penetration Testing Toolkit) contains four main recon functions.

4.1 Domain Information Lookup

This module resolves a domain to an IP and queries an IP intelligence API:

ip = socket.gethostbyname(domain)
response = requests.get(f"https://ipapi.co/{ip}/json/")


It retrieves WHOIS-style metadata such as:

Organisation

City

Country

ASN

Timezone

This helps analysts understand the infrastructure behind a target and identify potential hosting providers or cloud environments.

4.2 HTTP Header Reconnaissance

Using a HEAD request, the toolkit extracts server banners and security headers:

response = requests.head(url)
for k, v in response.headers.items():
    print(f"{k}: {v}")


HTTP headers reveal valuable information:

Web server type (Apache, Nginx, IIS)

Programming framework

Security posture (CSP, HSTS, X-Frame-Options, Cookies)

Missing headers often indicate misconfigurations or outdated deployments.

4.3 Basic TCP Port Scanner

A lightweight “TCP connect” scanner:

result = s.connect_ex((host, port))
if result == 0:
    print(f"Port {port} is OPEN")


This identifies externally reachable services.
Open ports reveal:

Attack surface

Entry points for exploitation

Lateral movement paths

While simple, this method mimics tools like netcat or the early Nmap -sT scan.

4.4 Nmap Service Enumeration

If python-nmap is installed:

nm.scan(host, ports, arguments='-sV')


Nmap’s -sV flag fingerprint services and versions:

Exposed SSH / FTP / HTTP services

Software versions (useful for CVE matching)

Deprecated or insecure protocols

This provides a deeper view of potential vulnerabilities beyond mere port openness.

If Nmap is unavailable, the toolkit falls back gracefully and notifies the user.

5. Example Execution Output

Running the toolkit may produce output such as:

Domain: python.com
IP Address: 151.101.128.223
Org: Fastly
Country: United States
ASN: AS54113

Headers for https://www.example.com:
Server: ECD (sec/1234)
Content-Type: text/html; charset=UTF-8

Port Scanner:
Port 22 OPEN
Port 80 OPEN

Nmap scan:
Port 22: ssh OpenSSH 8.2
Port 80: http Apache 2.4.41


This maps the visible external footprint of the system.

6. Security Analysis (Expert Level)
✔ Strengths of Reconnaissance

Establishes the external-facing attack surface

Identifies outdated or vulnerable services

Reveals misconfigured HTTP security settings

Provides infrastructure metadata useful for threat modelling

✔ Risks & Ethical Considerations

Because this week is titled Ethical Hacking, I applied strict safeguards:

Activity	Risk	Ethical Requirement
Port scanning	Can be interpreted as hostile	Must have explicit permission
Banner grabbing	Reveals server info	Allowed only on authorised systems
IP intelligence lookup	External API queries	Avoid leaking sensitive internal IPs
Nmap	Highly intrusive	Use only in controlled, authorised labs

This aligns with:

Computer Misuse Act (CMA)

ACM Code of Ethics

PTES Legal Considerations

✔ Limitations of Automated Recon

Cannot confirm vulnerabilities without manual testing

Port scanning does not reveal misconfigurations inside services

Headers alone do not guarantee correct security policy enforcement

API intel sometimes incomplete

7. Reflection

This week helped me understand reconnaissance as a structured, disciplined component of ethical hacking rather than a chaotic collection of tools. Writing my own recon toolkit forced me to think about:

How penetration testers fingerprint systems

Why information gathering must precede exploitation

How easily accessible metadata can reveal weaknesses

Ethical and legal constraints on scanning real systems

Developing these tools myself also clarified how larger frameworks (e.g., Nmap, ZAP, Nessus) operate internally.

If I extend this toolkit, I would:

Add subdomain enumeration

Implement threaded or asynchronous port scanning

Extract SSL/TLS configuration

Add directory brute-forcing and crawler modules

Build a reporting engine in Markdown or HTML

This lab deepened my understanding of ethical hacking methodology and strengthened my practical reconnaissance skills.
