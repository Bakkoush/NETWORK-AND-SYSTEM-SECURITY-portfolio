Week 5 — Web Security
1. Overview

In Week 5, I explored automated web vulnerability scanning using Wapiti, a widely used open-source web application security scanner. The goal of this lab was to understand how automated tools identify weaknesses in web applications, how results should be interpreted, and how each vulnerability maps to broader web security principles such as the OWASP Top Ten and the Web Security Testing Guide (WSTG).

Using my generated Wapiti report 

google-gruyere.appspot.com_1204…

, I analysed the scan output, reviewed identified vulnerabilities, and produced remediation strategies based on secure development and configuration best practices.

2. Objectives

The aims of this week’s lab were to:

Understand the role of automated tools in web security assessments

Run a vulnerability scan against a controlled target

Interpret the results of an automated scan accurately

Map vulnerabilities to relevant OWASP/WSTG categories

Propose both short-term and long-term mitigation strategies

Reflect on the strengths and limitations of automated scanning

3. Scanner Architecture & Workflow

The diagram below represents the simplified workflow of Wapiti during scanning:

                   +------------------------+
                   |  Target Web Application |
                   +-----------+------------+
                               |
                     (1) Crawling Phase
                               |
                               v
                   +------------------------+
                   |     URL Enumeration    |
                   |  • Forms               |
                   |  • Parameters          |
                   |  • Input Vectors       |
                   +-----------+------------+
                               |
                         (2) Attack Phase
                               |
                               v
                   +------------------------+
                   |  Payload Injection     |
                   |  • Headers             |
                   |  • Parameters          |
                   |  • Cookies             |
                   +-----------+------------+
                               |
                      (3) Response Analysis
                               |
                               v
                   +------------------------+
                   |   Vulnerability Report |
                   +------------------------+


This reflects the same high-level process used in other automated scanners like OWASP ZAP, Nikto, and Burp Suite’s Active Scan.

4. Scan Results Summary

According to the generated Wapiti report 

google-gruyere.appspot.com_1204…

, the scanner found four key issues:

Category	Count
Content Security Policy Misconfiguration	1
Clickjacking Protection Missing	1
HTTP Strict Transport Security (HSTS) Missing	1
MIME Type Confusion	1

The rest of the tested categories reported 0 vulnerabilities, including SQL Injection, XSS, CSRF, Path Traversal, Open Redirects, and file upload issues — 
indicating a relatively low attack surface from an input-handling perspective.

5. Detailed Vulnerability Analysis
5.1 Missing Content Security Policy (CSP)

(Severity: Medium)

The scan detected the absence of a Content-Security-Policy header, confirmed in the report summary and detail section 

google-gruyere.appspot.com_1204…

:

CSP is not set

Security Impact

Without CSP, the application is more vulnerable to:

Cross-Site Scripting (XSS)

Injection of malicious JavaScript

Data exfiltration via inline scripts

Clickjacking and UI redressing attacks

Mitigation

Add a restrictive CSP header such as:

Content-Security-Policy: default-src 'self'; frame-ancestors 'none';

5.2 Missing Clickjacking Protection

(Severity: Medium)

The scanner reported that no X-Frame-Options or frame-ancestors directive was set.

Security Impact

Attackers may embed the website inside an invisible iframe and trick users into clicking buttons (“UI redressing”).

Mitigation

Add either:

X-Frame-Options: DENY


or, preferably:

Content-Security-Policy: frame-ancestors 'none';

5.3 Missing HTTP Strict Transport Security (HSTS)

(Severity: Medium)

The scan identified an incomplete or missing HSTS header, which prevents browsers from enforcing HTTPS-only connections.

Security Impact

Susceptibility to downgrade attacks

Increased risk of MitM interception

Exposure during first unprotected request (“HSTS bootstrap problem”)

Mitigation

Set a strict HSTS header:

Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

5.4 MIME Type Confusion

(Severity: Medium)

The report flagged the absence of X-Content-Type-Options, which prevents browsers from MIME sniffing.

Security Impact

MIME sniffing can cause browsers to interpret files as different types than intended, potentially enabling XSS or file execution.

Mitigation

Add:

X-Content-Type-Options: nosniff

6. Testing & Verification

Wapiti generated a full interactive HTML report, using the structure defined in the Wapiti template file 

report

 and CSS stylesheets such as master.css 

master

.

After reviewing each vulnerability:

I validated that headers were indeed missing

I cross-referenced issues with OWASP WSTG codes included in the report

I compared the findings with modern secure configuration baselines (Mozilla Observatory, CIS Benchmarks)

All findings were reproducible and consistent with expected behaviour for an intentionally vulnerable web application.

7. Security Analysis (Expert Level)
✔ Automated Scanning Strengths

Quickly identifies missing configuration-based security headers

Highlights systemic weaknesses (e.g., lack of HTTPS enforcement)

Efficient for broad reconnaissance

Useful for validating baseline security posture

✔ Weaknesses of Automated Scanners

Limited ability to detect business-logic flaws

Cannot exploit advanced vulnerabilities without manual validation

May overlook reflected or DOM-based XSS not triggered by automated payloads

False negatives possible in complex authentication scenarios

✔ Broader Web Security Implications

Each missing header relates to a specific OWASP principle:

Header	OWASP Issue	Protection
CSP	WSTG-CONF-12	Prevents XSS & injection
X-Frame-Options / frame-ancestors	WSTG-CLNT-09	Prevents clickjacking
HSTS	WSTG-CONF-07	Ensures HTTPS-only communication
X-Content-Type-Options	WSTG-CONF-10	Prevents type confusion

These headers form the foundation of secure web application deployment.

8. Reflection

This lab helped reinforce how essential proper configuration is in web security. 
While no injection vulnerabilities were identified, several missing security headers presented real risks. The experience demonstrated that:

Applications can appear “safe” yet still be vulnerable due to weak configurations

Automated scanning is invaluable but must be complemented with manual testing

Security headers are simple to implement yet dramatically reduce the attack surface

Tools like Wapiti align closely with OWASP testing methodologies

Going forward, I aim to extend this work by:

Running comparative scans using OWASP ZAP and Nikto

Implementing the recommended headers and re-scanning

Performing manual exploitation tests to confirm scanner findings

This week solidified my understanding of how automated tools integrate into broader penetration testing workflows.
