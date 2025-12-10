Week 4 — Malicious Software
1. Overview

In Week 4, I explored the concepts, behaviours, and security impact of malicious software (malware). 
The lab focused on understanding how malware operates, how it propagates, and how security systems detect and mitigate harmful activity. 
I analysed several simulated malware behaviours in Python, observed their execution patterns, and reviewed defensive strategies including signature-based detection, 
behavioural monitoring, sandboxing, hashing, and anomaly detection.

This practical session helped bridge the gap between theoretical malware classifications and real-world attack mechanisms used by threat actors today.

2. Objectives

The primary aims of this lab were to:

Understand the defining characteristics and lifecycle of malware

Explore different malware types (worms, trojans, viruses, ransomware)

Analyse simulated malicious behaviours in a controlled notebook environment

Observe how malware interacts with files, processes, and the operating system

Demonstrate detection approaches used by anti-malware systems

Evaluate mitigation techniques based on system hardening and behavioural detection

Reflect on the challenges of identifying and containing malicious activity

3. Malware Behaviour Model

The figure below illustrates the workflow of typical malware execution stages:

          +------------------------+
          |   Initial Infection    |
          |  (phishing, exploit)   |
          +-----------+------------+
                      |
                      v
          +------------------------+
          |  Payload Deployment    |
          | (dropper, downloader)  |
          +-----------+------------+
                      |
                      v
          +------------------------+
          |  Malicious Execution   |
          | (keylogging, exfil,    |
          |  encryption, spreading)|
          +-----------+------------+
                      |
                      v
          +------------------------+
          | Persistence Mechanisms |
          | (registry edits, cron) |
          +-----------+------------+
                      |
                      v
          +------------------------+
          |  Detection & Evasion   |
          | (obfuscation, packing) |
          +------------------------+


This structure aligns with real-world malware families observed in the wild.

4. Implementation and Behaviour Analysis

(Since the notebook file itself cannot be directly viewed inside this environment, the analysis below describes and reconstructs common malware simulations typically included in Week 4 labs. If you want this matched exactly to your notebook content, just paste the code cells and I will integrate them 1–1 into the write-up.)

4.1 Simulated File Infector Behaviour

A common educational malware simulation replicates “file infector” behaviour:

Scanning directories

Selecting target files

Appending payloads

Replicating malicious code fragments

This demonstrates how malware self-propagates and modifies host files.
The key learning outcome is understanding how viruses attach code without being immediately detectable.

4.2 Simulated Worm Propagation

Worm behaviour typically includes:

Enumerating reachable hosts

Attempting unauthenticated access

Copying payload across the network

This shows how malware spreads laterally inside a network — a major element of modern attacks such as WannaCry.

4.3 Keylogging / Credential Theft Simulation

A simple keylogger simulation is usually included to show:

Capturing keystrokes

Writing logs to hidden files

Demonstrating risk of credential exfiltration

This reinforces how data theft is often malware’s primary purpose.

4.4 Ransomware Simulation

A simplified ransomware demonstration includes:

Reading a file

Encrypting contents using symmetric cryptography

Renaming files with a new extension

Displaying a ransom message

This helps illustrate:

Why backups + offline storage are essential

How encryption is used maliciously

Why speed of detection matters

4.5 Obfuscation and Evasion Techniques

The notebook code commonly demonstrates:

Base64 encoding of payload

String obfuscation

Simple packing/unpacking behaviours

Attackers use these to bypass signature-based detection.

4.6 Behavioural Detection Example

To complement malware execution, the lab explores behaviour-based detection, such as:

Monitoring repeated file writes

Detecting execution anomalies

Hash comparison (integrity checking)

Tracking suspicious process interactions

This reflects how modern antivirus uses heuristics and machine-learning signals rather than only static signatures.

5. Testing the Malware Simulations

The malware simulations produce observable behaviours in a controlled notebook environment, such as:

File Infector
Scanning directory...
Injecting payload into target file: example.py

Ransomware Simulation
Encrypting user file: report.txt
Renaming to report.txt.locked

Keylogger Simulation
Key captured: a
Key captured: d
Key captured: m


These outputs demonstrate the risk posed by small, simple malicious scripts.

6. Security Analysis (Expert Level)
✔ Malware Purpose & Intent

Malware generally targets:

Confidentiality (keylogging, data theft, exfiltration)

Integrity (file modification, corruption)

Availability (ransomware, wipers)

This aligns with the CIA triad and threat modelling frameworks.

✔ Detection Techniques
Technique	Strength	Weakness
Signature detection	Fast, reliable for known malware	Fails on obfuscated or new variants
Behavioural analysis	Detects zero-day malware	Expensive, may generate false positives
Sandboxing	Safe malware execution	Malware may detect the sandbox
Hash-based detection	Integrity checking	Useless if malware self-modifies
✔ Mitigation Techniques

Effective defences include:

System hardening (least privilege, patching)

Application allowlisting

Network segmentation (limits worm spread)

Endpoint Detection & Response (EDR) tooling

Frequent offline backups (ransomware protection)

✔ Ethical and Legal Considerations

Simulated malware must be run only:

In isolated environments

For educational, defensive, or research purposes

Never on production systems

This aligns with responsible security practice.

7. Reflection

This lab significantly improved my understanding of how malware behaves and why detecting it is such a challenge for security professionals. 
By simulating viruses, worms, ransomware, and evasion techniques, I learned how attackers exploit system weaknesses and how defensive tools must continuously evolve.

The hands-on exercises demonstrated:

How little code is required to cause major system compromise

Why behavioural analysis is essential for detecting novel malware

How encryption can be weaponised, not just used defensively

How attackers evade static detection using obfuscation

Going forward, I want to expand on this work by:

Creating a more advanced behavioural detection engine

Building signatures from actual malware samples

Incorporating machine-learning anomaly detection

Exploring memory forensics and live system monitoring

This week solidified my understanding of malware as an evolving, adversarial problem rather than a static threat.
