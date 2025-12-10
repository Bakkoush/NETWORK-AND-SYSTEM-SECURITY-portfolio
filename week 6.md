Week 6 — Binary Analysis & Symbolic Execution


1. Overview

In Week 6, I explored the foundations of binary analysis, focusing on the static inspection of executable files to support malware triage and reverse-engineering workflows. 
Rather than executing a suspicious binary—which carries inherent risk—static analysis provides a safe method to extract structural information, metadata, behavioural indicators, and potential malicious artefacts.

Using my custom triage.py tool 

triage

, I performed several core binary analysis tasks:

Computing cryptographic hashes

Extracting printable strings

Inspecting PE (Portable Executable) structure

Extracting indicators of compromise (IOCs), such as URLs and IPs

Performing basic signature detection using YARA

These techniques form the backbone of initial malware triage and are directly applicable to digital forensics, reverse engineering, and threat intelligence workflows.

2. Objectives

The goals of this laboratory exercise were to:

Understand the purpose and workflow of static binary analysis

Build a Python-based triage tool

Parse PE files to understand executable layouts

Extract relevant strings and behavioural artefacts

Detect URLs, IP addresses, or suspicious text sequences

Perform lightweight YARA-based signature matching

Reflect on how static analysis informs deeper dynamic or symbolic analysis

3. Architecture & Workflow

The diagram below illustrates the analysis pipeline implemented in Week 6:

                +-----------------------+
                |   Input Binary File   |
                +-----------+-----------+
                            |
                            v
       +-------------------------------------------+
       |        1. Cryptographic Hashing           |
       |   - MD5 / SHA1 / SHA256 fingerprints      |
       +--------------------+----------------------+
                            |
                            v
       +-------------------------------------------+
       |        2. ASCII String Extraction         |
       |   - Command paths                          |
       |   - URLs, registry keys, API hints        |
       +--------------------+----------------------+
                            |
                            v
       +-------------------------------------------+
       |        3. PE Header Inspection            |
       |   - Entry point                           |
       |   - Image base                            |
       |   - Imported DLLs and API functions       |
       +--------------------+----------------------+
                            |
                            v
       +-------------------------------------------+
       |  4. IOC Extraction (URLs / IP addresses)  |
       +--------------------+----------------------+
                            |
                            v
       +-------------------------------------------+
       |       5. YARA Signature Matching          |
       +--------------------+----------------------+
                            |
                            v
                +-----------------------+
                |     Triage Report     |
                +-----------------------+


This pipeline reflects industry-standard triage methodology.

4. Implementation

The binary analysis functionality is implemented in triage.py 

triage

.
Below is a breakdown of each module.

4.1 Cryptographic Hashing

Purpose: fingerprint the binary, compare against malware databases, identify variants.

def compute_hashes(path):
    algos = ["md5", "sha1", "sha256"]


Computing multiple hashes is essential because:

MD5 is fast but collision-prone

SHA1 is deprecated but still widely used in legacy systems

SHA256 is the modern standard for malware identification

These hashes allow analysts to:

Search known-malware databases

Correlate samples

Detect repackaged binaries

4.2 Printable String Extraction

Purpose: Identify readable text, hints, malware behaviour, config data, embedded IOCs, or suspicious commands.

pattern = rb"[ -~]{%d,}" % min_len


String extraction commonly reveals:

Hardcoded URLs

Encryption keys

Malware authorship tags

Command-and-control (C2) indicators

Error messages that hint at functionality

Your tool outputs the first 20 strings as a quick preview.

4.3 PE Header Inspection

Using pefile, the tool extracts executable metadata:

entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
image_base = hex(pe.OPTIONAL_HEADER.ImageBase)


And imported DLLs/functions:

for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll_name = entry.dll.decode()


Key insight:
Malware heavily relies on API imports (e.g., CreateProcess, URLDownloadToFileA, VirtualAlloc), which can reveal intent.

4.4 IOC Extraction (URLs & IPs)

The tool locates basic indicators of compromise:

urls = re.findall(r"https?://[^\s\"']+", decoded)
ips  = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", decoded)


This is vital for:

Threat hunting

Network defenders

Intelligence enrichment

Incident response

Even simple binaries often contain hardcoded network artefacts.

4.5 YARA Signature Matching

The script compiles an inline YARA rule:

rule ContainsHTTP {
    strings:
        $s = "http"
    condition:
        $s
}


This demonstrates how malware analysts use YARA to classify:

Malware families

Suspicious patterns

Known strings or behaviours

Your example rule is intentionally simple but demonstrates the mechanics of local signature matching.

5. Running the Triage Tool

Execution flow:

python triage.py <path_to_binary>


The tool then outputs:

Hashes

Extracted strings

PE header + imports

IOCs

YARA rule matches

This produces a concise triage profile for further investigation.

6. Security Analysis (Expert Level)
✔ Strengths of Static Binary Analysis

Safe — no execution required

Fast first-pass triage

Works on unknown or packed binaries

Reveals structure, imports, configuration strings

Enables high-level behavioural inference

✔ Limitations

Cannot observe dynamic behaviour

Obfuscated binaries may hide strings/imports

Packers remove useful metadata

Cannot reveal runtime C2 communication or syscalls

✔ Relation to Deeper Analysis

Static triage is the gateway to:

Dynamic analysis (sandboxing, debugging)

Memory forensics

Symbolic execution (angr, Triton)

Decompilation (Ghidra, IDA, Binary Ninja)

Your tool forms a foundational layer in this process.

7. Reflection

This lab solidified my understanding of binary analysis as the first step in malware investigation. 
By constructing my own triage tool, I gained deeper insight into how analysts deconstruct unknown binaries and quickly extract meaningful intelligence.

I learned how:

Hashes allow rapid classification and correlation

Strings reveal embedded behaviour and configuration

PE headers expose the execution flow and dependencies

IOC extraction supports threat hunting

YARA rules provide signature-based detection

Although this week did not cover symbolic execution, I now clearly understand how static analysis feeds into deeper reverse-engineering workflows.

Future improvements could include:

Integrating entropy calculations to detect packed binaries

Expanding YARA rules for behavioural signatures

Adding JSON output for automation

Building a GUI or web dashboard for triage reports

This week strengthened my confidence in malware triage methodology and its role in real-world incident response.
