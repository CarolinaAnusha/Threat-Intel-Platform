# Threat Intelligence Platform (TIP)

An AI-powered cyber threat intelligence platform that automates threat investigation by combining IOC extraction, vulnerability enrichment, MITRE ATT&CK mapping, AI-assisted analysis, and detection engineering into a single workflow.

The platform helps SOC analysts reduce manual effort by transforming raw threat reports into actionable intelligence, complete with risk assessment, ATT&CK techniques, detection rules, and investigation history.

---

# Features

## AI-Powered Threat Analysis
- Generates executive threat summaries using Groq (Llama 3.1)
- Produces attack scenario analysis
- Business impact assessment
- Immediate response recommendations
- Long-term remediation guidance
- Continuous monitoring recommendations
- AI Analyst Assessment with confidence reasoning

---

## IOC Extraction

Automatically extracts Indicators of Compromise including:

- IPv4 Addresses
- Domains
- URLs
- CVEs
- Email Addresses
- MD5 Hashes
- SHA1 Hashes
- SHA256 Hashes

---

## Vulnerability Enrichment

Enriches extracted CVEs with:

- CVSS Score
- Exploit Availability
- Malware Families
- Associated Threat Actors

---

## Dynamic Risk Scoring

Calculates a contextual risk score based on:

- CVSS Severity
- Public Exploit Availability
- Malware Associations
- Threat Actor Associations
- IOC Types
- Number of Correlated Indicators

Risk Levels:

- Low
- Medium
- High
- Critical

---

## MITRE ATT&CK Mapping

Maps observed attack behavior to MITRE ATT&CK tactics and techniques.

Examples include:

- Initial Access
- Credential Access
- Execution
- Persistence
- Discovery
- Command and Control

---

## Detection Engineering

Automatically generates detection content for multiple security platforms.

Supported Formats:

- Sigma
- YARA
- Splunk SPL
- Microsoft Sentinel (KQL)
- Elastic Query DSL

Detection content is dynamically generated based on the extracted indicators.

---

## IOC Relationship Graph

Automatically visualizes relationships between:

- Domains
- IP Addresses
- CVEs
- Malware
- Threat Actors

This helps analysts understand attack infrastructure quickly.

---

## File Upload Support

Supports analysis of uploaded threat reports.

Supported formats include:

- TXT
- PDF
- DOCX

Uploaded files follow the same complete analysis pipeline as text-based submissions.

---

## Investigation History

Stores every completed investigation including:

- Analysis ID
- Timestamp
- Risk Score
- Risk Level
- Original Input
- Full Analysis Result

---

# Technology Stack

## Frontend

- Next.js
- React
- TypeScript
- Tailwind CSS

## Backend

- FastAPI
- Python

## AI

- Groq API
- Llama 3.1

## Database

- SQLite
- SQLAlchemy

---

# System Architecture

```
                User Input
                     │
                     ▼
          Threat Intelligence Platform
                     │
         ┌───────────┴────────────┐
         │                        │
         ▼                        ▼
 IOC Extraction           File Parser
         │
         ▼
 Vulnerability Enrichment
         │
         ▼
 Dynamic Risk Scoring
         │
         ▼
 MITRE ATT&CK Mapping
         │
         ▼
 AI Threat Assessment (Groq)
         │
         ▼
 Detection Rule Generation
         │
         ▼
 IOC Relationship Graph
         │
         ▼
 Investigation History
```

---

# Project Structure

```
frontend/
│
├── src/
│   ├── app/
│   │   ├── dashboard/
│   │   ├── analysis/
│   │   ├── mitre/
│   │   ├── globals.css
│   │   └── layout.tsx
│
backend/
│
├── app/
│   ├── agents/
│   ├── routers/
│   ├── services/
│   ├── models/
│   ├── database/
│   └── main.py
```

---

# Installation

## Clone Repository

```bash
git clone <repository-url>
cd threat-intelligence-platform
```

---

## Backend

```bash
cd backend

python -m venv venv

venv\Scripts\activate

pip install -r requirements.txt

uvicorn app.main:app --reload
```

Backend:

```
http://127.0.0.1:8000
```

Swagger Documentation:

```
http://127.0.0.1:8000/docs
```

---

## Frontend

```bash
cd frontend

npm install

npm run dev
```

Frontend:

```
http://localhost:3000
```

---

# Usage

1. Open the Dashboard.

2. Paste a threat report or upload a file.

3. Run Threat Analysis.

4. Review:

- Extracted IOCs
- AI Threat Assessment
- Risk Score
- MITRE ATT&CK Mapping
- IOC Graph
- Detection Rules

5. Access previous investigations through Analysis History.

---

# Sample Threat Report

```
A phishing campaign targeted enterprise users.

The attackers used secure-login-update.com
which resolved to 185.199.108.153.

The campaign exploited CVE-2023-3519 to obtain
initial access before harvesting user credentials.
```

---

# Future Enhancements

- VirusTotal Integration
- AbuseIPDB Integration
- MISP Integration
- STIX/TAXII Support
- Real-time Threat Feed Monitoring
- PDF Report Export
- Multi-user Authentication
- Case Management
- Threat Hunting Dashboards

---
