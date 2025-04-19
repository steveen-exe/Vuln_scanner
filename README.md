# Advanced Vulnerability Scanner

## Overview
This tool is designed to perform security assessments of web applications by scanning for common vulnerabilities such as:
- Missing security headers
- Cross-Site Scripting (XSS)
- SQL Injection (SQLi)
- Open ports

It generates **detailed reports** in both **text** and **JSON** formats to help security professionals quickly analyze the findings.

## Features
- **Security Header Check**: Verifies the presence of key HTTP security headers (e.g., HSTS, X-XSS-Protection).
- **XSS Vulnerability Check**: Tests for potential XSS vulnerabilities in forms by injecting payloads.
- **SQL Injection Check**: Checks for possible SQL injection vulnerabilities by injecting typical payloads.
- **Port Scanning**: Performs a multi-threaded scan of open ports on the target host.
- **Report Generation**: Saves results in text and JSON formats for easy review and analysis.

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/steveen-exe/Simple_vuln_scanner.git
   cd vuln-scanner
