# VirusTotal CLI Scanner

A Python-based command-line security scanner that uses the **VirusTotal API v3** to analyze files, URLs, IP addresses, and domains.

The project provides security intelligence through multiple antivirus and threat intelligence vendors, directly from the terminal.

## Features

- **File Scanning**
  - Upload files for security analysis.
  - Calculate SHA-256 file hashes.
  - Retrieve detailed analysis reports.
  - Handle previously analyzed files.

- **URL Scanning**
  - Validate URL formats.
  - Submit URLs for security analysis.
  - Retrieve vendor detection results.

- **IP Address Lookup**
  - Support IPv4 and IPv6 validation.
  - Retrieve IP reputation and network information.
  - Display ASN, country, and organization.
  - Retrieve associated domains.

- **Domain Lookup**
  - Validate domain names.
  - Retrieve domain reputation.
  - Display DNS records.
  - Retrieve security vendor results.

- **Additional Features**
  - Colored terminal output.
  - Input validation.
  - API error handling.
  - Network timeout handling.
  - Analysis status polling.

## Technologies Used

- Python 3
- Requests
- VirusTotal API v3
- IP Address Validation (`ipaddress`)
- URL Parsing (`urllib.parse`)
- SHA-256 Hashing (`hashlib`)
- Base64 Encoding

## Requirements

- Python 3.10 or later
- VirusTotal account and API key
- `requests` library
- Internet connection

## Installation

Clone the repository:

```bash
git clone https://github.com/aswinott21-max/virustotal-cli-scanner.git
```

Navigate into the project directory:

```bash
cd virustotal-cli-scanner
```

Install the required dependency:

```bash
pip install requests
```

## API Key Configuration

Obtain your API key from [VirusTotal](https://www.virustotal.com/).

Set the API key as an environment variable:

```bash
read -s -p "Enter VirusTotal API Key: " VT_API_KEY
echo
export VT_API_KEY
```

The API key is loaded through an environment variable and is not hardcoded in the source code.

## Usage

Start the scanner:

```bash
python virustotal_scanner.py
```

The scanner provides the following menu:

```text
===== VIRUSTOTAL SCANNER =====

1. Scan a file
2. Scan a URL
3. Check an IP address
4. Check a domain
5. Exit
```

Select an option and provide the requested input.

## Security Notice

- Never expose or publish your VirusTotal API key.
- Do not execute suspicious files to test them.
- VirusTotal results are security intelligence, not a guarantee that a resource is safe.
- Different security vendors may produce conflicting results.
- File submissions may be shared with VirusTotal and its security partners. Avoid uploading confidential or sensitive files.

## Project Structure

```text
virustotal-cli-scanner/
│
├── virustotal_scanner.py
├── README.md
└── .gitignore
```

## Future Improvements

- Persistent scan history.
- Logging system.
- Improved API rate-limit handling.
- Exportable scan reports.
- Enhanced terminal interface.

## Author

**Aswin**

GitHub: [@aswinott21-max](https://github.com/aswinott21-max)

## License

This project is currently available without a specified open-source license. All rights are reserved unless a license is added.
