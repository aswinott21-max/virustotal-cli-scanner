import os
import base64
import requests
import ipaddress
import hashlib
import time
from urllib.parse import urlparse
from datetime import datetime, timezone

# VirusTotal API configuration
API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"

# Terminal colors
RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"

HEADERS = {
    "x-apikey": API_KEY or ""
}


def format_date(timestamp):
    """Convert Unix timestamp into readable UTC date."""
    if not timestamp:
        return "N/A"

    return datetime.fromtimestamp(
        timestamp, timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")




def get_analysis(analysis_id):
    """Poll VirusTotal until the file or URL analysis completes."""

    url = f"{BASE_URL}/analyses/{analysis_id}"

    print("\nWaiting for scan results...")

    for attempt in range(12):
        try:
            response = requests.get(
                url,
                headers=HEADERS,
                timeout=30
            )

            status = response.status_code

            if status == 401:
                print(f"{RED}Invalid or unauthorized API key.{RESET}")
                return False

            if status == 403:
                print(f"{RED}Access forbidden. Check your API permissions.{RESET}")
                return False

            if status == 404:
                print(
                    f"Analysis not available yet. "
                    f"Retrying ({attempt + 1}/12)..."
                )
                time.sleep(15)
                continue

            if status == 429:
                print(
                    f"{YELLOW}Rate limit reached. "
                    f"Waiting before retrying...{RESET}"
                )
                time.sleep(15)
                continue

            if status >= 500:
                print(
                    f"{YELLOW}VirusTotal server error ({status}). "
                    f"Retrying...{RESET}"
                )
                time.sleep(15)
                continue

            response.raise_for_status()

            data = response.json()["data"]
            attributes = data["attributes"]

            if attributes.get("status") == "completed":
                stats = attributes.get("stats", {})

                print(f"\n{CYAN}===== SCAN RESULTS ====={RESET}")
                print(f"{RED}Malicious: {stats.get('malicious', 0)}{RESET}")
                print(f"{YELLOW}Suspicious: {stats.get('suspicious', 0)}{RESET}")
                print(f"{GREEN}Harmless: {stats.get('harmless', 0)}{RESET}")
                print(f"{CYAN}Undetected: {stats.get('undetected', 0)}{RESET}")

                return True

            print(f"Scan in progress... ({attempt + 1}/12)")
            time.sleep(15)

        except requests.RequestException as error:
            print(f"{RED}Error checking analysis: {error}{RESET}")
            return False

        except (KeyError, ValueError) as error:
            print(f"{RED}Invalid analysis response: {error}{RESET}")
            return False

    print(f"{YELLOW}Analysis could not be retrieved. Try again later.{RESET}")
    return False




def scan_file():
    """Upload a file and display its detailed security report."""

    file_path = input("Enter file path: ").strip()

    # Validate empty path
    if not file_path:
        print(f"{RED}File path cannot be empty.{RESET}")
        return

    # Validate file existence
    if not os.path.exists(file_path):
        print(f"{RED}File not found.{RESET}")
        return

    # Reject directories
    if not os.path.isfile(file_path):
        print(f"{RED}The provided path is not a file.{RESET}")
        return

    try:
        # Calculate SHA-256 hash
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(8192), b""):
                sha256.update(chunk)

        file_hash = sha256.hexdigest()
        file_size = os.path.getsize(file_path)

        print(f"\n{CYAN}===== FILE INFORMATION ====={RESET}")
        print(f"File Name: {os.path.basename(file_path)}")
        print(f"File Size: {file_size:,} bytes")
        print(f"SHA-256: {file_hash}")

        # Upload file
        upload_url = f"{BASE_URL}/files"

        with open(file_path, "rb") as file:
            response = requests.post(
                upload_url,
                headers=HEADERS,
                files={"file": file},
                timeout=120
            )

        if response.status_code == 409:
            print(f"\n{YELLOW}Upload conflict detected.{RESET}")
            print("Checking for an existing VirusTotal report...")

        else:
            response.raise_for_status()

            analysis_id = response.json()["data"]["id"]

            print(f"{GREEN}File uploaded successfully.{RESET}")

            if not get_analysis(analysis_id):
                return

        # Retrieve detailed file report
        report_url = f"{BASE_URL}/files/{file_hash}"

        response = requests.get(
            report_url,
            headers=HEADERS,
            timeout=30
        )

        response.raise_for_status()

        attributes = response.json()["data"]["attributes"]

        # File details
        print(f"\n{CYAN}===== DETAILED FILE REPORT ====={RESET}")
        print(f"SHA-256: {attributes.get('sha256', file_hash)}")
        print(f"File Type: {attributes.get('type_description', 'N/A')}")
        print(f"File Size: {attributes.get('size', file_size):,} bytes")

        print(
            f"First Submission: "
            f"{format_date(attributes.get('first_submission_date'))}"
        )

        print(
            f"Last Analysis: "
            f"{format_date(attributes.get('last_analysis_date'))}"
        )

        # Security statistics
        stats = attributes.get("last_analysis_stats", {})

        print(f"\n{CYAN}--- SECURITY STATISTICS ---{RESET}")
        print(f"{RED}Malicious: {stats.get('malicious', 0)}{RESET}")
        print(f"{YELLOW}Suspicious: {stats.get('suspicious', 0)}{RESET}")
        print(f"{GREEN}Harmless: {stats.get('harmless', 0)}{RESET}")
        print(f"{CYAN}Undetected: {stats.get('undetected', 0)}{RESET}")
        print(f"{MAGENTA}Timeout: {stats.get('timeout', 0)}{RESET}")
        print(f"Total Analysed Vendors: {sum(stats.values())}")

        # Individual vendor results
        vendor_results = attributes.get("last_analysis_results", {})

        print(f"\n{CYAN}===== SECURITY VENDOR RESULTS ====={RESET}")

        categories = [
            ("malicious", RED),
            ("suspicious", YELLOW),
            ("harmless", GREEN),
            ("undetected", CYAN),
            ("timeout", MAGENTA),
            ("other", RESET)
        ]

        if vendor_results:
            for category, color in categories:
                matching_vendors = [
                    (vendor, result)
                    for vendor, result in vendor_results.items()
                    if result.get("category") == category
                ]

                if matching_vendors:
                    print(f"\n{color}--- {category.upper()} ---{RESET}")

                    for vendor, result in matching_vendors:
                        verdict = result.get("result") or "No detection"
                        print(f"{color}{vendor}: {verdict}{RESET}")
        else:
            print("No vendor results available.")

    except PermissionError:
        print(f"{RED}Permission denied: Cannot read this file.{RESET}")

    except requests.HTTPError as error:
        status = error.response.status_code if error.response is not None else None

        if status == 401:
            print(f"{RED}Invalid or unauthorized API key.{RESET}")
        elif status == 403:
            print(f"{RED}VirusTotal access forbidden.{RESET}")
        elif status == 404:
            print(f"{RED}File report not found.{RESET}")
        elif status == 429:
            print(f"{YELLOW}VirusTotal rate limit exceeded. Try again later.{RESET}")
        elif status and status >= 500:
            print(f"{RED}VirusTotal server error ({status}). Try again later.{RESET}")
        else:
            print(f"{RED}File scan failed: {error}{RESET}")

    except requests.RequestException as error:
        print(f"{RED}Network error during file scan: {error}{RESET}")

    except (OSError, ValueError, KeyError) as error:
        print(f"{RED}File processing failed: {error}{RESET}")






def scan_url():
    """Scan a URL and display its detailed security report."""

    target_url = input("\nEnter URL: ").strip()

    if not target_url:
        print(f"{RED}URL cannot be empty.{RESET}")
        return

    try:
        # Validate URL format
        if any(character.isspace() for character in target_url):
            print(f"{RED}Invalid URL. Spaces are not allowed.{RESET}")
            return

        parsed_url = urlparse(target_url)

        if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname:
            print(f"{RED}Invalid URL. Enter a valid HTTP or HTTPS URL.{RESET}")
            return

        # Validate port if provided
        _ = parsed_url.port

        print(f"\n{CYAN}Submitting URL for analysis...{RESET}")

        # Submit URL to VirusTotal
        response = requests.post(
            f"{BASE_URL}/urls",
            data={"url": target_url},
            headers=HEADERS,
            timeout=30
        )
        response.raise_for_status()

        analysis_id = response.json()["data"]["id"]

        print(f"{GREEN}URL submitted successfully!{RESET}")

        # Wait for analysis to complete
        if not get_analysis(analysis_id):
            return

        # Generate VirusTotal URL ID
        url_id = base64.urlsafe_b64encode(
            target_url.encode()
        ).decode().strip("=")

        # Retrieve detailed URL report
        report_response = requests.get(
            f"{BASE_URL}/urls/{url_id}",
            headers=HEADERS,
            timeout=30
        )
        report_response.raise_for_status()

        data = report_response.json()["data"]["attributes"]

        # URL information
        print(f"\n{CYAN}========== URL REPORT =========={RESET}")
        print(f"URL: {target_url}")

        final_url = data.get("last_final_url")
        if final_url and final_url != target_url:
            print(f"Final URL: {final_url}")

        if data.get("title"):
            print(f"Page Title: {data['title']}")

        print(f"Reputation: {data.get('reputation', 'N/A')}")

        # Submission and analysis dates
        if data.get("first_submission_date"):
            print(
                f"First Submission: "
                f"{format_date(data['first_submission_date'])}"
            )

        if data.get("last_analysis_date"):
            print(
                f"Last Analysis: "
                f"{format_date(data['last_analysis_date'])}"
            )

        # Security statistics
        stats = data.get("last_analysis_stats", {})

        print(f"\n{YELLOW}Security Statistics:{RESET}")

        categories = [
            "malicious",
            "suspicious",
            "harmless",
            "undetected",
            "timeout"
        ]

        for category in categories:
            print(f"{category.capitalize()}: {stats.get(category, 0)}")

        print(f"Total: {sum(stats.values())}")

        # URL categories
        url_categories = data.get("categories", {})

        if url_categories:
            print(f"\n{YELLOW}URL Categories:{RESET}")
            for vendor, category in url_categories.items():
                print(f"{vendor}: {category}")

        # Vendor results
        results = data.get("last_analysis_results", {})

        print(f"\n{CYAN}========== VENDOR RESULTS =========={RESET}")

        for category in categories:
            matching_results = {
                vendor: result
                for vendor, result in results.items()
                if result.get("category") == category
            }

            if matching_results:
                print(f"\n{YELLOW}{category.upper()}:{RESET}")

                for vendor, result in matching_results.items():
                    color = (
                        RED if category == "malicious"
                        else YELLOW if category == "suspicious"
                        else GREEN if category == "harmless"
                        else CYAN
                    )

                    print(
                        f"{color}{vendor}: "
                        f"{result.get('result') or category}{RESET}"
                    )

        # Other vendor categories
        other_results = {
            vendor: result
            for vendor, result in results.items()
            if result.get("category") not in categories
        }

        if other_results:
            print(f"\n{MAGENTA}OTHER:{RESET}")

            for vendor, result in other_results.items():
                print(
                    f"{MAGENTA}{vendor}: "
                    f"{result.get('result') or result.get('category')}{RESET}"
                )

    except requests.HTTPError as error:
        status = error.response.status_code if error.response is not None else None

        if status == 401:
            print(f"{RED}Invalid or unauthorized API key.{RESET}")
        elif status == 403:
            print(f"{RED}VirusTotal access forbidden.{RESET}")
        elif status == 404:
            print(f"{RED}URL report not found.{RESET}")
        elif status == 429:
            print(f"{YELLOW}VirusTotal rate limit exceeded. Try again later.{RESET}")
        elif status and status >= 500:
            print(f"{RED}VirusTotal server error ({status}). Try again later.{RESET}")
        else:
            print(f"{RED}API Error: {error}{RESET}")

    except requests.RequestException as error:
        print(f"{RED}Network error: {error}{RESET}")

    except (KeyError, ValueError) as error:
        print(f"{RED}Error processing URL: {error}{RESET}")


def check_ip():
    """Retrieve complete IP address security information."""

    ip_address = input("Enter IP address: ").strip()

    if not ip_address:
        print(f"{RED}IP address cannot be empty.{RESET}")
        return

    # Validate and normalize IPv4 or IPv6
    try:
        ip_address = str(ipaddress.ip_address(ip_address))
    except ValueError:
        print(f"{RED}Invalid IP address. Enter a valid IPv4 or IPv6 address.{RESET}")
        return

    url = f"{BASE_URL}/ip_addresses/{ip_address}"

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=30
        )

        response.raise_for_status()

        data = response.json()["data"]
        attributes = data.get("attributes", {})

        print(f"\n{CYAN}===== IP ADDRESS SECURITY REPORT ====={RESET}")

        # IP information
        print(f"\n{CYAN}--- IP INFORMATION ---{RESET}")
        print(f"IP Address: {ip_address}")
        print(f"Reputation: {attributes.get('reputation', 'N/A')}")
        print(f"Country: {attributes.get('country', 'N/A')}")
        print(f"Network: {attributes.get('network', 'N/A')}")
        print(f"ASN: {attributes.get('asn', 'N/A')}")
        print(f"Organization: {attributes.get('as_owner', 'N/A')}")

        # Security statistics
        stats = attributes.get("last_analysis_stats", {})

        print(f"\n{CYAN}--- SECURITY STATISTICS ---{RESET}")
        print(f"{RED}Malicious: {stats.get('malicious', 0)}{RESET}")
        print(f"{YELLOW}Suspicious: {stats.get('suspicious', 0)}{RESET}")
        print(f"{GREEN}Harmless: {stats.get('harmless', 0)}{RESET}")
        print(f"{CYAN}Undetected: {stats.get('undetected', 0)}{RESET}")
        print(f"{MAGENTA}Timeout: {stats.get('timeout', 0)}{RESET}")
        print(f"Total Analysed Vendors: {sum(stats.values())}")

        last_analysis = attributes.get("last_analysis_date")
        print(f"Last Analysis Date: {format_date(last_analysis)}")

        # Security vendor results
        vendor_results = attributes.get("last_analysis_results", {})

        print(f"\n{CYAN}===== SECURITY VENDOR RESULTS ====={RESET}")

        if vendor_results:
            categories_to_show = [
                ("malicious", RED),
                ("suspicious", YELLOW),
                ("harmless", GREEN),
                ("undetected", CYAN),
                ("timeout", MAGENTA),
                ("other", RESET)
            ]

            for category, color in categories_to_show:
                matching_vendors = [
                    (vendor, result)
                    for vendor, result in vendor_results.items()
                    if result.get("category") == category
                ]

                if matching_vendors:
                    print(f"\n{color}--- {category.upper()} ---{RESET}")

                    for vendor, result in matching_vendors:
                        detection = result.get("result") or "No detection"
                        method = result.get("method", "N/A")

                        print(
                            f"{color}{vendor}: {detection} "
                            f"(Method: {method}){RESET}"
                        )
        else:
            print("No vendor results available.")

        # Associated domains
        print(f"\n{CYAN}--- ASSOCIATED DOMAINS ---{RESET}")

        try:
            domains_url = f"{BASE_URL}/ip_addresses/{ip_address}/resolutions"
            domains_response = requests.get(
                domains_url,
                headers=HEADERS,
                params={"limit": 10},
                timeout=30
            )
            domains_response.raise_for_status()

            domains = domains_response.json().get("data", [])

            if domains:
                for item in domains:
                    hostname = item.get("attributes", {}).get(
                        "host_name", "N/A"
                    )
                    print(hostname)
            else:
                print("No associated domains available.")

        except requests.RequestException:
            print("Could not retrieve associated domains.")

    except requests.HTTPError as error:
        status = error.response.status_code if error.response is not None else None

        if status == 401:
            print(f"{RED}Invalid or unauthorized API key.{RESET}")
        elif status == 403:
            print(f"{RED}VirusTotal access forbidden.{RESET}")
        elif status == 404:
            print(f"{RED}IP address report not found.{RESET}")
        elif status == 429:
            print(f"{YELLOW}VirusTotal rate limit exceeded. Try again later.{RESET}")
        elif status and status >= 500:
            print(f"{RED}VirusTotal server error ({status}). Try again later.{RESET}")
        else:
            print(f"{RED}IP lookup failed: {error}{RESET}")

    except requests.RequestException as error:
        print(f"{RED}Network error during IP lookup: {error}{RESET}")

    except (KeyError, ValueError) as error:
        print(f"{RED}Error processing IP report: {error}{RESET}")



def check_domain():
    """Retrieve complete domain security information."""

    domain = input("Enter domain: ").strip().lower()

    if not domain:
        print(f"{RED}Domain cannot be empty.{RESET}")
        return

    # Remove optional trailing dot
    if domain.endswith("."):
        domain = domain[:-1]

    # Convert international domain names to ASCII
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        print(f"{RED}Invalid domain name.{RESET}")
        return

    # Reject valid IP addresses
    try:
        ipaddress.ip_address(domain)
        print(f"{RED}Invalid domain. Enter a domain name, not an IP address.{RESET}")
        return
    except ValueError:
        pass

    # Reject invalid IPv4-like addresses
    if len(domain.split(".")) == 4 and all(
        label.isdigit() for label in domain.split(".")
    ):
        print(f"{RED}Invalid domain name. Enter a valid domain.{RESET}")
        return

    # Validate domain length and labels
    labels = domain.split(".")

    if (
        len(domain) > 253
        or len(labels) < 2
        or any(
            not label
            or len(label) > 63
            or not label[0].isalnum()
            or not label[-1].isalnum()
            or any(
                not (character.isalnum() or character == "-")
                for character in label
            )
            for label in labels
        )
    ):
        print(f"{RED}Invalid domain name. Enter a valid domain.{RESET}")
        return

    url = f"{BASE_URL}/domains/{domain}"

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=30
        )

        response.raise_for_status()

        data = response.json()["data"]
        attributes = data.get("attributes", {})

        print(f"\n{CYAN}===== DOMAIN SECURITY REPORT ====={RESET}")

        # Domain information
        print(f"\n{CYAN}--- DOMAIN INFORMATION ---{RESET}")
        print(f"Domain: {domain}")
        print(f"Reputation: {attributes.get('reputation', 'N/A')}")
        print(f"Registrar: {attributes.get('registrar', 'N/A')}")

        creation_date = attributes.get("creation_date")
        print(f"Creation Date: {format_date(creation_date)}")

        # Security statistics
        stats = attributes.get("last_analysis_stats", {})

        print(f"\n{CYAN}--- SECURITY STATISTICS ---{RESET}")
        print(f"{RED}Malicious: {stats.get('malicious', 0)}{RESET}")
        print(f"{YELLOW}Suspicious: {stats.get('suspicious', 0)}{RESET}")
        print(f"{GREEN}Harmless: {stats.get('harmless', 0)}{RESET}")
        print(f"{CYAN}Undetected: {stats.get('undetected', 0)}{RESET}")
        print(f"{MAGENTA}Timeout: {stats.get('timeout', 0)}{RESET}")
        print(f"Total Analysed Vendors: {sum(stats.values())}")

        last_analysis = attributes.get("last_analysis_date")
        print(f"Last Analysis Date: {format_date(last_analysis)}")

        # Domain categories
        categories = attributes.get("categories", {})

        print(f"\n{CYAN}--- DOMAIN CATEGORIES ---{RESET}")

        if categories:
            for vendor, category in categories.items():
                print(f"{vendor}: {category}")
        else:
            print("No category information available.")

        # DNS records
        dns_records = attributes.get("last_dns_records", [])

        print(f"\n{CYAN}--- DNS RECORDS ---{RESET}")

        if dns_records:
            for record in dns_records:
                record_type = record.get("type", "N/A")
                value = record.get("value", "N/A")
                ttl = record.get("ttl", "N/A")

                if record_type == "A":
                    color = GREEN
                elif record_type == "MX":
                    color = YELLOW
                elif record_type == "NS":
                    color = CYAN
                elif record_type == "TXT":
                    color = MAGENTA
                else:
                    color = RESET

                print(
                    f"{color}Type: {record_type} | "
                    f"Value: {value} | TTL: {ttl}{RESET}"
                )
        else:
            print("No DNS records available.")

        # Security vendor results
        vendor_results = attributes.get("last_analysis_results", {})

        print(f"\n{CYAN}===== SECURITY VENDOR RESULTS ====={RESET}")

        if vendor_results:
            categories_to_show = [
                ("malicious", RED),
                ("suspicious", YELLOW),
                ("harmless", GREEN),
                ("undetected", CYAN),
                ("timeout", MAGENTA),
                ("other", RESET)
            ]

            for category, color in categories_to_show:
                matching_vendors = [
                    (vendor, result)
                    for vendor, result in vendor_results.items()
                    if result.get("category") == category
                ]

                if matching_vendors:
                    print(f"\n{color}--- {category.upper()} ---{RESET}")

                    for vendor, result in matching_vendors:
                        detection = result.get("result") or "No detection"
                        method = result.get("method", "N/A")

                        print(
                            f"{color}{vendor}: {detection} "
                            f"(Method: {method}){RESET}"
                        )
        else:
            print("No vendor results available.")

    except requests.HTTPError as error:
        status = error.response.status_code if error.response is not None else None

        if status == 401:
            print(f"{RED}Invalid or unauthorized API key.{RESET}")
        elif status == 403:
            print(f"{RED}VirusTotal access forbidden.{RESET}")
        elif status == 404:
            print(f"{RED}Domain report not found.{RESET}")
        elif status == 429:
            print(f"{YELLOW}VirusTotal rate limit exceeded. Try again later.{RESET}")
        elif status and status >= 500:
            print(f"{RED}VirusTotal server error ({status}). Try again later.{RESET}")
        else:
            print(f"{RED}Domain lookup failed: {error}{RESET}")

    except requests.RequestException as error:
        print(f"{RED}Network error during domain lookup: {error}{RESET}")

    except (KeyError, ValueError) as error:
        print(f"{RED}Error processing domain report: {error}{RESET}")



def main():
    """Display the scanner menu and handle user choices."""

    if not API_KEY:
        print(f"{RED}VirusTotal API key not found.{RESET}")
        print("Set the VT_API_KEY environment variable first.")
        return

    while True:
        print(f"\n{CYAN}===== VIRUSTOTAL SCANNER ====={RESET}")
        print("1. Scan a file")
        print("2. Scan a URL")
        print("3. Check an IP address")
        print("4. Check a domain")
        print("5. Exit")

        choice = input("\nChoose an option: ").strip()

        if choice == "1":
            scan_file()

        elif choice == "2":
            scan_url()

        elif choice == "3":
            check_ip()

        elif choice == "4":
            check_domain()

        elif choice == "5":
            print(f"{GREEN}Exiting VirusTotal Scanner. Goodbye!{RESET}")
            break

        else:
            print(f"{RED}Invalid choice. Try again.{RESET}")

if __name__ == "__main__":
    main()
