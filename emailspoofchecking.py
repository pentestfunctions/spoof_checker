#!/usr/bin/env python3
"""
Subdomain Email Authentication Scanner
Fetches subdomains from Web Archive and checks their email authentication records.
"""

import sys
import re
import concurrent.futures
import requests
import dns.resolver
import argparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

# Initialize Rich console for colored output
console = Console()

def fetch_subdomains(domain):
    """Fetch subdomains from Web Archive."""
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey"
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        if not response.text.strip():
            console.print(f"[yellow]No subdomains found for {domain}[/yellow]")
            return []

        # Extract domain patterns from URLs
        urls = response.text.splitlines()
        subdomains = set()

        # Regular expression pattern to match subdomains
        pattern = re.compile(r'https?://([^:/]*\.' + re.escape(domain) + ')')

        # First item in JSON output is headers, skip it if it's JSON
        start_idx = 1 if urls and urls[0].startswith('[') else 0

        for url in urls[start_idx:]:
            url = url.strip('"[] ')
            match = pattern.search(url)
            if match:
                subdomains.add(match.group(1))

        # Always include the base domain
        subdomains.add(domain)

        return sorted(list(subdomains))
    except requests.RequestException as e:
        console.print(f"[red]Error fetching subdomains: {e}[/red]")
        return [domain]  # Return at least the base domain

def check_dns_record(domain, record_type, prefix=""):
    """Check if a DNS record exists."""
    try:
        query_domain = f"{prefix}.{domain}" if prefix else domain
        answers = dns.resolver.resolve(query_domain, record_type)
        return [str(answer) for answer in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except Exception as e:
        return [f"Error: {str(e)}"]

def check_email_auth(subdomain):
    """Check email authentication records for a subdomain."""
    results = {
        "domain": subdomain,
        "exists": True,
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "mx_records": None,
        "spoofable": False,
        "vulnerable": False
    }

    # Check if domain exists (has any DNS records)
    try:
        dns.resolver.resolve(subdomain, 'A')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        try:
            dns.resolver.resolve(subdomain, 'MX')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            results["exists"] = False
            return results

    # Check SPF
    txt_records = check_dns_record(subdomain, 'TXT')
    for record in txt_records:
        if "v=spf1" in record.lower():
            results["spf"] = record
            break

    # Check DKIM (default selector)
    dkim_records = check_dns_record(subdomain, 'TXT', "default._domainkey")
    if dkim_records:
        for record in dkim_records:
            if "v=dkim1" in record.lower():
                results["dkim"] = record
                break
        if not results["dkim"] and dkim_records:
            results["dkim"] = dkim_records[0]  # If no clear DKIM marker but records exist

    # Check DMARC
    dmarc_records = check_dns_record(subdomain, 'TXT', "_dmarc")
    for record in dmarc_records:
        if "v=dmarc1" in record.lower():
            results["dmarc"] = record
            break

    # Check MX records
    mx_records = []
    try:
        answers = dns.resolver.resolve(subdomain, 'MX')
        for rdata in answers:
            mx_records.append(str(rdata.exchange))
        results["mx_records"] = mx_records
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        results["mx_records"] = []

    # Determine risk levels
    # High risk: Missing SPF or DMARC with MX records (practically spoofable)
    # Moderate risk: Has SPF+DMARC but missing DKIM with MX records
    # Low risk/Protected: Has all authentication protocols or no MX records

    results["risk_level"] = "protected"

    if results["mx_records"]:
        if not results["spf"] or not results["dmarc"]:
            results["vulnerable"] = True
            results["risk_level"] = "high"

            # Consider it practically spoofable if it has MX records but no SPF
            if not results["spf"]:
                results["spoofable"] = True
        elif not results["dkim"]:
            results["risk_level"] = "moderate"

    return results

def scan_domain(domain, recipient="myemail@gmail.com"):
    """Complete scan workflow for a domain."""
    with console.status(f"[bold blue]Fetching subdomains for {domain}...[/bold blue]"):
        subdomains = fetch_subdomains(domain)

    console.print(f"[bold]Found {len(subdomains)} subdomains for {domain}[/bold]")

    results = []
    with console.status(f"[bold blue]Checking email authentication records for {len(subdomains)} domains...[/bold blue]"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(check_email_auth, subdomains))

    # Create a table for results
    table = Table(title=f"Email Authentication Results for {domain}", box=box.ROUNDED)
    table.add_column("Subdomain", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("SPF", style="green")
    table.add_column("DKIM", style="blue")
    table.add_column("DMARC", style="magenta")
    table.add_column("MX Records", style="yellow")

    vulnerable_domains = []
    spoofable_domains = []
    moderate_risk_domains = []

    for result in results:
        subdomain = result["domain"]

        if not result["exists"]:
            status = "❌ [red]Not Active[/red]"
            table.add_row(
                subdomain,
                status,
                "N/A",
                "N/A",
                "N/A",
                "N/A"
            )
            continue

        # Format SPF
        spf_status = "✅" if result["spf"] else "❌ [red]Missing[/red]"
        spf_display = (result["spf"] or "").replace('"', '')
        if len(spf_display) > 40:
            spf_display = spf_display[:37] + "..."

        # Format DKIM
        dkim_status = "✅" if result["dkim"] else "❌ [red]Missing[/red]"
        dkim_display = "Found" if result["dkim"] else "Not Found"

        # Format DMARC
        dmarc_status = "✅" if result["dmarc"] else "❌ [red]Missing[/red]"
        dmarc_display = (result["dmarc"] or "").replace('"', '')
        if len(dmarc_display) > 40:
            dmarc_display = dmarc_display[:37] + "..."

        # Format MX
        mx_display = ", ".join(result["mx_records"][:2]) if result["mx_records"] else "None"
        if len(mx_display) > 20 and result["mx_records"]:
            mx_display = f"{result['mx_records'][0]}... ({len(result['mx_records'])} records)"

        # Overall status based on risk level
        if result["risk_level"] == "high":
            if result["spoofable"]:
                status = "🚨 [bold red]Spoofable[/bold red]"
                spoofable_domains.append(subdomain)
            else:
                status = "⚠️ [bold yellow]High Risk[/bold yellow]"
            vulnerable_domains.append(subdomain)
        elif result["risk_level"] == "moderate":
            status = "⚠️ [yellow]Moderate Risk[/yellow]"
            moderate_risk_domains.append(subdomain)
        else:
            status = "✅ [green]Protected[/green]"

        table.add_row(
            subdomain,
            status,
            f"{spf_status} {spf_display}",
            f"{dkim_status} {dkim_display}",
            f"{dmarc_status} {dmarc_display}",
            mx_display
        )

    console.print(table)

    # Print summary
    active_count = sum(1 for r in results if r["exists"])
    protected_count = sum(1 for r in results if r["exists"] and not r["vulnerable"])
    spoofable_count = sum(1 for r in results if r["exists"] and r["spoofable"])

    # Find high-risk domains (has MX records but missing SPF or DMARC)
    high_risk_domains = [r["domain"] for r in results if r["exists"] and
                        r["mx_records"] and
                        (not r["spf"] or not r["dmarc"])]
    high_risk_count = len(high_risk_domains)

    # Find moderate-risk domains (has SPF+DMARC but missing DKIM)
    moderate_risk_count = len(moderate_risk_domains)

    console.print(Panel(
        f"[bold]Summary:[/bold]\n"
        f"Total Subdomains: {len(results)}\n"
        f"Active Domains: {active_count}\n"
        f"Protected Domains: {protected_count}\n"
        f"Vulnerable Domains: {len(vulnerable_domains)}\n"
        f"[bold red]Practically Spoofable: {spoofable_count}[/bold red]\n"
        f"[bold red]HIGH RISK (Missing SPF/DMARC): {high_risk_count}[/bold red]\n"
        f"[yellow]MODERATE RISK (Missing DKIM): {moderate_risk_count}[/yellow]",
        title="Scan Results",
        border_style="blue"
    ))

    # Print high-risk domains first (most important for security)
    if high_risk_domains:
        console.print("[bold red]HIGH RISK DOMAINS (Missing SPF/DMARC):[/bold red]")

        for domain in high_risk_domains:
            domain_result = next((r for r in results if r["domain"] == domain), None)
            if not domain_result:
                continue

            vuln_types = []
            if not domain_result["spf"]:
                vuln_types.append("SPF")
            if not domain_result["dmarc"]:
                vuln_types.append("DMARC")

            vuln_type_str = " and ".join(vuln_types)
            mx_count = len(domain_result["mx_records"])
            console.print(f"  • {domain} - Missing {vuln_type_str} - Has {mx_count} MX Records")

            # Create spoofing command examples
            console.print(f"    [dim]Spoofing verification:[/dim]")
            console.print(f"    [dim cyan]host -t TXT {domain}[/dim cyan]")
            console.print(f"    [dim cyan]host -t TXT _dmarc.{domain}[/dim cyan]")
            console.print(f"    [dim cyan]host -t MX {domain}[/dim cyan]")

            console.print(f"    [dim]Spoofing example:[/dim]")

            if "SPF" in vuln_types:
                console.print(f"    [yellow]swaks --to {recipient} --from security@{domain} --server smtp.gmail.com:587 -tls --auth --auth-user your-gmail@gmail.com --header 'Subject: Important Security Alert' --body 'This is a spoofed email demonstration'[/yellow]")

    # Print moderate-risk domains second
    if moderate_risk_domains:
        console.print("\n[yellow]MODERATE RISK DOMAINS (Missing DKIM):[/yellow]")

        for domain in moderate_risk_domains:
            domain_result = next((r for r in results if r["domain"] == domain), None)
            if not domain_result:
                continue

            mx_count = len(domain_result["mx_records"])
            console.print(f"  • {domain} - Has SPF & DMARC but missing DKIM - Has {mx_count} MX Records")

            # Verification commands only
            console.print(f"    [dim]Verification commands:[/dim]")
            console.print(f"    [dim cyan]host -t TXT {domain}[/dim cyan]")
            console.print(f"    [dim cyan]host -t TXT default._domainkey.{domain}[/dim cyan]")
            console.print(f"    [dim cyan]host -t TXT _dmarc.{domain}[/dim cyan]")

    # Then show other spoofable domains
    if spoofable_domains:
        if high_risk_domains:
            console.print("\n[bold red]Other Spoofable Domains:[/bold red]")
        else:
            console.print("[bold red]Spoofable Domains (High Confidence):[/bold red]")

        # Find relevant vulnerability type and provide commands for spoofable domains
        for domain in spoofable_domains:
            # Skip if already listed in high-risk domains
            if domain in high_risk_domains:
                continue
            domain_result = next((r for r in results if r["domain"] == domain), None)
            if not domain_result:
                continue

            vuln_types = []
            if not domain_result["spf"]:
                vuln_types.append("SPF")
            if not domain_result["dmarc"]:
                vuln_types.append("DMARC")

            mx_status = "No MX Records" if not domain_result["mx_records"] else f"Has {len(domain_result['mx_records'])} MX Records"
            vuln_type_str = " and ".join(vuln_types)
            console.print(f"  • {domain} - Missing {vuln_type_str} - {mx_status}")

            # Create spoofing command examples
            console.print(f"    [dim]Spoofing verification:[/dim]")
            console.print(f"    [dim cyan]host -t TXT {domain}[/dim cyan]")
            console.print(f"    [dim cyan]host -t TXT _dmarc.{domain}[/dim cyan]")
            console.print(f"    [dim cyan]host -t MX {domain}[/dim cyan]")

            console.print(f"    [dim]Spoofing example:[/dim]")

            if "SPF" in vuln_types:
                console.print(f"    [yellow]swaks --to {recipient} --from security@{domain} --server smtp.gmail.com:587 -tls --auth --auth-user your-gmail@gmail.com --header 'Subject: Important Security Alert' --body 'This is a spoofed email demonstration'[/yellow]")

            if len(vuln_types) > 0:
                console.print(f"    [yellow]sendEmail -f security@{domain} -t {recipient} -u 'Security Notice' -m 'This domain lacks proper email authentication' -s smtp.gmail.com:587 -xu your-gmail@gmail.com -xp yourpassword[/yellow]")

    elif vulnerable_domains:
        console.print("[bold yellow]Potentially Vulnerable Domains:[/bold yellow]")

        # Find relevant vulnerability type for other vulnerable domains
        for domain in vulnerable_domains:
            if domain in spoofable_domains:
                continue  # Skip domains we already covered above

            domain_result = next((r for r in results if r["domain"] == domain), None)
            if not domain_result:
                continue

            vuln_types = []
            if not domain_result["spf"]:
                vuln_types.append("SPF")
            if not domain_result["dmarc"]:
                vuln_types.append("DMARC")

            vuln_type_str = " and ".join(vuln_types)
            mx_status = "Has MX Records" if domain_result["mx_records"] else "No MX Records"
            console.print(f"  • {domain} - Missing {vuln_type_str} - {mx_status}")

    # Print verification commands
    console.print("\n[bold blue]To Verify Any Domain:[/bold blue]")
    console.print("  host -t TXT domain.com")
    console.print("  host -t TXT _dmarc.domain.com")
    console.print("  host -t MX domain.com")

    console.print("\n[bold yellow]Recommendations:[/bold yellow]")
    console.print("  • [bold red]HIGH RISK:[/bold red] Implement both SPF and DMARC records immediately for these domains")
    console.print("  • [yellow]MODERATE RISK:[/yellow] Add DKIM authentication to complete your email security profile")
    console.print("  • For DKIM setup, consult your email provider's documentation or use a tool like OpenDKIM")

def main():
    parser = argparse.ArgumentParser(description="Email Authentication Scanner for Domains")
    parser.add_argument("domain", help="Domain to scan (e.g., example.com)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("-r", "--recipient", default="myemail@gmail.com", help="Email recipient for spoofing examples (default: myemail@gmail.com)")
    args = parser.parse_args()

    console.print(Panel(
        "[bold blue]Subdomain Email Authentication Scanner[/bold blue]\n"
        "Fetches subdomains and checks their email security configurations",
        border_style="blue"
    ))

    scan_domain(args.domain, args.recipient)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)
