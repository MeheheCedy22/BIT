

# Email Spoofing Tool

A Python-based educational tool that demonstrates email spoofing vulnerabilities by identifying domains without proper email authentication (DMARC, SPF, DKIM) and simulating spoofed email sending.

## Disclaimer

EN:

This tool is created **strictly for educational purposes** to demonstrate email security vulnerabilities. **DO NOT USE FOR MALICIOUS PURPOSES.** The author is not responsible for any misuse or damage caused by this tool.

SK:

Tento repozitár je vytvorený výhradne na vzdelávacie účely. Materiály tu uvedené sú určené na zlepšenie učenia a porozumenia konceptom informačnej bezpečnosti. Nie na škodlivé použitie. Autor nezodpovedá za zneužitie informácií uvedených v tomto repozitári.

## Project Structure

```
project/
├── email_tool.py               # Main application
├── requirements.txt            # Python dependencies
├── README.md                   # This file
└── deps/
    └── dmarc/
        └── getdmarcrecords.py  # DMARC checking script
    docs/
        ├── project.pdf         # Project documentation
        └── project.md          # ^^^^^^^^^^^^^^^^^^^^^
```

## Features

- **Domain Discovery**: Downloads and filters disposable email domains
- **Security Analysis**: Checks domains for DMARC, SPF, and DKIM records
- **Vulnerability Detection**: Identifies domains without email authentication
- **Email Simulation**: Demonstrates spoofed email sending using `swaks`
- **Interactive CLI**: User-friendly interface with rich formatting
- **Flexible Configuration**: Supports custom domains and extensions

## Prerequisites

### System Dependencies

Tested only on Kali Linux.

- `dig` (DNS lookup tool)
- `swaks` (Swiss Army Knife for SMTP)
- Python 3.13+ (probably works with older versions too, however not tested)

### Python Dependencies
- `typer` - CLI framework
- `requests` - HTTP library
- `rich` - Terminal formatting

## Installation

1. **Clone the repository**
```bash
git clone [<repository-url>](https://github.com/MeheheCedy22/BIT.git)
cd project
```

2. **Create virtual environment** (recommended)
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
```

3. **Install Python dependencies**
```bash
pip install -r requirements.txt
```

4. **Install system dependencies**

Debian/Ubuntu/Kali:
```bash
sudo apt update
sudo apt install -y dnsutils swaks
```

## Usage

For help run:
```bash
python3 email_tool.py --help
```

### Interactive Mode (Recommended)
```bash
python3 email_tool.py interactive
```

### Direct Send Mode
```bash
python3 email_tool.py send target@example.com \
  --domain vulnerable-domain.com \
  --sender-name "John Doe" \
  --subject "Test Email" \
  --body "Email content"
```

### Check Dependencies Only
```bash
python3 email_tool.py check
```

## How It Works

1. **Domain Collection**: Downloads list of disposable email domains
2. **Filtering**: Searches for domains with specific extensions (default: .sk, .cz)
3. **Security Analysis**: Uses [`getdmarcrecords.py`](project/deps/dmarc/getdmarcrecords.py) to check email authentication
4. **Vulnerability Detection**: Identifies domains lacking DMARC, SPF, and DKIM protection
5. **Email Simulation**: Uses `swaks` to demonstrate spoofed email sending



## Resources

- for resources check [project documentation](docs/project.md)