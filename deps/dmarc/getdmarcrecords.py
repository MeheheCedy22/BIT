#!/usr/bin/python

import sys
import os
import optparse
import subprocess
import re


## Get Options
parser = optparse.OptionParser()
parser.add_option('-i',
  dest="infile",
  default=False,
  help='a file containing a list of domains'
  )
parser.add_option('-o',
  dest="outfile",
  default=False,
  help='(OPTIONAL) an output file name'
  )
description = """

Query and parse DMARC, SPF, and DKIM records for a list of domains. Input a list
of domains with the '-i' option. To output results to a CSV file,
define an output file name with the '-o' option.

Example:
python getdmarcrecords.py -i domains.txt -o DMARCRecords.csv"""
usagetxt = """Usage: python getdmarcrecords.py -i <infile> -o <outfile>"""
parser.set_usage(usagetxt + description)
options, remainder = parser.parse_args()

infile = options.infile
outfile = options.outfile


# make sure an input file was provided
if infile:
  # make sure input file exists
  if not os.path.isfile(infile):
    print('[!] Input file does not exist')
    print(usagetxt)
    sys.exit()
else:
  print('[!] Please specify an input file')
  print(usagetxt)
  sys.exit()


def find_between(s, first, last):
  try:
    start = s.index(first) + len(first)
    end = s.index(last, start)
    return s[start:end]
  except ValueError:
    return ""


domains = []
invalid = []
dmarc = {}
spf = {}
dkim = {}


# populate list of domains from input file
with open(infile) as f:
  for line in f:
    domain = line.strip()
    # strip off any url protocol info
    if '://' in domain:
      domain = domain.split('://',1)[1]
    # strip off any extra url data
    if '/' in domain:
      domain = domain.split('/',1)[0]
    # make sure domain contains only alphanumeric characters
    if re.match('^[\\w.-]+$', domain):
      if '.' in domain:
        # strip out subdomains ('some.thing.example.com' -> 'example.com')
        domain = '.'.join(domain.split('.')[-2:])
        domains.append(domain)
      else:
        # line in file is not a valid domain
        invalid.append(domain)
    else:
      invalid.append(domain)

totaldomains = len(domains)
# remove duplicates
domains = list(set(domains))
duplicates = totaldomains - len(domains)

if invalid:
  print("[!] WARNING input file contains %s errors" % len(invalid))
if duplicates:
  print("[!] WARNING omitting %s duplicate domain(s)" % duplicates)
print("[-] pulling DMARC, SPF, and DKIM records for %s domains..." % len(domains))
for domain in domains:
  # DMARC Records
  cmd = "dig TXT _dmarc.%s" % domain
  raw_response = subprocess.check_output(cmd, shell=True).decode("utf-8", errors="ignore")
  fullrecord = ""
  if ";; ANSWER SECTION:" in raw_response:
    answer_section = find_between(raw_response, ";; ANSWER SECTION:", ";;")
    for line in answer_section.split('\n'):
      if 'TXT' in line and '"' in line:
        parts = line.split('"')
        for i in range(1, len(parts), 2):
          fullrecord += parts[i]
        if fullrecord:
          break
  if fullrecord and not fullrecord.endswith(';'):
    fullrecord += ";"

  v = find_between(fullrecord, "v=", ";")
  p = find_between(fullrecord, "p=", ";")
  sp = find_between(fullrecord, "sp=", ";")
  rua = find_between(fullrecord, "rua=", ";")
  ruf = find_between(fullrecord, "ruf=", ";")
  pct = find_between(fullrecord, "pct=", ";")
  adkim = find_between(fullrecord, "adkim=", ";")
  aspf = find_between(fullrecord, "aspf=", ";")

  dmarc[domain] = [v, p, sp, rua, ruf, pct, adkim, aspf, fullrecord[:-1]]

  # SPF Records
  cmd_spf = "dig TXT %s" % domain
  raw_response_spf = subprocess.check_output(cmd_spf, shell=True).decode("utf-8", errors="ignore")
  spf_record = ""
  if ";; ANSWER SECTION:" in raw_response_spf:
    answer_section = find_between(raw_response_spf, ";; ANSWER SECTION:", ";;")
    # Look for SPF record (starts with "v=spf1")
    for line in answer_section.split('\n'):
      if '"v=spf1' in line or '"v=SPF1' in line:
        # Extract text between quotes
        parts = line.split('"')
        if len(parts) >= 2:
          spf_record = parts[1]
          break
  spf[domain] = spf_record

  # DKIM Records (checking common selectors)
  dkim_selectors = ['default', 'selector1', 'selector2', 'google', 'k1', 's1', 's2', 'dkim']
  dkim_records = []
  for selector in dkim_selectors:
    cmd_dkim = "dig TXT %s._domainkey.%s" % (selector, domain)
    try:
      raw_response_dkim = subprocess.check_output(cmd_dkim, shell=True).decode("utf-8", errors="ignore")
      if ";; ANSWER SECTION:" in raw_response_dkim:
        answer_section = find_between(raw_response_dkim, ";; ANSWER SECTION:", ";;")
        if answer_section and '"' in answer_section:
          dkim_text = find_between(answer_section, '"', '"')
          if dkim_text and ('v=DKIM1' in dkim_text or 'k=' in dkim_text or 'p=' in dkim_text):
            dkim_records.append(f"{selector}: {dkim_text}")
    except:
      pass
  dkim[domain] = ' | '.join(dkim_records) if dkim_records else ""

if outfile:
# if output file is specified, send output to that file (in CSV format)
  delim = '","'
  try:
    with open(outfile, 'w') as f:
      f.write('"' + delim.join(["Domain", "v", "p", "sp", "rua", "ruf", "pct", "adkim", "aspf", "Raw DMARC", "SPF", "DKIM"]) + '"\n')
      for domain in dmarc:
        f.write('"' + domain + delim + delim.join(dmarc[domain]) + delim + spf.get(domain, '') + delim + dkim.get(domain, '') + '"\n')
    print("[+] results saved to '%s'" % outfile)
  except:
    print("[!] Error writing to output file '%s'\n\n" % outfile)
    raise
    sys.exit()
else:
# if no output file is specified, output to the terminal
  for domain in dmarc:
    print("\n\nDomain: %s\n" % domain)
    if dmarc[domain][8]:
      print("Raw DMARC record:\n%s\n" % dmarc[domain][8])
      print("DMARC Tags:")
      print("v:     %s" % dmarc[domain][0])
      print("p:     %s" % dmarc[domain][1])
      print("sp:    %s" % dmarc[domain][2])
      print("rua:   %s" % dmarc[domain][3])
      print("ruf:   %s" % dmarc[domain][4])
      print("pct:   %s" % dmarc[domain][5])
      print("adkim: %s" % dmarc[domain][6])
      print("aspf:  %s" % dmarc[domain][7])
    else:
      print("DMARC record not found")
    
    print("\nSPF Record:")
    if spf.get(domain):
      print(spf[domain])
    else:
      print("SPF record not found")
    
    print("\nDKIM Records:")
    if dkim.get(domain):
      print(dkim[domain])
    else:
      print("DKIM records not found (checked common selectors)")