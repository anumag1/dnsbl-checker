# DNSBL Checker

This Python script checks if a given domain or IP address is listed in various DNS Blacklists (DNSBL). DNSBLs are commonly used to identify sources of spam, malware, and other malicious behavior.

## Features
- Checks a given IP address or domain against a predefined list of DNS Blacklists.
- Uses multithreading to speed up the blacklist checking process.
- Logs detailed results for each DNSBL, including whether the IP is blocked, not blocked, or if there were any errors.
- Supports verbose logging for more detailed output.

## Requirements
- Python 3.6+
- The following Python libraries:
  - `dnspython`
  - `argparse`
  - `concurrent.futures`
  - `socket`

To install the required packages, run:

```
pip install dnspython
```

## Usage

To run the script, use the following command:

```
python dnsblcheck.py <target> [options]
```

### Parameters:
- `<target>`: The domain name or IP address to check.
- `-v`, `--verbose`: Optional flag to increase output verbosity for debugging purposes.

### Example:

```
python dnsblcheck.py example.com
```

This command will:
1. Resolve the domain `example.com` to an IP address.
2. Check the resolved IP against multiple DNS Blacklists.
3. Display the results in the console.

To check an IP address directly:

```
python dnsblcheck.py 192.0.2.1
```

### Verbose Output:

To see more detailed logs, use the `-v` option:

```
python dnsblcheck.py example.com -v
```

## Logging

The script uses Python's `logging` module to display results in the terminal. Important messages, like errors and blocked IPs, are displayed in **bold** to increase visibility. The logging levels include:
- INFO: Standard log output.
- WARNING: Indicates blocked IPs.
- ERROR: Displays any errors encountered during DNSBL checks.

## DNSBL List

The script uses a predefined list of DNSBLs, which includes services such as:
- `bl.spamcop.net`
- `dnsbl.sorbs.net`
- `psbl.surriel.com`
- ... and many more.

You can modify the `DNSBL_LIST` variable in the script to add or remove blacklists as needed.
