import sys
import socket
import concurrent.futures
from typing import Dict, Union, List, Tuple
import dns.resolver
import argparse
import logging


class BoldFormatter(logging.Formatter):
    def format(self, record):
        message = super().format(record)
        if record.levelno >= logging.WARNING:
            return f"\033[1m{message}\033[0m"
        return message


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setFormatter(BoldFormatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(console_handler)

DNSBL_LIST = [
    'virus.rbl.jp', 'all.s5h.net', 'bl.spamcop.net',
    'combined.abuse.ch', 'dnsbl-2.uceprotect.net',
    'drone.abuse.ch', 'ips.backscatterer.org',
    'noptr.spamrats.com', 'psbl.surriel.com',
    'relays.nether.net', 'spam.dnsbl.anonmails.de',
    'spamrbl.imp.ch', 'ubl.unsubscore.com',
    'z.mailspike.net', 'b.barracudacentral.org',
    'blacklist.woody.ch', 'db.wpbl.info',
    'dnsbl-3.uceprotect.net', 'duinv.aupads.org',
    'ix.dnsbl.manitu.net', 'orvedb.aupads.org',
    'rbl.0spam.org', 'singular.ttk.pte.hu',
    'spam.spamrats.com', 'spamsources.fabel.dk',
    'virus.rbl.jp', 'bl.0spam.org',
    'bogons.cymru.com', 'dnsbl-1.uceprotect.net',
    'dnsbl.dronebl.org', 'dyna.spamrats.com',
    'korea.services.net', 'proxy.bl.gweep.ca',
    'relays.bl.gweep.ca', 'spam.abuse.ch',
    'spambot.bls.digibase.ca', 'ubl.lashback.com',
    'wormrbl.imp.ch'
]


def reverse_ip(ip: str) -> str:
    return '.'.join(reversed(ip.split('.')))


def get_ip_from_domain(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as e:
        logger.error(f"Could not resolve IP address for domain {domain}: {e}")
        sys.exit(1)


def check_single_dnsbl(ip: str, dnsbl: str) -> Tuple[str, Union[bool, str]]:
    reversed_ip = reverse_ip(ip)
    query = f"{reversed_ip}.{dnsbl}"
    try:
        dns.resolver.resolve(query, 'A')
        return dnsbl, True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return dnsbl, False
    except Exception as e:
        return dnsbl, f"Error: {str(e)}"


def check_ip_in_dnsbl(ip: str) -> Dict[str, Union[bool, str]]:
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(check_single_dnsbl, ip, dnsbl) for dnsbl in DNSBL_LIST]
        results = dict(future.result() for future in concurrent.futures.as_completed(futures))
    return results


def print_results(ip: str, results: Dict[str, Union[bool, str]]) -> None:
    blocked: List[str] = []
    not_blocked: List[str] = []
    errors: List[str] = []

    for dnsbl, is_listed in results.items():
        if isinstance(is_listed, bool):
            if is_listed:
                blocked.append(f"IP address {ip} is blocked in list {dnsbl}")
            else:
                not_blocked.append(f"IP address {ip} is not blocked in list {dnsbl}")
        else:
            errors.append(f"IP address {ip} - {is_listed}")

    logger.info(f"Results for IP: \033[1m{ip}\033[0m")
    logger.info(f"Blocked in \033[1m{len(blocked)}\033[0m lists")
    logger.info(f"Not blocked in \033[1m{len(not_blocked)}\033[0m lists")
    logger.info(f"Errors in \033[1m{len(errors)}\033[0m lists")

    if blocked:
        logger.warning("\033[1m⚠ Blocked lists:\033[0m")
        for message in blocked:
            logger.warning(message)
    if not_blocked:
        logger.info("\033[1m✓ Not blocked lists:\033[0m")
        for message in not_blocked:
            logger.info(message)
    if errors:
        logger.error("\033[1m⚠ Errors:\033[0m")
        for message in errors:
            logger.error(message)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check if an IP or domain is listed in various DNSBLs.")
    parser.add_argument("target", help="Domain or IP address to check")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    target = args.target

    try:
        socket.inet_aton(target)
        ip = target
    except socket.error:
        logger.info(f"Resolving IP address for domain: \033[1m{target}\033[0m")
        ip = get_ip_from_domain(target)

    logger.info(f"Checking IP: \033[1m{ip}\033[0m")
    results = check_ip_in_dnsbl(ip)
    print_results(ip, results)


if __name__ == "__main__":
    main()
