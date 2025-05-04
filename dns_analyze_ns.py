#!/usr/bin/env python3

import dns.resolver
import argparse
import logging
import sys

def get_parent_zone(domain):
    """
    Calculates the parent zone of a given domain.

    Args:
        domain (str): The domain to calculate the parent zone for.

    Returns:
        str: The parent zone, or None if the domain is a top-level domain.
    """
    parts = domain.split('.')
    if len(parts) > 1:
        return '.'.join(parts[1:])
    else:
        return None

def get_nameservers(zone):
    """
    Retrieves the nameservers for a given DNS zone.

    Args:
        zone (str): The DNS zone to query.

    Returns:
        list: A list of nameserver hostnames, or None on error.
    """
    try:
        resolver = dns.resolver.Resolver()
        nameservers = resolver.resolve(zone, 'NS')
        return [str(ns.target) for ns in nameservers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
        logging.error(f"Error querying NS records for {zone}: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error querying NS records for {zone}: {e}")
        return None

def query_domain_ns(domain, nameservers):
    """
    Queries the NS records for a domain at the given nameservers.

    Args:
        domain (str): The domain to query.
        nameservers (list): A list of nameserver hostnames to query.

    Returns:
        list: A list of NS record hostnames, or None on error.
    """
    ns_records = []
    for ns in nameservers:
        resolver = dns.resolver.Resolver()
        try:
            answers = resolver.resolve(domain, 'NS')
            for rdata in answers:
                ns_records.append(str(rdata.target))
        except dns.resolver.NXDOMAIN as e:
            logging.warning(f"Domain {domain} does not exist: {e}")
            return []
        except dns.resolver.NoAnswer:
            try:
                # Look for NS records in the AUTHORITY section
                answers = resolver.resolve(domain, 'NS')
                for rdata in answers.authority: #changed from .answer to .authority
                    if rdata.type == dns.rdatatype.NS:
                        ns_records.append(str(rdata.target))
            except Exception as e:
                logging.warning(f"No NS records found in AUTHORITY section for {domain} at {ns}: {e}")
        except dns.exception.Timeout as e:
            logging.warning(f"Timeout querying NS records for {domain} at {ns}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error querying NS records for {domain} at {ns}: {e}")
            return None
    return ns_records



def analyze_ns_records(domain_ns_records, search_strings):
    """
    Analyzes the NS records of a domain against a list of search strings.

    Args:
        domain_ns_records (list): A list of NS record hostnames.
        search_strings (list): A list of strings to search for.

    Returns:
        dict: A dictionary where keys are the matching search strings,
              and values are the NS records that matched.
              Returns an empty dict if no matches are found.
    """
    matches = {}
    for ns_record in domain_ns_records:
        for search_string in search_strings:
            if search_string.lower() in ns_record.lower():
                if search_string not in matches:
                    matches[search_string] = []
                matches[search_string].append(ns_record)
    return matches

def main():
    """
    Main function to parse arguments, read domains, perform DNS queries,
    and output the analysis results.
    """
    parser = argparse.ArgumentParser(description="Analyze NS records of domains.")
    parser.add_argument("domain_file", help="File containing a list of domains.")
    parser.add_argument("search_string", nargs='+',help="String(s) to search for in NS records.")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity.") # added verbose
    args = parser.parse_args()

    # Configure logging
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
    elif args.verbose: # added verbose
        logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s")

    domain_file = args.domain_file
    search_strings = [s.lower() for s in args.search_string] # lowercase search

    parent_zones = {}
    domains = []

    # 1. Read domains from the input file
    try:
        with open(domain_file, 'r') as f:
            for line in f:
                domain = line.strip()
                if domain:  # Skip empty lines
                    domains.append(domain)
    except FileNotFoundError:
        logging.critical(f"Error: Domain file not found: {domain_file}")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"Error reading domain file: {e}")
        sys.exit(1)

    # 2. Calculate parent zones and store them in a dictionary
    for domain in domains:
        parent_zone = get_parent_zone(domain)
        if parent_zone:
            if parent_zone not in parent_zones:
                parent_zones[parent_zone] = None  # Initialize with None

    # 3. Get nameservers for parent zones
    for zone in parent_zones:
        nameservers = get_nameservers(zone)
        parent_zones[zone] = nameservers  # Store the list of nameservers
        if nameservers:
            logging.info(f"Found nameservers for {zone}: {nameservers}")
        else:
            logging.warning(f"No nameservers found for {zone}")

    # 4. Analyze NS records for each domain
    for domain in domains:
        logging.info(f"Analyzing domain: {domain}")
        matched_ns_records_count = 0
        matched_strings = {}
        parent_zones_to_query = []

        # Collect nameservers to query for this domain
        parent_zone = get_parent_zone(domain)
        if parent_zone and parent_zones[parent_zone]:
            parent_zones_to_query = parent_zones[parent_zone][:4] # Limit to 4
        
        if not parent_zones_to_query:
            logging.warning(f"No nameservers available to query for {domain}")
            print(f"Domain: {domain}")
            print(f"  Matched NS records: 0")
            print(f"  Matching strings: None")
            continue
            
        domain_ns_records = query_domain_ns(domain, parent_zones_to_query)
        if domain_ns_records is None:
            logging.error(f"Failed to retrieve NS records for {domain}")
            continue  # Move to the next domain
            
        if not domain_ns_records:
            logging.warning(f"No NS records found for domain: {domain}")

        matches = analyze_ns_records(domain_ns_records, search_strings)
        matched_ns_records_count = len(matches)
        matched_strings = matches
        
        print(f"Domain: {domain}")
        print(f"  Matched NS records: {matched_ns_records_count}")
        if matched_strings:
            print(f"  Matching strings:")
            for string, records in matched_strings.items():
                print(f"    {string}: {records}")
        else:
            print(f"  Matching strings: None")

        if args.debug and not matched_strings:
            print(f"  Queried nameservers: {parent_zones_to_query}")
            print(f"  NS records: {domain_ns_records}")

if __name__ == "__main__":
    main()

