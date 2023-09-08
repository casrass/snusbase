import json
import requests
import argparse
import os

snusbase_auth = os.environ.get('SNUSBASE_AUTH')
if not snusbase_auth:
        raise ValueError("SNUSBASE_AUTH environment variable is not set")

snusbase_api = 'https://api-experimental.snusbase.com/'

def send_request(url, body=None):
    headers = {
        'Auth': snusbase_auth,
        'Content-Type': 'application/json',
    }
    method = 'POST' if body else 'GET'
    data = json.dumps(body) if body else None
    response = requests.request(method, snusbase_api + url, headers=headers, data=data)
    return response.json()

def search_snusbase(terms, types, wildcard):
    search_response = send_request('data/search', {
        'terms': terms,
        'types': types,
        'wildcard': wildcard,
    })
    return search_response

def get_snusbase_stats():
    stats_response = send_request('data/stats')
    return stats_response

def get_ip_whois(terms):
    ip_whois_response = send_request('tools/ip-whois', {
        'terms': terms,
    })
    return ip_whois_response

def hash_lookup(terms, types):
    hash_lookup_response = send_request('tools/hash-lookup', {
        'terms': terms,
        'types': types,
    })
    return hash_lookup_response

def main():
    parser = argparse.ArgumentParser(description="Snusbase API Command Line Tool")
    parser.add_argument("--search", nargs="+", help="Search Snusbase for terms")
    parser.add_argument("--types", nargs="+", default=["email"], help="Types to search for (e.g., email, username)")
    parser.add_argument("--wildcard", action="store_true", help="Enable wildcard search")
    parser.add_argument("--stats", action="store_true", help="Get Snusbase statistics")
    parser.add_argument("--ip", nargs="+", help="Get IP Whois information for an IP address")
    parser.add_argument("--hash", nargs="+", help="Lookup a hash")
    args = parser.parse_args()
 
    if args.search:
        search_response = search_snusbase(args.search, args.types, args.wildcard)
        print(json.dumps(search_response, indent=4))

    if args.stats:
        stats_response = get_snusbase_stats()
        print(json.dumps(stats_response, indent=4))


    if args.ip_whois:
        ip_whois_response = get_ip_whois(args.ip_whois)
        print(json.dumps(ip_whois_response, indent=4))

    if args.hash_lookup:
        hash_lookup_response = hash_lookup(args.hash_lookup, ["hash"])
        print(json.dumps(hash_lookup_response, indent=4))


if __name__ == "__main__":
    main()
