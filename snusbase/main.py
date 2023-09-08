import json
import requests
import argparse
import os

snusbase_auth = os.environ.get('SNUSBASE_AUTH')
if not snusbase_auth:
        raise ValueError("SNUSBASE_AUTH environment variable is not set")

snusbase_api = 'https://api-experimental.snusbase.com/'

# make it a little nicer
def pretty_print(data, raw=False, indent=0):
    error = data.get('errors')
    if error:
        print("errors:", error)
    else:
        results = data.get('results', {})
        if raw:
            print(json.dumps(results, indent=4))
        else:
            if isinstance(results, dict):
                for key, value in results.items():
                    print(" " * indent + str(key) + ":")
                    pretty_print(value, raw, indent + 2)
            elif isinstance(results, list):
                for item in results:
                    pretty_print(item, raw, indent + 2)
            else:
                print(" " * indent + str(results))

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
    parser.add_argument("--ip-whois", nargs="+", help="Get IP Whois information for an IP address")
    parser.add_argument("--hash-lookup", nargs="+", help="Lookup a hash")
    parser.add_argument("--raw", action="store_true", help="Print raw JSON data")
    args = parser.parse_args()
 
    if args.search:
        search_response = search_snusbase(args.search, args.types, args.wildcard)
        pretty_print(search_response, args.raw)

    if args.stats:
        stats_response = get_snusbase_stats()
        pretty_print(stats_response, args.raw)

    if args.ip_whois:
        ip_whois_response = get_ip_whois(args.ip_whois)
        pretty_print(ip_whois_response, args.raw)

    if args.hash_lookup:
        hash_lookup_response = hash_lookup(args.hash_lookup, ["hash"])
        pretty_print(hash_lookup_response, args.raw)

if __name__ == "__main__":
    main()
