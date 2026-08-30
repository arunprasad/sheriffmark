# Requires: pip install dnspython requests
import dns.message, dns.query, dns.resolver, dns.rcode
import requests, time
import os
from concurrent.futures import ProcessPoolExecutor, as_completed

#sed -e 's/^/a/' 4letters.txt > a-5-letters.txt

def rdap_head_check(domain, user_agent="MyChecker/1.0 (+mailto:ops@example.com)"):
    
    url = f"https://rdap.verisign.com/com/v1/domain/{domain}"
    #print(f"here {url}")
    try:
        r = requests.head(url, timeout=5)
        #print(f"status {r.status_code}")
        return r.status_code == 404  # 404 = unregistered, 200 = registered
    except Exception as e:
        print(e)
        return True
# example usage
TLD_NS = {}
def load_ns(tld):
    tld_ns = [str(rr.target) for rr in dns.resolver.resolve(tld+".", 'NS')]
    TLD_NS[tld] = TLD_NS.get(tld,[])
    for ns in tld_ns:
        try:
            ns_ip = dns.resolver.resolve(ns, 'A')[0].to_text()
            print (f"Got in {ns} {ns_ip}")
            TLD_NS[tld].append((ns,ns_ip))
        except Exception:
            continue

def domain_availability_v1(domain, tld, ns_tuple=None, ns_index=0):
    """Check domain using a single NS server (load distributed via ns_index)
    If ns_tuple is provided, use that NS directly (safer for multiprocessing)."""
    domain_tld = domain + "." + tld
    q = dns.message.make_query(domain_tld, dns.rdatatype.NS, want_dnssec=False)
    q.flags &= ~dns.flags.RD

    # If caller supplied a specific NS tuple, use it; otherwise fallback to global
    if ns_tuple is not None:
        ns, ns_ip = ns_tuple
    else:
        ns_servers = TLD_NS.get(tld, [])
        if not ns_servers:
            raise KeyError(tld)
        ns, ns_ip = ns_servers[ns_index % len(ns_servers)]

    try:
        resp = dns.query.udp(q, ns_ip, timeout=3)
        if resp.rcode() == dns.rcode.NXDOMAIN:
            return rdap_head_check(domain_tld)

        for rrset in resp.authority:
            if rrset.rdtype == dns.rdatatype.NS:
                return False
            if rrset.rdtype == dns.rdatatype.SOA:
                return rdap_head_check(domain_tld)
    except Exception:
        pass
    return None

def check_domain_worker(domain, tld, ns_tuple):
    """Wrapper for multiprocessing — ns_tuple is passed from parent so worker doesn't rely on globals"""
    try:
        available = domain_availability_v1(domain, tld, ns_tuple=ns_tuple)
        return domain, available
    except Exception as e:
        print(f"Error checking {domain}: {e}")
        return domain, None

# single test
#if __name__ == "__main__":
#    for d in ["this-should-not-exist-12345-example.com", "google.com"]:
#        print(domain_availability(d))
#        time.sleep(1)  # be courteous

SET_NAME = "a-5-letters"
TLD = "com"
INPUT_FILE = SET_NAME + ".txt"
OUTPUT_FILE = SET_NAME + "." + TLD + ".available.txt"
PROCESSED_FILE = SET_NAME + "." + TLD + ".checked.txt"

NSINDEX = 1

def load_processed():
    if not os.path.exists(PROCESSED_FILE):
        return set()
    with open(PROCESSED_FILE, "r") as f:
        return set(line.strip() for line in f if line.strip())

def append_to_file(filename, domain, processed_set=None):
    """Append domain to file and optionally update processed set."""
    with open(filename, "a") as f:
        f.write(domain + "\n")
    if processed_set is not None:
        processed_set.add(domain)

def main():
    load_ns("com")
    print(TLD_NS)
    processed = load_processed()

    with open(INPUT_FILE, "r") as f:
        domains = [line.strip() for line in f if line.strip() and line.strip() not in processed]

    ns_servers = TLD_NS.get(TLD, [])
    if not ns_servers:
        print("No NS servers loaded for", TLD)
        return

    # Use ProcessPoolExecutor with 8 workers
    with ProcessPoolExecutor(max_workers=8) as executor:
        futures = {}
        for idx, domain in enumerate(domains):
            ns_tuple = ns_servers[idx % len(ns_servers)]
            future = executor.submit(check_domain_worker, domain, TLD, ns_tuple)
            futures[future] = domain

        for future in as_completed(futures):
            domain, available = future.result()
            append_to_file(PROCESSED_FILE, domain, processed)

            if available:
                append_to_file(OUTPUT_FILE, domain)
                print(f"✅ Available: {domain}")
            else:
                print(f"❌ Taken: {domain}")

def check(domain, tld):
    try:
        available = domain_availability_v1(domain, tld)
    except Exception as e:
        print(f"Error checking {domain}: {e}")
    if available:
        print(f"✅ Available: {domain}")
    else:
        print(f"❌ Taken: {domain}")

if __name__ == "__main__":
    main()
#load_ns("com")
#check("aguo","com")