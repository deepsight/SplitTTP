# splittp_client.py
import argparse
import base64
import json
import asyncio
import aiohttp
from aiohttp import web
import random
import string
from urllib.parse import urljoin
import logging
import pickle  # For potential errors from dnsclient related to pickling

# --- Import your actual dnsclient ---
DNSCLIENT_AVAILABLE = False
try:
    import dnsclient  # dnsclient.py should be in PYTHONPATH or same directory
    import dns.resolver  # Import dnspython's exceptions for specific handling

    DNSCLIENT_AVAILABLE = True
except ImportError:
    logging.critical(
        "Failed to import dnsclient module or dnspython. Ensure dnsclient.py is available and dnspython is installed ('pip install dnspython').")

    # Fallback dummy if import fails
    class dnsclient_fallback:
        def get_file(self, upload_id: str):
            logging.error(f"FALLBACK DNSCLIENT: get_file called for {upload_id}. DNS client module not available.")
            raise ImportError("dnsclient module or dnspython not found")

        def configure_dns_client(self, server_ip, port, domain):  # Add dummy configure for fallback
            logging.error(
                f"FALLBACK DNSCLIENT: configure_dns_client called with {server_ip}:{port} for {domain}. DNS client module not available.")
            pass  # Does nothing in fallback


    dnsclient = dnsclient_fallback()  # Assign fallback

    # Define common dns exceptions if the module didn't load, to prevent NameError in except blocks
    if 'dns' not in globals() or not hasattr(dns, 'resolver'):
        class FakeDNSException(Exception):
            pass

        class NXDOMAIN(FakeDNSException):
            pass

        class Timeout(FakeDNSException):
            pass

        class NoAnswer(FakeDNSException):
            pass

        if 'dns' not in globals():
            dns = type('module', (object,), {'__name__': 'dns_fallback'})()  # Dummy dns module
        if not hasattr(dns, 'resolver'):
            # Dummy dns.resolver module
            dns.resolver = type('module', (object,), {'__name__': 'dns_resolver_fallback'})()
        dns.resolver.NXDOMAIN = NXDOMAIN
        dns.resolver.Timeout = Timeout
        dns.resolver.NoAnswer = NoAnswer

# --- Argument Parsing ---
parser = argparse.ArgumentParser(description='Async Proxy client using aiohttp (SplitTTP Client)')
parser.add_argument('-s', '--server', type=str, required=True,
                    help='URL of the intermediary server (e.g., http://splittp-server-ip:8080)')
parser.add_argument('--host', type=str, default=None,
                    help='Host header for outgoing requests to the intermediary -server (if needed)')
parser.add_argument('-p', '--port', type=int, default=5000,
                    help='Port number to run this splittp_client proxy on (default: 5000)')
parser.add_argument('--listen-host', type=str, default='0.0.0.0',  # New argument
                    help='Host IP address for this splittp_client proxy to listen on (default: 0.0.0.0 for all interfaces)')

# DNS Configuration Arguments
parser.add_argument('--dns-server-ip', type=str, default='127.0.0.1',
                    help='IP address of your custom DNS server for dnsclient (default: 127.0.0.1)')
parser.add_argument('--dns-server-port', type=int, default=5354,
                    help='Port of your custom DNS server for dnsclient (default: 5354)')
parser.add_argument('-dd', '--dns-domain', type=str, default='my.files',
                    help='Base domain for DNS queries used by dnsclient (e.g., my.files). Default: my.files')

# Logging and Debugging Arguments
parser.add_argument('-ll', '--loglevel', choices=['debug', 'info', 'warning', 'error', 'critical'], default='info',
                    help='Log level (default: info)')
parser.add_argument('--debug', action='store_true', help='Enable debug mode (sets loglevel to DEBUG)')
parser.add_argument('--outbound-proxy', type=str, default=None,
                    help='HTTP proxy ONLY for outgoing requests to the intermediary -server. DNS queries do NOT use this.')
args = parser.parse_args()

# --- Configuration ---
MAX_CHUNK_SIZE = 2000
DEFAULT_CONTENT_TYPE = 'application/octet-stream'


# --- aiohttp Request Handler ---
async def proxy_handler(request: web.Request):
    upload_id = ''.join(random.choices(string.ascii_letters + string.digits, k=7))
    original_request_url = str(request.url)
    logger = request.app['logger']

    try:
        raw_body = await request.read()
        body_as_text = ""
        if raw_body:
            try:
                body_as_text = raw_body.decode('utf-8')
            except UnicodeDecodeError:
                body_as_text = base64.b64encode(raw_body).decode('ascii')
                logger.warning(f"Original request body for {original_request_url} was not UTF-8. "
                               f"Sent as Base64 in JSON payload to intermediary server.",
                               extra={"upload_id": upload_id})

        request_data_for_intermediary = {
            "method": request.method,
            "headers": dict(request.headers),
            "data": body_as_text,
            "url": original_request_url,
        }
        serialized_request = json.dumps(request_data_for_intermediary).encode('utf-8')
        encoded_payload_for_url = base64.b64encode(serialized_request)
        encoded_payload_str = encoded_payload_for_url.decode('utf-8').replace("+", "%2B").replace("/", "%2F")

        chunks = [encoded_payload_str[i:i + MAX_CHUNK_SIZE] for i in range(0, len(encoded_payload_str), MAX_CHUNK_SIZE)]
        if not chunks: chunks.append("")

        base_url_for_intermediary_server = args.server
        custom_outgoing_headers = {}
        if args.host: custom_outgoing_headers['Host'] = args.host

        logger.info(
            f"Sending {len(chunks)} chunks for {upload_id} to intermediary server {base_url_for_intermediary_server}",
            extra={"upload_id": upload_id})

        async with aiohttp.ClientSession(headers=custom_outgoing_headers) as session:
            for i, chunk_str in enumerate(chunks):
                receive_url = urljoin(base_url_for_intermediary_server,
                                      f"/receive/{upload_id}/{i}/{len(chunks)}/{chunk_str}")
                logger.debug(f"Sending chunk {i + 1}/{len(chunks)} to {receive_url}", extra={"upload_id": upload_id})
                try:
                    async with session.get(receive_url, proxy=args.outbound_proxy,
                                           timeout=aiohttp.ClientTimeout(total=30)) as resp:
                        if resp.status not in [200, 202, 401]:
                            error_text_preview = (await resp.text())[:200]
                            logger.warning(
                                f"Intermediary server {receive_url} (chunk {i + 1}) returned status {resp.status}. Body: {error_text_preview}...",
                                extra={"upload_id": upload_id})
                        else:
                            logger.debug(f"Intermediary server {receive_url} (chunk {i + 1}) status {resp.status}.",
                                         extra={"upload_id": upload_id})
                except asyncio.TimeoutError:
                    logger.error(f"Timeout sending chunk {i + 1} to {receive_url}. Continuing...",
                                 extra={"upload_id": upload_id})
                except aiohttp.ClientError as e:
                    logger.error(f"Client error sending chunk {i + 1} to {receive_url}: {e}. Continuing...",
                                 extra={"upload_id": upload_id})
                except Exception as e:
                    logger.error(f"Generic error sending chunk {i + 1} to {receive_url}: {e}. Continuing...",
                                 extra={"upload_id": upload_id})

        logger.info(f"All chunks sent for {upload_id}. Pausing before DNS retrieval.", extra={"upload_id": upload_id})
        await asyncio.sleep(2)

        logger.info(f"Calling dnsclient.get_file for {upload_id}", extra={"upload_id": upload_id})
        try:
            loop = asyncio.get_running_loop()
            final_content_bytes, final_status, final_headers_dict = await loop.run_in_executor(
                None, dnsclient.get_file, upload_id
            )

            safe_final_headers = {
                k: v for k, v in (final_headers_dict or {}).items()
                if
                k.lower() not in ['transfer-encoding', 'connection', 'content-encoding', 'content-length', 'keep-alive']
            }
            if final_content_bytes and 'content-type' not in (key.lower() for key in safe_final_headers):
                safe_final_headers['Content-Type'] = DEFAULT_CONTENT_TYPE

            logger.info(f"Response from dnsclient for {upload_id}: status={final_status}. Sending to original client.",
                        extra={"upload_id": upload_id})
            return web.Response(body=final_content_bytes, status=final_status, headers=safe_final_headers)

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
            logger.warning(f"DNS query failed for {upload_id}: {type(e).__name__} - {e}",
                           extra={"upload_id": upload_id})
            http_status = 404 if isinstance(e, dns.resolver.NXDOMAIN) else 502
            return web.Response(
                text=f"Proxy error: Resource for {upload_id} not found or no answer via DNS ({type(e).__name__}).",
                status=http_status)
        except dns.resolver.Timeout as e:
            logger.error(f"DNS query timed out for {upload_id}: {e}", extra={"upload_id": upload_id})
            return web.Response(text=f"Proxy error: DNS query timed out for {upload_id}.", status=504)
        except (base64.binascii.Error, pickle.UnpicklingError, ValueError) as data_err:
            logger.error(f"Error decoding/processing data from DNS for {upload_id}: {data_err}",
                         extra={"upload_id": upload_id})
            return web.Response(text=f"Proxy error: Invalid data format received from DNS for {upload_id}.", status=502)
        except ImportError as e:
            logger.critical(f"ImportError related to dnsclient for {upload_id}: {e}", extra={"upload_id": upload_id})
            return web.Response(text="Proxy critical error: DNS client component is not available or misconfigured.",
                                status=500)
        except Exception as e:
            logger.exception(f"Unexpected error during dnsclient processing for {upload_id}: {e}",
                             extra={"upload_id": upload_id})
            return web.Response(text=f"Proxy error: Failed to retrieve or process final content via DNS: {str(e)}",
                                status=502)

    except json.JSONDecodeError as e:
        logger.error(f"Error serializing original client request for {upload_id} to JSON: {e}",
                     extra={"upload_id": upload_id, "url": original_request_url})
        return web.Response(text="Proxy error: Could not serialize original request data.", status=500)
    except Exception as e:
        logger.exception(f"Unexpected error in proxy_handler (pre-DNS stage) for {upload_id}: {e}",
                         extra={"upload_id": upload_id})
        return web.Response(text=f"Proxy error: An unexpected internal server error occurred: {str(e)}", status=500)


# --- Main Application Setup and Run ---
async def main_async():
    log_level_str = args.loglevel.upper()
    if args.debug: log_level_str = 'DEBUG'

    numeric_level = getattr(logging, log_level_str, logging.INFO)
    if not isinstance(numeric_level, int):
        print(f"Warning: Invalid log level '{args.loglevel}'. Defaulting to INFO.")
        numeric_level = logging.INFO

    log_format = '%(asctime)s %(levelname)s [%(name)s:%(filename)s:%(lineno)d] (%(upload_id)s) %(message)s'

    class UploadIdFilter(logging.Filter):
        def filter(self, record):
            if not hasattr(record, 'upload_id'): record.upload_id = 'N/A'
            return True

    logging.basicConfig(level=numeric_level, format=log_format, force=True)

    for handler_ in logging.getLogger().handlers:
        is_already_filtered = any(isinstance(f, UploadIdFilter) for f in handler_.filters)
        if not is_already_filtered:
            handler_.addFilter(UploadIdFilter())
        current_formatter = handler_.formatter
        if not isinstance(current_formatter, logging.Formatter) or \
                (hasattr(current_formatter, '_fmt') and current_formatter._fmt != log_format) or \
                (hasattr(current_formatter, '_style') and hasattr(current_formatter._style,
                                                                  '_fmt') and current_formatter._style._fmt != log_format):
            formatter = logging.Formatter(log_format)
            handler_.setFormatter(formatter)

    if not args.debug:
        for noisy_logger_name in ['aiohttp.access', 'aiohttp.client', 'aiohttp.internal', 'aiohttp.server',
                                  'aiohttp.web', 'asyncio', 'dnslib.server']:
            logging.getLogger(noisy_logger_name).setLevel(logging.WARNING)

    # --- Configure dnsclient module ---
    if DNSCLIENT_AVAILABLE and hasattr(dnsclient, 'configure_dns_client'):
        try:
            dnsclient.configure_dns_client(
                server_ip=args.dns_server_ip,
                port=args.dns_server_port,
                domain=args.dns_domain
            )
            logging.info(
                f"dnsclient configured for domain: {args.dns_domain}, server: {args.dns_server_ip}:{args.dns_server_port}")
        except Exception as e:
            logging.error(f"Failed to configure dnsclient: {e}. dnsclient will use its internal defaults or fail.")
    elif DNSCLIENT_AVAILABLE:
        logging.warning("The imported 'dnsclient' module does not have 'configure_dns_client' method. "
                        "DNS settings (server IP, port, domain) will rely on defaults within dnsclient.py.")
    else:
        logging.error("dnsclient module is not available. DNS retrieval for responses will fail.")

    app = web.Application()
    app['logger'] = logging.getLogger("splitttp_client.app")

    app.router.add_route("*", "/{path_info:.*}", proxy_handler)
    app.router.add_route("*", "/", proxy_handler)

    runner = web.AppRunner(app, access_log=logging.getLogger('aiohttp.access') if args.debug else None)
    await runner.setup()
    # Use the new --listen-host argument here
    site = web.TCPSite(runner, host=args.listen_host, port=args.port)

    app['logger'].info(f"Starting SplitTTP Client (HTTP Proxy) on http://{args.listen_host}:{args.port}")
    app['logger'].info(f"Intermediary server for exfiltration: {args.server}")
    if args.host: app['logger'].info(
        f"Custom Host header for intermediary -server: {args.host}")  # Corrected log message
    if args.outbound_proxy: app['logger'].info(f"Outbound HTTP proxy for intermediary server: {args.outbound_proxy}")

    await site.start()
    app['logger'].info("SplitTTP Client started. Listening for application requests. Press Ctrl+C to stop.")
    try:
        while True: await asyncio.sleep(3600)
    except KeyboardInterrupt:
        app['logger'].info("KeyboardInterrupt received, shutting down SplitTTP Client...")
    finally:
        await runner.cleanup()
        app['logger'].info("SplitTTP Client stopped.")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(main_async(), debug=args.debug)
    except KeyboardInterrupt:
        logging.info("Application launch interrupted by user.")
    except Exception as e:
        logging.exception(
            "Critical error occurred that prevented application start or caused unhandled runtime failure:")