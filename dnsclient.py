# dnsclient.py
import dns.resolver
import base64
import sys
import pickle
import logging

logger = logging.getLogger(__name__)

# Global resolver, its configuration can be updated via configure_dns_client
resolver = dns.resolver.Resolver(configure=False)
# Default settings, can be overridden by configure_dns_client
resolver.nameservers = ['127.0.0.1']
resolver.port = 5354
_primary_domain = 'my.domain'  # Default, will be updated by configure_dns_client


def configure_dns_client(server_ip='127.0.0.1', port=5354, domain='my.domain'):
    """
    Configures the DNS client's resolver and primary domain.
    """
    global _primary_domain, resolver  # Declare modification of global variables
    resolver.nameservers = [server_ip]
    resolver.port = int(port)  # Ensure port is an integer
    _primary_domain = domain
    logger.info(f"DNSCLIENT configured: ServerIP={server_ip}, Port={resolver.port}, PrimaryDomain={_primary_domain}")


def get_file(filename: str):  # filename is typically the upload_id
    """
    Retrieves a "file" (expected to be a pickled requests.Response object)
    via DNS CNAME and TXT records, using the configured _primary_domain.
    """
    chunks_b32_bytes = b""  # Initialize as bytes for concatenation
    # Use the globally configured _primary_domain
    thedomfile = filename + "." + _primary_domain

    txt_query_domain_for_logging = "N/A"  # Initialize for logging in case of early CNAME failure

    try:
        logger.debug(f"DNSCLIENT: Resolving CNAME for {thedomfile}")
        query = resolver.resolve(thedomfile, 'CNAME')  # Can raise NXDOMAIN, NoAnswer, Timeout

        if not query:  # Should not happen if resolve doesn't raise NoAnswer, but a safeguard
            logger.error(f"DNSCLIENT: CNAME query for {thedomfile} returned empty result set.")
            raise dns.resolver.NoAnswer(f"Empty result set for CNAME {thedomfile}")
        cname_result = query[0].to_text()  # Get the first CNAME record
        logger.debug(f"DNSCLIENT: CNAME result for {thedomfile}: {cname_result}")

        # Retrieve number of chunks from the first part of the CNAME record
        # e.g., "10.original.query.name." -> 10
        # Split only on the first dot to handle cases where original_query_name might have numbers
        cname_parts = cname_result.split('.', 1)
        if not cname_parts or not cname_parts[0].isdigit():
            logger.error(f"DNSCLIENT: CNAME result for {thedomfile} has unexpected format: {cname_result}")
            raise ValueError(f"Unexpected CNAME format from DNS for {filename}: {cname_result}")
        num_chunks_total = int(cname_parts[0])

        # Do TXT queries to retrieve each chunk
        # The query format is <chunk_index>.<original_CNAME_query_domain> (which is thedomfile)
        for i in range(num_chunks_total):  # Iterate from 0 to num_chunks_total - 1
            txt_query_domain_for_logging = f'{i}.{thedomfile}'  # e.g., "0.filename.my.domain"
            logger.debug(f"DNSCLIENT: Resolving TXT for {txt_query_domain_for_logging}")
            txt_query_response = resolver.resolve(txt_query_domain_for_logging, 'TXT')

            for rdata in txt_query_response:
                for s in rdata.strings:  # rdata.strings is a tuple of bytes objects
                    chunks_b32_bytes += s

        logger.debug(f"DNSCLIENT: Total Base32 encoded chunks length: {len(chunks_b32_bytes)}")
        if not chunks_b32_bytes:
            logger.warning(f"DNSCLIENT: No data chunks received for {filename}")
            raise ValueError(f"No data chunks found in DNS for {filename}")

        # Decode base32 data - this should be the pickled requests.Response object
        pickled_response_bytes = base64.b32decode(chunks_b32_bytes)
        logger.debug(f"DNSCLIENT: Length of B32 decoded (pickled) data: {len(pickled_response_bytes)}")

        # Unpickle the requests.Response object
        response_obj = pickle.loads(pickled_response_bytes)
        logger.debug(f"DNSCLIENT: Successfully unpickled response object of type: {type(response_obj)}")

        # Basic validation: Ensure it's a requests.Response-like object (duck-typing)
        if not all(hasattr(response_obj, attr) for attr in ['content', 'status_code', 'headers']):
            logger.error(f"DNSCLIENT: Unpickled object for {filename} is not a valid response object.")
            raise ValueError(f"Data from DNS for {filename} did not unpickle into a valid response object.")

        content = response_obj.content  # Bytes
        status_code = response_obj.status_code  # Integer
        headers = dict(response_obj.headers)  # Dictionary

        logger.info(
            f"DNSCLIENT: Extracted content (len:{len(content)}), status:{status_code}, headers from unpickled object for {filename}")
        return content, status_code, headers

    except pickle.UnpicklingError as e:
        logger.exception(f"DNSCLIENT: Failed to unpickle response for {filename}: {e}")
        raise ValueError(f"Invalid pickled data from DNS for {filename}") from e
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
        failed_query = thedomfile if 'txt_query_domain_for_logging' not in locals() or locals()[
            'txt_query_domain_for_logging'] == "N/A" else txt_query_domain_for_logging
        logger.warning(
            f"DNSCLIENT: DNS record not found or no answer for {filename} (Query: {failed_query}): {type(e).__name__} - {e}")
        raise
    except dns.resolver.Timeout as e:
        failed_query = thedomfile if 'txt_query_domain_for_logging' not in locals() or locals()[
            'txt_query_domain_for_logging'] == "N/A" else txt_query_domain_for_logging
        logger.warning(f"DNSCLIENT: DNS query timed out for {filename} (Query: {failed_query}): {e}")
        raise
    except base64.binascii.Error as e:
        logger.exception(f"DNSCLIENT: Base32 decoding failed for {filename}: {e}")
        raise ValueError(f"Invalid Base32 data from DNS for {filename}") from e
    except Exception as e:
        logger.exception(f"DNSCLIENT: An unexpected error occurred in get_file for {filename}: {e}")
        raise RuntimeError(f"DNS client failed for {filename}") from e


if __name__ == "__main__":
    # Basic logging for direct script execution
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    if len(sys.argv) < 2:
        print("Usage: python dnsclient.py <filename_on_server> [dns_server_ip] [dns_port] [dns_primary_domain]")
        print("Example: python dnsclient.py somefile 127.0.0.1 5354 my.files")
        sys.exit(1)

    filename_to_get = sys.argv[1]
    # Defaults for standalone testing if not provided
    dns_ip_arg = sys.argv[2] if len(sys.argv) > 2 else '127.0.0.1'
    dns_port_arg = sys.argv[3] if len(sys.argv) > 3 else 5354
    dns_domain_arg = sys.argv[4] if len(
        sys.argv) > 4 else 'my.domain'  # Default to 'my.domain' for standalone test consistency

    try:
        dns_port_arg = int(dns_port_arg)
    except ValueError:
        print(f"Error: Invalid port number '{dns_port_arg}'. Must be an integer.")
        sys.exit(1)

    # Configure the client using command-line arguments for standalone testing
    configure_dns_client(server_ip=dns_ip_arg, port=dns_port_arg, domain=dns_domain_arg)

    print(
        f"Attempting to retrieve file: {filename_to_get} via DNS server {dns_ip_arg}:{dns_port_arg} for domain {dns_domain_arg}")

    try:
        content, status, headers = get_file(filename_to_get)
        # Outputting to stdout; ensure it can handle bytes if content is binary
        sys.stdout.buffer.write(b"Status: " + str(status).encode() + b"\n")
        sys.stdout.buffer.write(b"Headers: " + str(headers).encode() + b"\n")
        sys.stdout.buffer.write(b"Content:\n")
        sys.stdout.buffer.write(content)
        sys.stdout.buffer.write(b"\n")  # Ensure a newline at the end if writing to terminal
    except Exception as e:
        # Log the full exception details if it's not one of the re-raised DNS ones
        if not isinstance(e, (
        dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, ValueError, RuntimeError)):
            logger.exception(f"Unexpected error during standalone get_file for {filename_to_get}:")
        sys.stderr.write(f"Error retrieving file '{filename_to_get}': {type(e).__name__} - {e}\n")