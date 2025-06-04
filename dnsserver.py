import os
import base64
import argparse
import threading  # Added for running TCP and UDP servers concurrently
import time  # Added for the main loop sleep
from dnslib import RR, QTYPE, RCODE, CNAME, TXT
from dnslib.server import DNSServer, BaseResolver

# Define the intended base directory for files.
# Ensure this directory exists and the server process has read access to it.
# Using a dedicated subdirectory is generally safer.
BASE_FILE_DIR = b"/tmp/dns_files"


class MyResolver(BaseResolver):
    file_dict = {}
    base_domain_labels = []
    base_domain_str = ""

    def __init__(self, base_domain_str):
        self.base_domain_str = base_domain_str
        # Normalize to lowercase and encode for consistent matching, as DNS is case-insensitive.
        self.base_domain_labels = [label.lower().encode('idna') for label in base_domain_str.split('.')]
        # Get the absolute path of the base directory as bytes
        self.abs_base_file_dir = os.path.abspath(BASE_FILE_DIR)

        if not os.path.isdir(self.abs_base_file_dir):
            print(
                f"[Warning] MyResolver: Base directory '{self.abs_base_file_dir.decode(errors='replace')}' does not exist or is not a directory at resolver instantiation.")

    def _is_safe_path(self, filename_bytes_label):
        """
        Validates if the filename (derived from a DNS label) is safe and resolves
        to a path strictly within the BASE_FILE_DIR.
        Returns the absolute, validated path (bytes) if safe, otherwise None.
        """
        if not isinstance(filename_bytes_label, bytes):
            return None

        if filename_bytes_label == b'.' or filename_bytes_label == b'..' or b'\x00' in filename_bytes_label:
            return None

        try:
            prospective_path = os.path.join(self.abs_base_file_dir, filename_bytes_label)
            resolved_path = os.path.abspath(prospective_path)
        except ValueError:
            return None

        path_separator_bytes = os.sep.encode()
        if resolved_path.startswith(self.abs_base_file_dir + path_separator_bytes) and \
                resolved_path != self.abs_base_file_dir:
            if os.path.basename(resolved_path) == filename_bytes_label:
                return resolved_path
        return None

    def resolve(self, request, handler):
        reply = request.reply()
        query_labels = request.q.qname.label

        if len(query_labels) <= len(self.base_domain_labels):
            return reply

        query_suffix_labels = query_labels[-len(self.base_domain_labels):]
        is_our_domain = True
        for i in range(len(self.base_domain_labels)):
            if query_suffix_labels[i].lower() != self.base_domain_labels[i]:
                is_our_domain = False
                break
        if not is_our_domain:
            return reply

        payload_labels = query_labels[:-len(self.base_domain_labels)]

        if request.q.qtype == QTYPE.CNAME:
            if len(payload_labels) != 1:
                reply.header.rcode = RCODE.FORMERR
                return reply

            file_label_as_filename = payload_labels[0]
            safe_file_path = self._is_safe_path(file_label_as_filename)

            if not safe_file_path:
                reply.header.rcode = RCODE.REFUSED
                return reply

            if not os.path.isfile(safe_file_path):
                reply.header.rcode = RCODE.NXDOMAIN
            else:
                try:
                    with open(safe_file_path, 'rb') as f:
                        content = f.read()
                except IOError:
                    reply.header.rcode = RCODE.SERVFAIL
                    return reply

                encoded_content = base64.b32encode(content).decode('ascii')
                self.file_dict[file_label_as_filename] = [encoded_content[i: i + 253] for i in
                                                          range(0, len(encoded_content), 253)]

                # Corrected line: use str(request.q.qname)
                cname_target_str = '{}.{}'.format(len(self.file_dict[file_label_as_filename]),
                                                  str(request.q.qname))
                reply.add_answer(
                    RR(request.q.qname, QTYPE.CNAME, rdata=CNAME(cname_target_str)))

        elif request.q.qtype == QTYPE.TXT:
            if len(payload_labels) != 2:
                reply.header.rcode = RCODE.FORMERR
                return reply

            chunk_index_label = payload_labels[0]
            file_label_as_key = payload_labels[1]

            if file_label_as_key == b'.' or file_label_as_key == b'..' or b'\x00' in file_label_as_key:
                reply.header.rcode = RCODE.REFUSED
                return reply

            try:
                chunk_index_str = chunk_index_label.decode('ascii')
                chunk_index = int(chunk_index_str)
            except (ValueError, UnicodeDecodeError):
                reply.header.rcode = RCODE.FORMERR
                return reply

            if file_label_as_key in self.file_dict:
                file_content_chunks = self.file_dict[file_label_as_key]
                if 0 <= chunk_index < len(file_content_chunks):
                    reply.add_answer(RR(request.q.qname, QTYPE.TXT,
                                        rdata=TXT(file_content_chunks[chunk_index])))
                else:
                    reply.header.rcode = RCODE.NXDOMAIN
            else:
                reply.header.rcode = RCODE.NXDOMAIN

        elif not reply.rr and reply.header.rcode == RCODE.NOERROR:
            reply.header.rcode = RCODE.REFUSED

        return reply


def main():
    parser = argparse.ArgumentParser(description="DNS File Transfer Server")
    parser.add_argument(
        "-d", "--domain",
        default="my.files",
        help="Base domain for the DNS service (e.g., my.files). Default: my.files"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=5354,
        help="Port to listen on. Default: 5354"
    )
    parser.add_argument(
        "--tcp",
        action="store_true",
        help="Enable TCP listener."
    )
    parser.add_argument(
        "--udp",
        action="store_true",
        help="Enable UDP listener."
    )
    args = parser.parse_args()

    service_base_domain = args.domain
    listen_port = args.port
    listen_address = "0.0.0.0"

    use_tcp_flag = args.tcp
    use_udp_flag = args.udp

    if not use_tcp_flag and not use_udp_flag:
        print("No protocol specified (--tcp or --udp), defaulting to both TCP and UDP.")
        use_tcp_flag = True
        use_udp_flag = True

    target_base_dir_abs = os.path.abspath(BASE_FILE_DIR)
    if not os.path.isdir(target_base_dir_abs):
        print(f"Base file directory '{target_base_dir_abs.decode(errors='replace')}' does not exist.")
        try:
            print(f"Attempting to create directory: '{target_base_dir_abs.decode(errors='replace')}'")
            os.makedirs(target_base_dir_abs, exist_ok=True)
            print(f"Successfully created/confirmed directory: '{target_base_dir_abs.decode(errors='replace')}'")
        except OSError as e:
            print(f"Fatal: Could not create base directory '{target_base_dir_abs.decode(errors='replace')}': {e}")
            print("Please create this directory manually and ensure the server has read permissions.")
            return

    print(f"Initializing MyResolver for base domain: *.{service_base_domain}")
    resolver = MyResolver(service_base_domain)

    active_server_threads = []
    server_instances_to_manage = []

    if use_udp_flag:
        try:
            print(f"Preparing UDP DNS server on {listen_address}:{listen_port}...")
            udp_server = DNSServer(resolver, port=listen_port, address=listen_address, tcp=False)
            server_instances_to_manage.append({"instance": udp_server, "protocol": "UDP"})
        except Exception as e:
            print(f"Failed to prepare UDP server: {e}")

    if use_tcp_flag:
        try:
            print(f"Preparing TCP DNS server on {listen_address}:{listen_port}...")
            tcp_server = DNSServer(resolver, port=listen_port, address=listen_address, tcp=True)
            server_instances_to_manage.append({"instance": tcp_server, "protocol": "TCP"})
        except Exception as e:
            print(f"Failed to prepare TCP server: {e}")

    if not server_instances_to_manage:
        print("Error: No DNS server protocols could be prepared to start.")
        return

    try:
        for server_info in server_instances_to_manage:
            s = server_info["instance"]
            protocol = server_info["protocol"]
            print(f"Starting {protocol} DNS server in a thread...")
            thread = threading.Thread(target=s.start, name=f"DNSServer-{protocol}")
            thread.daemon = True
            thread.start()
            active_server_threads.append(thread)

        protocol_names = ", ".join([si["protocol"] for si in server_instances_to_manage])
        print(
            f"DNS server(s) (Protocols: {protocol_names}) running on {listen_address}:{listen_port}. Press Ctrl+C to stop.")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nDNS Server stopping due to KeyboardInterrupt...")
    except Exception as e:
        print(f"An unexpected error occurred during server operation: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("Shutting down DNS servers...")
        for server_info in server_instances_to_manage:
            instance = server_info["instance"]
            protocol = server_info["protocol"]
            print(f"Stopping {protocol} server...")
            try:
                if hasattr(instance, 'server') and hasattr(instance.server, 'shutdown') and callable(
                        instance.server.shutdown):
                    instance.server.shutdown()
                    if hasattr(instance, 'stop') and callable(instance.stop):
                        instance.stop()
                    elif hasattr(instance.server, 'server_close') and callable(instance.server.server_close):
                        instance.server.server_close()
                elif hasattr(instance, 'stop') and callable(instance.stop):
                    instance.stop()
                else:
                    print(
                        f"Note: {protocol} server instance does not have a standard stop() or server.shutdown() method.")
            except Exception as e_shutdown:
                print(f"Error while stopping {protocol} server: {e_shutdown}")

        print("All DNS servers signaled to stop.")


if __name__ == '__main__':
    main()