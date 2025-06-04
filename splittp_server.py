import binascii
import os
import argparse
import urllib.parse
import logging
from flask import Flask, request, make_response
import base64
import json
import requests
import pickle

app = Flask(__name__)

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Proxy server')
parser.add_argument('-server', type=str, required=False,
                    help='URL of the destination server (e.g., http://example.com:8080)')
parser.add_argument('-port', type=int, default=5000, help='Port number to run the server on (default: 5000)')
parser.add_argument('-loglevel', choices=['debug', 'info', 'warning', 'error', 'critical'], default='info',
                    help='Log level (default: info)')
parser.add_argument('-ssl-cert', type=str, default=None, help='Path to SSL certificate file')
parser.add_argument('-ssl-key', type=str, default=None, help='Path to SSL private key file')
parser.add_argument('--debug', action='store_true', help='Enable debug mode')
args = parser.parse_args()

# Configure logging
log_level = logging.DEBUG if args.debug else logging.INFO
logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s: %(message)s')


def reconstruct_url(args, request_data):
    if args.server:
        base_host = args.server.split("://")[-1]
        print("BASEUELLLLLL", base_host)
    else:
        base_host = request_data.get('headers', {}).get('Host', '')
        print("BASEUELLLLLL", base_host)

    if not base_host:
        logging.error("No destination server provided in either -server argument or Host header.")
        return None

    path = request_data.get('url', '')
    path = '/' + "/".join(path.split("/", )[3:])

    return "http://" + base_host + path


chunks = {}


@app.route('/receive/<upload_id>/<int:chunk_index>/<int:total_chunks>/<path:chunk>', methods=['GET'])
def receive_chunk(upload_id, chunk_index, total_chunks, chunk):
    logging.debug(f"Received chunk {chunk_index + 1}/{total_chunks} for upload {upload_id}")
    if upload_id in chunks.keys():
        chunks[upload_id] += chunk
    else:
        chunks[upload_id] = chunk

    if chunk_index == total_chunks - 1:
        # decode all chunks
        try:
            decoded_chunks = base64.b64decode(chunks[upload_id])
            original_data = bytes(decoded_chunks)
            logging.info(f"Received complete data for upload {upload_id}")


        except binascii.Error as e:
            logging.error(f"Error decoding chunks: {e}")
            return make_response("Invalid chunks encoding", 400)

        try:
            request_data = json.loads(original_data.decode('utf-8'))
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON: {e}")
            return make_response("Invalid request data", 400)

        logging.debug(f"Reconstructed request data: {request_data}")

        destination_url = reconstruct_url(args, request_data)

        if not destination_url:
            return make_response("Invalid destination URL", 400)

        logging.info(f"Sending now request to destination: {destination_url}")

        try:
            response = requests.request(
                request_data['method'],
                destination_url,
                headers=request_data['headers'],
                data=request_data['data'],
                verify=False,
                stream=True
            )
            print(response.text)
            with open(os.path.join('/tmp/dns_files', upload_id), 'wb') as f:
                pickle.dump(response, f)

            logging.debug(f"Sent request to destination: {destination_url}")

        except requests.RequestException as e:
            logging.error(f"Error sending request to destination: {e}")
            return make_response(f"Error forwarding request", 500)

        chunks.pop(upload_id, None)

        return make_response(response.content, response.status_code, response.headers.items())

    return 'OK'


@app.errorhandler(404)
def page_not_found(error):
    return """
<!DOCTYPE html>
<html>
<head>
    <title>Page Not Found</title>
</head>
<body>
    <h1>404 - Page Not Found</h1>
    <p>The page you are looking for does not exist.</p>
</body>
</html>
""", 404  # Return the HTML string and the 404 status code


if __name__ == '__main__':
    ssl_context = None
    if args.ssl_cert and args.ssl_key:
        ssl_context = (args.ssl_cert, args.ssl_key)

    app.run(debug=args.debug, port=args.port, ssl_context=ssl_context)