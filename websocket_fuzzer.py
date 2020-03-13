#!/usr/bin/env python3


__author__ = "Jake Miller"
__date__ = "20200313"
__version__ = "0.01"
__description__ = """A multiprocessed, multithreaded, websockets fuzzer."""

import argparse
import ssl
import threading
import time
import sys
import socket
from queue import Queue
from multiprocessing import Pool, cpu_count

try:
    from websocket import create_connection
except ImportError:
    print('[-] Missing dependency. Try "pip install websocket-client".')
    exit()


def send_recv_message(ws_obj, msg, uri):
    """Accepts a websocket object and a message, sends the 
    message, and waits for the response. Prints the response.
    """
    ws_obj.send(msg)
    try:
        resp = ws_obj.recv()
    except Exception as e:
        resp = ""
    if resp == "":
        return
    with print_lock:
        print(f"\nSent: {msg}\nReceived from {uri}:\n{resp}\n")


def test_connection(uri):
    """Creates a connection to a URI.
    """
    if uri.startswith('wss://') and args.proxy:
        ws = create_connection(
            uri,
            header = headers, 
            sslopt = {"cert_reqs": ssl.CERT_NONE},
            timeout = network_timeout,
            http_proxy_host = proxy_host, 
            http_proxy_port = proxy_port
        )
    elif uri.startswith('wss://'):
        ws = create_connection(
            uri,
            header = headers, 
            sslopt = {"cert_reqs": ssl.CERT_NONE},
            timeout = network_timeout,
        )
    elif uri.startswith('ws://') and args.proxy:
        ws = create_connection(
            uri,
            header = headers, 
            timeout = network_timeout,
            http_proxy_host = proxy_host, 
            http_proxy_port = proxy_port
        )
    elif uri.startswith('ws://'):
        ws = create_connection(
            uri,
            header = headers, 
            timeout = network_timeout,
        )
    else:
        raise ValueError


def fuzz_websocket(uri, payload):
    """Creates a connection with a websocket and calls 
    send_recv_messages()
    """
    if uri.startswith('wss://') and args.proxy:
        ws = create_connection(
            uri,
            header = headers, 
            sslopt = {"cert_reqs": ssl.CERT_NONE},
            timeout = network_timeout,
            http_proxy_host = proxy_host, 
            http_proxy_port = proxy_port
        )
    elif uri.startswith('wss://'):
        ws = create_connection(
            uri,
            header = headers, 
            sslopt = {"cert_reqs": ssl.CERT_NONE},
            timeout = network_timeout,
        )
    elif uri.startswith('ws://') and args.proxy:
        ws = create_connection(
            uri,
            header = headers, 
            timeout = network_timeout,
            http_proxy_host = proxy_host, 
            http_proxy_port = proxy_port
        )
    elif uri.startswith('ws://'):
            ws = create_connection(
                uri,
                header = headers, 
                timeout = network_timeout,
            )
    else:
        with print_lock:
            print(f"URI {uri} must start with either ws:// or wss://. Skipping.")
        return
    ws.settimeout(timeout)
    send_recv_message(ws, payload, uri)


def manage_queue(uri, payload_queue):
    """Manages the queue, ensuring payloads are only sent once
    to each URI.
    """
    while True:
        current_payload = payload_queue.get()
        try:
            fuzz_websocket(uri, current_payload)
        except Exception as e:
            print(e)

        payload_queue.task_done()


def websocket_fuzzer_multithreader(uri):
    """Initiates multithreading and calls the manage queue
    function.
    """

    # Tests the connection to a specified URI. If an exception 
    # occurs, then this URI will be skipped, and no payloads
    # will be sent.
    try:
        test_connection(uri)
    except socket.timeout:
        print(f"Timeout Error: {uri}")
        return
    except ValueError:
        print(f"Invalid URI: {uri}")
        return
    except Exception as e:
        print(f"{e} for {uri}")
        return

    # Initiates the queue and starts multithreading
    payload_queue = Queue()

    for i in range(number_of_threads):
        t = threading.Thread(target=manage_queue, args=[uri, payload_queue])
        t.daemon = True
        t.start()

    for current_payload in payloads:
        payload_queue.put(current_payload)

    payload_queue.join()


def main():
    """Utilizes multiprocessing to send requests to one URI per
    processor. Each URI will be connected to and sent payloads.
    """

    # Print banner
    print()
    word_banner = '{} version: {}. Coded by: {}'.format(sys.argv[0].title()[:-3], __version__, __author__)
    print('=' * len(word_banner))
    print(word_banner)
    print('=' * len(word_banner))
    print()
    time.sleep(1)

    # Starts multiprocessing
    with Pool(cores) as p:
        p.map(websocket_fuzzer_multithreader, uris)


# Command line arguments
parser = argparse.ArgumentParser()
parser.add_argument(
    "-u", "--uri",
    nargs='*',
    help="Specify a single uri formatted ws(s)://addr:port"
)
parser.add_argument(
    "-uf", "--uri_file",
    help="Specify a file path containing uris formatted ws(s)://addr:port"
)
parser.add_argument(
    "-p", "--payloads",
    nargs='*',
    help="Specify payloads to send. (-p 1 exit help foo bar)"
)
parser.add_argument(
    "-pf", "--payload_file",
    nargs='*',
    help="Specify the file path containing payloads to send. (-pf /path/to/payloadfile)"
)
parser.add_argument(
    "-pr", "--proxy", 
    help="Specify a proxy to use (-pr 127.0.0.1:8080)"
)
parser.add_argument(
    "-ch", "--custom_headers", 
    nargs='*',
    help='Specify one or more custom header and value. Example: -ch "X-Custom-Header: CustomValue" "Another-Header: Value"'
)
parser.add_argument(
    "-t", "--threads",
    nargs="?",
    type=int,
    const=30,
    default=30,
    help="Specify number of threads (default=30)"
)
parser.add_argument(
    "-to", "--timeout",
    nargs="?", 
    type=int, 
    default=20, 
    help="Specify number of seconds until a connection timeout when websocket is already established (default=20)"
)
parser.add_argument(
    "--network_timeout",
    nargs="?", 
    type=int, 
    default=2, 
    help="Specify number of seconds until a connection timeout (default=2)"
)
args = parser.parse_args()

if not args.uri and not args.uri_file:
    print('[-] Please specify a URI (-u) or file containing URIs (-uf)')
    exit()

if not args.payloads and not args.payload_file:
    print('[-] Please specify the payload(s) (-p) or file containing payloads (-pf)')
    exit()

if args.uri_file:
    if not os.path.exists(uri_file):
        print(f"\n[-] The file path, {uri_file}, cannot be found or you do not have permission to open the file. Please check the path and try again\n")
        exit()
    with open(uri_file) as fh:
        uris = fh.read().splitlines() 
else:
    uris = args.uri

if args.payload_file:
    if not os.path.exists(payload_file):
        print(f"\n[-] The file path, {payload_file}, cannot be found or you do not have permission to open the file. Please check the path and try again\n")
        exit()
    with open(payload_file) as fh:
        payloads = fh.read().splitlines() 
else:
    payloads = args.payloads

if args.proxy:
    try:
        proxy_host = args.proxy.split(':')[0]
        proxy_port = int(args.proxy.split(':')[1])
    except Exception as e:
        print(f"Invalid proxy: {args.proxy}. Proxy must be formatted addr:port. Example: -pr 127.0.0.1:8080")
        exit()
if args.custom_headers:
    headers = {}
    for item in args.custom_headers:
        index = item.find(':')
        key = item[:index]
        value = item[index:].lstrip()
        headers[key] = value
else:
    # Figure out default headers
    headers = {}

number_of_threads = args.threads

timeout = args.timeout
network_timeout = args.network_timeout

# Number of cores. Will launch a process for each core.
cores = cpu_count()

# Needed to print in a thread-safe way
print_lock = threading.Lock()

if __name__ == '__main__':
    main()