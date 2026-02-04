import socket
import sys

# Host retrieved from previous debug logs (one of the shards)
host = "ac-nf8lqvh-shard-00-00.lixcvyn.mongodb.net"
port = 27017

print(f"Testing TCP connection to {host}:{port}...")

try:
    sock = socket.create_connection((host, port), timeout=5)
    print("SUCCESS: TCP connection established!")
    sock.close()
except socket.timeout:
    print("FAILURE: Connection timed out. Firewall is likely blocking port 27017.")
except socket.gaierror:
    print("FAILURE: Could not resolve hostname (DNS issue).")
except Exception as e:
    print(f"FAILURE: {e}")
