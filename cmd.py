import argparse
import subprocess
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(SCRIPT_DIR, "ipscan")

parser = argparse.ArgumentParser(description="IP port scanner")

parser.add_argument("--target", required=True, help="Target IP address")
parser.add_argument("-p", "--ports", type=int, help="Port")
args = parser.parse_args()

cmd = [BIN, args.target]
if args.ports:
    cmd.append(str(args.ports))
    
subprocess.run(cmd)