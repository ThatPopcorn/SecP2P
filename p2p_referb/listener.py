#!/usr/bin/env python3
import argparse
import sys
import time
from datetime import datetime

# --- Important: Check if running as root/admin ---
import os
try:
    PERMISSION_CHECK = os.geteuid() == 0
except AttributeError:  # os.geteuid not available on Windows
    try:
        import ctypes
        PERMISSION_CHECK = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        PERMISSION_CHECK = False # Assume no admin if check fails

if not PERMISSION_CHECK:
    print("-----------------------------------------------------", file=sys.stderr)
    print("WARNING: Scapy needs root/administrator privileges!", file=sys.stderr)
    print("Please run this script using 'sudo' (Linux/macOS) or 'Run as Administrator' (Windows).", file=sys.stderr)
    print("-----------------------------------------------------", file=sys.stderr)
    # Optionally exit, or let Scapy fail later
    # sys.exit(1)

try:
    from scapy.all import sniff, TCP, IP, Raw, Ether, Packet, conf, show_interfaces
except ImportError:
    print("Error: Scapy is not installed. Please install it using 'pip install scapy'", file=sys.stderr)
    sys.exit(1)


DEFAULT_PORT = 65001 # Should match the port in p2p_chat_app.py
PAYLOAD_DISPLAY_LIMIT = 150 # Limit how much payload repr/decoded is printed

# --- Callback function for each sniffed packet ---
def packet_handler(packet: Packet):
    """Processes sniffed packets to check TCP payload."""
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return # Ignore non-TCP/IP packets

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    print(f"\n--- Packet Captured [{timestamp}] ---")
    print(f"From: {src_ip}:{src_port}  To: {dst_ip}:{dst_port}  Flags: {packet[TCP].flags}")

    if packet.haslayer(Raw):
        payload = packet[Raw].load # Payload as bytes
        payload_len = len(payload)
        print(f"TCP Payload Length: {payload_len} bytes")

        # Print Representation (useful for binary data)
        payload_repr = repr(payload[:PAYLOAD_DISPLAY_LIMIT])
        if payload_len > PAYLOAD_DISPLAY_LIMIT:
            payload_repr += f"... ({payload_len - PAYLOAD_DISPLAY_LIMIT} more bytes)"
        print(f"Payload (repr): {payload_repr}")

        # Attempt to Decode (should fail or look garbled for encrypted data)
        try:
            # Use 'replace' to avoid crashing on invalid UTF-8
            decoded_payload = payload.decode('utf-8', errors='replace')
            decoded_display = decoded_payload[:PAYLOAD_DISPLAY_LIMIT]
            if len(decoded_payload) > PAYLOAD_DISPLAY_LIMIT:
                 decoded_display += f"... ({len(decoded_payload) - PAYLOAD_DISPLAY_LIMIT} more chars)"
            print(f"Payload (UTF-8 Attempt): {decoded_display}")
            # Check if it looks like plaintext JSON (key exchange) or actual chat
            if payload_len > 10 and ('{"type":' in decoded_payload or '{"payload":' in decoded_payload):
                print("INFO: Payload might be unencrypted JSON (e.g., key exchange).")
            elif payload_len > 5 and not any(c == '\ufffd' for c in decoded_payload[:20]): # Check for replacement chars
                # Simple heuristic: if it decodes cleanly and isn't clearly JSON... maybe suspect?
                 print("WARNING: Payload decoded cleanly. Was encryption expected at this stage?")

        except Exception as e:
            # This case shouldn't happen often with errors='replace'
            print(f"Payload (UTF-8 Attempt): Error during decode attempt - {e}")

    else:
        print("TCP Packet has NO Raw Payload (e.g., ACK, SYN, FIN)")

    print("-" * (len(f"--- Packet Captured [{timestamp}] ---"))) # Match separator length


# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scapy-based Packet Listener for P2P Chat Encryption Test.",
        formatter_class=argparse.RawTextHelpFormatter
        )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"TCP port the chat application uses (default: {DEFAULT_PORT})"
    )
    parser.add_argument(
        "-i", "--iface",
        type=str,
        default=None,
        help=("Network interface to sniff on (e.g., 'eth0', 'en0', 'Wi-Fi').\n"
              "If not specified, Scapy might guess or use the default.\n"
              "Use '--list-ifaces' to see available interfaces.")
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (default: 0, sniff indefinitely)"
    )
    parser.add_argument(
        '--list-ifaces',
        action='store_true',
        help='List available network interfaces and exit.'
    )

    args = parser.parse_args()

    if args.list_ifaces:
        print("Available network interfaces:")
        try:
            # Use show_interfaces() for better output if available
            if hasattr(conf, 'route') and hasattr(conf.route, 'route') and conf.route.routes:
                 show_interfaces()
            else: # Fallback for simpler listing if routing table is weird
                 ifs = conf.ifaces
                 for idx, name in ifs.items():
                     print(f"  Index: {idx}, Name: {name.name}, MAC: {name.mac}, IP: {name.ip}")

        except Exception as e:
             print(f"Error listing interfaces: {e}")
             print("Scapy might need root/admin privileges or Npcap/libpcap installed correctly.")
        sys.exit(0)

    # Construct BPF filter
    bpf_filter = f"tcp port {args.port}"
    print(f"[*] Starting Scapy Listener...")
    print(f"[*] Using BPF filter: '{bpf_filter}'")
    if args.iface:
        print(f"[*] Sniffing on interface: {args.iface}")
    else:
        print("[*] Sniffing on default interface (specify -i if needed).")
    if args.count > 0:
        print(f"[*] Capturing {args.count} packets.")
    else:
        print("[*] Capturing indefinitely (Press Ctrl+C to stop).")

    if not PERMISSION_CHECK:
         print("\nWARNING: Attempting to sniff without root/admin privileges. This might fail.\n")


    try:
        sniff(
            iface=args.iface,       # Network interface
            filter=bpf_filter,    # BPF filter string
            prn=packet_handler,   # Function to call for each packet
            store=0,              # Don't store packets in memory
            count=args.count      # Number of packets to capture (0=infinite)
        )
        print("\n[*] Sniffing finished.")
    except PermissionError as e:
         print(f"\nERROR: Permission denied. Scapy requires root/admin privileges to sniff. ({e})", file=sys.stderr)
         sys.exit(1)
    except OSError as e:
         print(f"\nERROR: OSError during sniffing. Is the interface '{args.iface}' correct and up? ({e})", file=sys.stderr)
         if "No such device" in str(e) or "Network is down" in str(e):
             print("Try listing interfaces with --list-ifaces", file=sys.stderr)
         sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Sniffing stopped by user (Ctrl+C).")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)