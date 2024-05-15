#!/usr/bin/env python3
import argparse
import binascii
import logging
import subprocess
import sys

import netifaces
import scapy.all as scapy

default_invoc = (
    "dnsmasq --log-queries --log-dhcp --log-facility=/dnsmasq.log --bind-interfaces --port=0 --dhcp-range=interface:eth0,172.17.0.10,172.17.0.100,2m"
)


def _shell_cmd(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True)


def get_dnsmasq_invocation() -> str:
    invoc = _shell_cmd("ps -ao args | grep '^[d]nsmasq'").stdout.strip()
    if not invoc:
        logging.info(f"no instance of dnsmasq detected, assuming default invocation of '{default_invoc}'")
        return default_invoc
    else:
        logging.info(f"dnsmasq was started with '{invoc}'")
        return invoc


def shutdown_dnsmasq() -> None:
    logging.info("Shutting down dnsmasq")
    subprocess.run(["pkill", "dnsmasq"])
    logging.info("Clearing dnsmasq leases")
    _shell_cmd("echo '' > /var/lib/misc/leases.conf")


def start_dnsmasq(orig_invoc: str) -> None:
    logging.info(f"Starting dnsmasq with '{orig_invoc}'")
    _shell_cmd(orig_invoc)


def _send_force_renew(iface: str, xid: int, dstmac: str, dstip: str) -> None:
    srcmac = netifaces.ifaddresses(iface)[netifaces.AF_PACKET][0]["addr"]
    dstmacbytes = binascii.unhexlify(dstmac.replace(":", ""))
    srcip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]["addr"]

    force_renew = (
        scapy.Ether(dst=dstmac, src=srcmac, type=0x0800)
        / scapy.IP(src=srcip, dst=dstip)
        / scapy.UDP(dport=68, sport=67)
        / scapy.BOOTP(op=2, chaddr=dstmacbytes, xid=xid)
        / scapy.DHCP(options=[("message-type", "force_renew"), ("server_id", srcip), ("end")])
    )

    scapy.sendp(force_renew, iface=iface, verbose=False)


def _wait_for_request(iface: str, xid: int, dstmac: str, dstip: str) -> None:
    dhcp_request = scapy.sniff(iface=iface, stop_filter=lambda x: x.haslayer(scapy.DHCP), quiet=True, timeout=3)

    if not dhcp_request:
        raise RuntimeError("Could not get DHCP FORCERENEW response")
    bootp = dhcp_request[-1].getlayer(scapy.BOOTP)
    dhcp = dhcp_request[-1].getlayer(scapy.DHCP)

    if ("message-type", 3) not in dhcp.fields["options"]:
        raise RuntimeError("Client response not DHCP REQUEST")

    if bootp.fields["xid"] != xid:
        raise RuntimeError(f"Client response does not match expected xid '0x{xid:08X}'")

    logging.info("Client response looks OK!")


def _nak_request(iface: str, xid: int, dstmac: str, dstip: str) -> None:
    srcmac = netifaces.ifaddresses(iface)[netifaces.AF_PACKET][0]["addr"]
    dstmacbytes = binascii.unhexlify(dstmac.replace(":", ""))
    srcip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]["addr"]

    nak = (
        scapy.Ether(dst=dstmac, src=srcmac, type=0x0800)
        / scapy.IP(src=srcip, dst=dstip)
        / scapy.UDP(dport=68, sport=67)
        / scapy.BOOTP(op=2, chaddr=dstmacbytes, xid=xid)
        / scapy.DHCP(options=[("message-type", "nak"), ("server_id", srcip), ("end")])
    )

    logging.info("Sending NAK for the previous request")

    scapy.sendp(nak, iface=iface, verbose=False)


def perform_force_renew(iface: str, xid: int, dstmac: str, dstip: str) -> None:
    _send_force_renew(iface, xid, dstmac, dstip)
    _wait_for_request(iface, xid, dstmac, dstip)
    _nak_request(iface, xid, dstmac, dstip)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--xid", type=int, default=0xDEADBEEF, help="XID of DHCP server")
    parser.add_argument("--iface", type=str, default="eth0", help="interface to send/receive from")
    parser.add_argument("dstmac", type=str, help="MAC address of FORCERENEW target")
    parser.add_argument("dstip", type=str, help="IP address of FORCERENEW target")

    return parser.parse_args()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    args = parse_args()

    dnsmasq_invocation = get_dnsmasq_invocation()
    shutdown_dnsmasq()

    perform_force_renew(args.iface, args.xid, args.dstmac, args.dstip)

    start_dnsmasq(dnsmasq_invocation)
