#!/usr/bin/env python3
"""Config documents for the TUN benchmark.

Constants match crates/segue-bench/src/lib.rs (the 2026-11-17 / 2026-11-18
SOCKS comparison) so the TUN path speaks the same VLESS. The Xray
freedom outbound redirects every accepted flow to the local sink; the
client dials the documentation address 198.51.100.20, which is not on
this machine. REALITY's fallback `dest` is that same sink, not
www.google.com:443, so a non-REALITY probe cannot leave the VM.
"""

from __future__ import annotations

import argparse
import json
import sys

# crates/segue-bench/src/lib.rs
UUID = "00010203-0405-0607-0809-0a0b0c0d0e0f"
REALITY_SERVER_NAME = "www.google.com"
REALITY_PRIVATE_KEY = "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks"
REALITY_PUBLIC_KEY = "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM"
REALITY_SHORT_ID = "0123456789abcdef"
GRPC_SERVICE = "bench"

FAKE_IP = "198.51.100.20"
SINK = "127.0.0.1:5001"


def _reality_user():
    return {
        "id": UUID,
        "encryption": "none",
        "flow": "xtls-rprx-vision",
    }


def _grpc_user():
    return {"id": UUID, "encryption": "none"}


def xray_server(reality_port: int, grpc_port: int, sink: str = SINK) -> str:
    return _dump(
        {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": reality_port,
                    "protocol": "vless",
                    "tag": "reality-in",
                    "settings": {
                        "clients": [
                            {"id": UUID, "flow": "xtls-rprx-vision"}
                        ],
                        "decryption": "none",
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "show": False,
                            "dest": sink,
                            "serverNames": [REALITY_SERVER_NAME],
                            "privateKey": REALITY_PRIVATE_KEY,
                            "shortIds": [REALITY_SHORT_ID],
                            "type": "tcp",
                        },
                    },
                },
                {
                    "listen": "127.0.0.1",
                    "port": grpc_port,
                    "protocol": "vless",
                    "tag": "grpc-in",
                    "settings": {
                        "clients": [{"id": UUID}],
                        "decryption": "none",
                    },
                    "streamSettings": {
                        "network": "grpc",
                        "security": "none",
                        "grpcSettings": {"serviceName": GRPC_SERVICE},
                    },
                },
            ],
            "outbounds": [
                {
                    "protocol": "freedom",
                    "tag": "direct",
                    "settings": {
                        "redirect": sink,
                        "finalRules": [{"action": "allow"}],
                    },
                }
            ],
        }
    )


def _xray_outbound(protocol: str, port: int) -> dict:
    if protocol == "reality":
        return {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "127.0.0.1",
                        "port": port,
                        "users": [_reality_user()],
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": REALITY_SERVER_NAME,
                    "fingerprint": "chrome",
                    "publicKey": REALITY_PUBLIC_KEY,
                    "shortId": REALITY_SHORT_ID,
                    "spiderX": "/",
                },
            },
        }
    if protocol == "grpc":
        # No flow. Xray rejects xtls-rprx-vision unless the inner conn is
        # TLS or REALITY; h2c gRPC is neither. serviceName has no leading
        # slash so sing-box lite and Xray agree on "/bench/Tun".
        return {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "127.0.0.1",
                        "port": port,
                        "users": [_grpc_user()],
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "security": "none",
                "grpcSettings": {"serviceName": GRPC_SERVICE},
            },
        }
    raise SystemExit("unknown protocol {0}".format(protocol))


def kernel_config(protocol: str, port: int, listen: str = "127.0.0.1:10808") -> str:
    """Lab inline rules. Only the documentation address is proxied.

    `ipv6` is false so the kernel does not install ::/1 and 8000::/1.
    Loopback is not given a host route; the carrier dial stays on lo0.
    """
    return _dump(
        {
            "listen": listen,
            "outbounds": {"proxy": _xray_outbound(protocol, port)},
            "rules": [
                {
                    "ip_cidr": FAKE_IP + "/32",
                    "action": {"type": "proxy", "outbound": "proxy"},
                }
            ],
            "default": {"type": "direct"},
            "tun": {
                "mtu": 1500,
                "ipv4": "172.19.0.1/30",
                "ipv4_peer": "172.19.0.2",
                "ipv6": False,
            },
        }
    )


def singbox_config(protocol: str, port: int) -> str:
    if protocol == "reality":
        proxy = {
            "type": "vless",
            "tag": "proxy",
            "server": "127.0.0.1",
            "server_port": port,
            "uuid": UUID,
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": True,
                "server_name": REALITY_SERVER_NAME,
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": REALITY_PUBLIC_KEY,
                    "short_id": REALITY_SHORT_ID,
                },
            },
        }
    elif protocol == "grpc":
        proxy = {
            "type": "vless",
            "tag": "proxy",
            "server": "127.0.0.1",
            "server_port": port,
            "uuid": UUID,
            "transport": {"type": "grpc", "service_name": GRPC_SERVICE},
        }
    else:
        raise SystemExit("unknown protocol {0}".format(protocol))
    return _dump(
        {
            "log": {"level": "warn"},
            "inbounds": [
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "address": ["172.19.0.1/30"],
                    "mtu": 1500,
                    "auto_route": True,
                    "strict_route": False,
                    "dns_mode": "disabled",
                    "route_exclude_address": ["127.0.0.0/8", "::1/128"],
                }
            ],
            "outbounds": [proxy, {"type": "direct", "tag": "direct"}],
            "route": {
                "auto_detect_interface": True,
                "rules": [
                    {"ip_cidr": [FAKE_IP + "/32"], "outbound": "proxy"}
                ],
                "final": "direct",
            },
        }
    )


def mihomo_config(protocol: str, stack: str, port: int) -> str:
    if stack not in ("system", "mixed"):
        raise SystemExit("mihomo stack must be system or mixed")
    if protocol == "reality":
        proxy = """
  - name: proxy
    type: vless
    server: 127.0.0.1
    port: {port}
    uuid: {uuid}
    network: tcp
    udp: false
    flow: xtls-rprx-vision
    tls: true
    servername: {sni}
    client-fingerprint: chrome
    reality-opts:
      public-key: {public}
      short-id: {short}
      support-x25519mlkem768: true
""".format(
            port=port,
            uuid=UUID,
            sni=REALITY_SERVER_NAME,
            public=REALITY_PUBLIC_KEY,
            short=REALITY_SHORT_ID,
        )
    elif protocol == "grpc":
        proxy = """
  - name: proxy
    type: vless
    server: 127.0.0.1
    port: {port}
    uuid: {uuid}
    network: grpc
    udp: false
    tls: false
    grpc-opts:
      grpc-service-name: {service}
""".format(
            port=port, uuid=UUID, service=GRPC_SERVICE
        )
    else:
        raise SystemExit("unknown protocol {0}".format(protocol))
    # parseTun derives the utun address from dns.fake-ip-range as a /30
    # (198.18.0.1/30). inet4-address in this file would be overwritten.
    # dns-hijack is an empty list so the 0.0.0.0:53 default does not apply.
    return (
        "mixed-port: 17890\n"
        "allow-lan: false\n"
        "bind-address: 127.0.0.1\n"
        "mode: rule\n"
        "log-level: warning\n"
        "find-process-mode: off\n"
        "ipv6: false\n"
        "geo-auto-update: false\n"
        "dns:\n"
        "  enable: false\n"
        "  fake-ip-range: 198.18.0.1/16\n"
        "tun:\n"
        "  enable: true\n"
        "  stack: {stack}\n"
        "  auto-route: true\n"
        "  auto-detect-interface: true\n"
        "  strict-route: false\n"
        "  mtu: 1500\n"
        "  dns-hijack: []\n"
        "  route-exclude-address:\n"
        "    - 127.0.0.0/8\n"
        '    - "::1/128"\n'
        "proxies:\n"
        "{proxy}"
        "rules:\n"
        "  - IP-CIDR,{fake}/32,proxy,no-resolve\n"
        "  - MATCH,DIRECT\n"
    ).format(stack=stack, proxy=proxy, fake=FAKE_IP)


def _dump(value) -> str:
    return json.dumps(value, indent=2) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="write TUN benchmark configs")
    sub = parser.add_subparsers(dest="cmd", required=True)
    server = sub.add_parser("xray-server")
    server.add_argument("--reality-port", type=int, required=True)
    server.add_argument("--grpc-port", type=int, required=True)
    server.add_argument("--sink", default=SINK)
    kernel = sub.add_parser("kernel")
    kernel.add_argument("--protocol", required=True)
    kernel.add_argument("--port", type=int, required=True)
    kernel.add_argument("--listen", default="127.0.0.1:10808")
    sing = sub.add_parser("sing-box")
    sing.add_argument("--protocol", required=True)
    sing.add_argument("--port", type=int, required=True)
    mihomo = sub.add_parser("mihomo")
    mihomo.add_argument("--protocol", required=True)
    mihomo.add_argument("--stack", required=True)
    mihomo.add_argument("--port", type=int, required=True)
    args = parser.parse_args(argv)
    if args.cmd == "xray-server":
        sys.stdout.write(xray_server(args.reality_port, args.grpc_port, args.sink))
    elif args.cmd == "kernel":
        sys.stdout.write(kernel_config(args.protocol, args.port, args.listen))
    elif args.cmd == "sing-box":
        sys.stdout.write(singbox_config(args.protocol, args.port))
    else:
        sys.stdout.write(mihomo_config(args.protocol, args.stack, args.port))
    return 0


if __name__ == "__main__":
    sys.exit(main())
