#!/usr/bin/env python3
"""
Cisco Networking Industry Problem Statement – Reference Implementation Scaffold
-----------------------------------------------------------------------------
This single-file Python scaffold helps you build a working solution that:
  1) Parses router config files and auto-generates a hierarchical network topology
  2) Validates configuration and topology (duplicate IPs, MTU mismatch, missing peers, loops)
  3) Estimates link load vs capacity and recommends load-balancing
  4) Runs Day-1 discovery simulation (ARP/ND, OSPF-hello) and Day-2 link-failure scenarios
  5) Uses multithreading to represent routers/switches and IPC (Queues) for metadata exchange

Notes
-----
• Keep the file in your project root as `nettool.py`. 
• Create a folder `configs/Conf/<RouterName>/config.dump` and copy your configs there.
• Optional: create `endpoints.yaml` to list endpoints and expected traffic loads.
• Requires Python 3.10+ and the `networkx` library.

Run Examples
------------
$ python nettool.py --confdir ./configs \
    --simulate day1 \
    --report report.txt

$ python nettool.py --confdir ./configs \
    --simulate day2 \
    --fail-link R1:Gi0/1 \
    --report report.txt
"""
from __future__ import annotations
import argparse
import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from queue import Queue
from typing import Dict, List, Optional, Tuple, Set

try:
    import networkx as nx
except ImportError as e:
    print("This tool requires the 'networkx' package. Install with: pip install networkx", file=sys.stderr)
    raise

# ------------------------------
# Data Models
# ------------------------------

@dataclass
class Interface:
    name: str
    ip: Optional[str] = None
    mask: Optional[str] = None
    vlan: Optional[str] = None
    bandwidth_mbps: Optional[int] = None
    mtu: Optional[int] = None
    peer_device: Optional[str] = None
    peer_if: Optional[str] = None

@dataclass
class Device:
    name: str
    role: str
    interfaces: Dict[str, Interface] = field(default_factory=dict)
    protocols: Set[str] = field(default_factory=set)

    def add_interface(self, iface: Interface) -> None:
        self.interfaces[iface.name] = iface

@dataclass
class Link:
    a_dev: str
    a_if: str
    b_dev: str
    b_if: str
    bandwidth_mbps: int
    mtu_pair: Tuple[Optional[int], Optional[int]]

# ------------------------------
# Parser
# ------------------------------

HOST_RE = re.compile(r"^hostname\s+(?P<host>\S+)")
ROLE_RE = re.compile(r"^role\s+(?P<role>\S+)")
IF_RE = re.compile(r"^interface\s+(?P<if>\S+)")
IP_RE = re.compile(r"^\s*ip address\s+(?P<ip>\S+)\s+(?P<mask>\S+)")
VLAN_RE = re.compile(r"^\s*vlan\s+(?P<vlan>\S+)")
BW_RE = re.compile(r"^\s*bandwidth\s+(?P<bw>\d+)")
MTU_RE = re.compile(r"^\s*mtu\s+(?P<mtu>\d+)")
DESC_RE = re.compile(r"^\s*description\s+LINK:(?P<peer>[^:]+):(?P<pif>\S+)")
OSPF_RE = re.compile(r"^router\s+ospf")
BGP_RE = re.compile(r"^router\s+bgp")

class ConfigParser:
    def __init__(self, confdir: str):
        self.confdir = confdir

    def parse(self) -> Dict[str, Device]:
        devices: Dict[str, Device] = {}
        root = os.path.abspath(self.confdir)
        if not os.path.isdir(root):
            raise FileNotFoundError(f"Config directory not found: {root}")

        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                if not fn.endswith('.dump'):
                    continue
                fpath = os.path.join(dirpath, fn)
                dev = self._parse_file(fpath)
                devices[dev.name] = dev
        return devices

    def _parse_file(self, path: str) -> Device:
        hostname = None
        role = 'router'
        cur_if: Optional[Interface] = None
        interfaces: Dict[str, Interface] = {}
        protocols: Set[str] = set()

        with open(path, 'r', encoding='utf-8') as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue

                if m := HOST_RE.match(line):
                    hostname = m.group('host')
                    continue
                if m := ROLE_RE.match(line):
                    role = m.group('role').lower()
                    continue
                if m := IF_RE.match(line):
                    if cur_if is not None:
                        interfaces[cur_if.name] = cur_if
                    cur_if = Interface(name=m.group('if'))
                    continue
                if m := IP_RE.match(line):
                    if cur_if:
                        cur_if.ip = m.group('ip')
                        cur_if.mask = m.group('mask')
                    continue
                if m := VLAN_RE.match(line):
                    if cur_if:
                        cur_if.vlan = m.group('vlan')
                    continue
                if m := BW_RE.match(line):
                    if cur_if:
                        cur_if.bandwidth_mbps = int(m.group('bw'))
                    continue
                if m := MTU_RE.match(line):
                    if cur_if:
                        cur_if.mtu = int(m.group('mtu'))
                    continue
                if m := DESC_RE.match(line):
                    if cur_if:
                        cur_if.peer_device = m.group('peer')
                        cur_if.peer_if = m.group('pif')
                    continue
                if OSPF_RE.match(line):
                    protocols.add('OSPF')
                    continue
                if BGP_RE.match(line):
                    protocols.add('BGP')
                    continue

        if cur_if is not None:
            interfaces[cur_if.name] = cur_if
        if not hostname:
            raise ValueError(f"Missing hostname in config: {path}")
        return Device(name=hostname, role=role, interfaces=interfaces, protocols=protocols)

# ------------------------------
# Topology
# ------------------------------

class Topology:
    def __init__(self, devices: Dict[str, Device]):
        self.devices = devices
        self.graph = nx.Graph()
        self.links: List[Link] = []

    def build(self) -> None:
        for d in self.devices.values():
            self.graph.add_node(d.name, role=d.role, protocols=','.join(sorted(d.protocols)))
        for d in self.devices.values():
            for iface in d.interfaces.values():
                if iface.peer_device and iface.peer_if:
                    if self._link_exists(d.name, iface.name, iface.peer_device, iface.peer_if):
                        continue
                    bw = iface.bandwidth_mbps or 100
                    peer = self._find_peer_interface(iface.peer_device, iface.peer_if)
                    mtu_pair = (iface.mtu, peer.mtu if peer else None)
                    link = Link(d.name, iface.name, iface.peer_device, iface.peer_if, bw, mtu_pair)
                    self.links.append(link)
                    eff_bw = min(bw, (peer.bandwidth_mbps or bw) if peer else bw)
                    self.graph.add_edge(d.name, iface.peer_device,
                                        a_if=iface.name, b_if=iface.peer_if,
                                        bandwidth_mbps=eff_bw, mtu_pair=mtu_pair)

    def _link_exists(self, a_dev: str, a_if: str, b_dev: str, b_if: str) -> bool:
        for L in self.links:
            if {L.a_dev, L.b_dev} == {a_dev, b_dev} and {L.a_if, L.b_if} == {a_if, b_if}:
                return True
        return False

    def _find_peer_interface(self, dev: str, ifname: str) -> Optional[Interface]:
        D = self.devices.get(dev)
        if not D:
            return None
        return D.interfaces.get(ifname)

# ------------------------------
# Validation & Load
# ------------------------------

class Validator:
    def __init__(self, topo: Topology):
        self.topo = topo
        self.issues: List[str] = []

    def run_all(self) -> List[str]:
        self.issues.clear()
        self._check_missing_components()
        self._check_duplicate_ips()
        self._check_mtu_mismatch()
        self._check_loops()
        self._check_gateway_placeholders()
        return self.issues

    def _check_missing_components(self) -> None:
        for d in self.topo.devices.values():
            for iface in d.interfaces.values():
                if iface.peer_device and iface.peer_device not in self.topo.devices:
                    self.issues.append(f"Missing peer device config: {d.name}.{iface.name} -> {iface.peer_device}")

    def _check_duplicate_ips(self) -> None:
        ip_map: Dict[str, List[str]] = {}
        for d in self.topo.devices.values():
            for iface in d.interfaces.values():
                if iface.ip:
                    key = f"{iface.vlan or 'no-vlan'}:{iface.ip}"
                    ip_map.setdefault(key, []).append(f"{d.name}.{iface.name}")
        for key, owners in ip_map.items():
            if len(owners) > 1:
                self.issues.append(f"Duplicate IP within VLAN ({key}) used by {owners}")

    def _check_mtu_mismatch(self) -> None:
        for (u, v, data) in self.topo.graph.edges(data=True):
            m1, m2 = data.get('mtu_pair', (None, None))
            if m1 and m2 and m1 != m2:
                self.issues.append(f"MTU mismatch on link {u}<->{v}: {m1} vs {m2}")

    def _check_loops(self) -> None:
        try:
            cycles = list(nx.cycle_basis(self.topo.graph))
            for cyc in cycles:
                if len(cyc) >= 3:
                    self.issues.append(f"Potential layer-2/3 loop (cycle): {' -> '.join(cyc)}")
        except Exception:
            pass

    def _check_gateway_placeholders(self) -> None:
        vlan_gateways: Dict[str, List[Tuple[str, str]]] = {}
        for d in self.topo.devices.values():
            for iface in d.interfaces.values():
                if iface.vlan and iface.ip and iface.ip.endswith('.1'):
                    vlan_gateways.setdefault(iface.vlan, []).append((d.name, iface.name))
        for vlan, lst in vlan_gateways.items():
            if len(lst) > 1:
                self.issues.append(
                    f"Multiple '.1' gateway-looking IPs in VLAN {vlan}: {lst} (check gateway assignments)")

class LoadAdvisor:
    def __init__(self, topo: Topology, endpoints: Optional[Dict[str, Dict]] = None):
        self.topo = topo
        self.endpoints = endpoints or {}

    def evaluate(self) -> Tuple[List[str], Dict[Tuple[str, str], float]]:
        demands = self._synthetic_demands()
        util: Dict[Tuple[str, str], float] = {}
        for (src, dst, mbps) in demands:
            try:
                path = nx.shortest_path(self.topo.graph, src, dst)
            except nx.NetworkXNoPath:
                continue
            for i in range(len(path)-1):
                u, v = path[i], path[i+1]
                data = self.topo.graph.get_edge_data(u, v)
                cap = max(1, int(data.get('bandwidth_mbps', 100)))
                util[(u, v)] = util.get((u, v), 0.0) + mbps / cap
                util[(v, u)] = util.get((v, u), 0.0) + mbps / cap
        recs: List[str] = []
        for (u, v), frac in util.items():
            if u < v:
                if frac > 1.0:
                    recs.append(
                        f"Overutilized link {u}<->{v} at {frac*100:.1f}% of capacity. Recommend secondary path or ECMP.")
        return recs, util

    def _synthetic_demands(self) -> List[Tuple[str, str, float]]:
        if self.endpoints:
            demands = []
            for name, spec in self.endpoints.items():
                src = spec.get('attach')
                dst = spec.get('to')
                mbps = float(spec.get('mbps', 10))
                demands.append((src, dst, mbps))
            return demands
        nodes = sorted(self.topo.graph.nodes())
        if len(nodes) < 2:
            return []
        dst = nodes[-1]
        demands: List[Tuple[str, str, float]] = []
        for n in nodes[:-1]:
            demands.append((n, dst, 20.0))
        return demands

# ------------------------------
# Multithreaded Simulation
# ------------------------------

class Message:
    def __init__(self, src: str, dst: Optional[str], kind: str, payload: dict):
        self.src = src
        self.dst = dst
        self.kind = kind
        self.payload = payload

class NodeThread(threading.Thread):
    def __init__(self, name: str, topo: Topology, inbox: Queue, outboxes: Dict[str, Queue], stop_flag: threading.Event):
        super().__init__(daemon=True)
        self.name = name
        self.topo = topo
        self.inbox = inbox
        self.outboxes = outboxes
        self.stop_flag = stop_flag

    def run(self):
        while not self.stop_flag.is_set():
            try:
                msg: Message = self.inbox.get(timeout=0.2)
            except Exception:
                continue
            self.process_message(msg)  # renamed

    def _neighbors(self) -> List[str]:
        return list(self.topo.graph.neighbors(self.name)) if self.name in self.topo.graph else []

    def _broadcast(self, kind: str, payload: dict):
        for nb in self._neighbors():
            self._send(nb, kind, payload)

    def _send(self, dst: str, kind: str, payload: dict):
        if dst in self.outboxes:
            self.outboxes[dst].put(Message(self.name, dst, kind, payload))

    def process_message(self, msg: Message):
        if msg.kind == 'DAY1_BOOT':
            self._broadcast('ARP', {"who": self.name})
            if 'OSPF' in self.topo.graph.nodes[self.name].get('protocols', ''):
                self._broadcast('OSPF_HELLO', {"from": self.name})
        elif msg.kind in ('ARP', 'OSPF_HELLO'):
            if msg.src in self._neighbors():
                self._send(msg.src, 'ACK', {"to": msg.src, "from": self.name, "kind": msg.kind})
        elif msg.kind == 'LINK_DOWN':
            pass

class Simulator:
    def __init__(self, topo: Topology):
        self.topo = topo
        self.threads: Dict[str, NodeThread] = {}
        self.mailboxes: Dict[str, Queue] = {}
        self.stop_flag = threading.Event()

    def start(self):
        for n in self.topo.graph.nodes():
            q = Queue()
            self.mailboxes[n] = q
        for n in self.topo.graph.nodes():
            t = NodeThread(n, self.topo, self.mailboxes[n], self.mailboxes, self.stop_flag)
            self.threads[n] = t
            t.start()

    def stop(self):
        self.stop_flag.set()
        for t in self.threads.values():
            t.join(timeout=0.5)

    def day1_boot(self):
        for n in self.topo.graph.nodes():
            self.mailboxes[n].put(Message('controller', n, 'DAY1_BOOT', {}))

    def fail_link(self, spec: str):
        try:
            dev, ifname = spec.split(':', 1)
        except ValueError:
            print(f"Invalid --fail-link format. Use Device:IfName, e.g., R1:Gi0/1")
            return
        remove: List[Tuple[str, str]] = []
        for u, v, data in self.topo.graph.edges(data=True):
            if (u == dev and data.get('a_if') == ifname) or (v == dev and data.get('b_if') == ifname):
                remove.append((u, v))
        for (u, v) in remove:
            if self.topo.graph.has_edge(u, v):
                self.topo.graph.remove_edge(u, v)
                if u in self.mailboxes:
                    self.mailboxes[u].put(Message('controller', u, 'LINK_DOWN', {"peer": v}))
                if v in self.mailboxes:
                    self.mailboxes[v].put(Message('controller', v, 'LINK_DOWN', {"peer": u}))
        if not remove:
            print(f"No link matched for failure spec: {spec}")

# ------------------------------
# Reporting
# ------------------------------

def write_report(path: Optional[str], topo: Topology, issues: List[str], recs: List[str], util: Dict[Tuple[str, str], float]):
    out = []
    out.append("=== Topology Summary ===")
    out.append(f"Nodes: {len(topo.graph.nodes())}, Links: {len(topo.graph.edges())}")
    for u, v, data in topo.graph.edges(data=True):
        out.append(f" - {u}<->{v} bw={data.get('bandwidth_mbps','?')}Mbps mtu={data.get('mtu_pair')}")

    out.append("\n=== Validation Issues ===")
    if not issues:
        out.append("No issues detected.")
    else:
        out.extend([f" - {x}" for x in issues])

    out.append("\n=== Load & Recommendations ===")
    if not recs:
        out.append("No overutilized links detected.")
    else:
        out.extend([f" - {r}" for r in recs])

    out.append("\n=== Link Utilization (fraction of capacity) ===")
    for (u, v), frac in sorted(util.items()):
        if u < v:
            out.append(f" {u}<->{v}: {frac:.2f}")

    text = "\n".join(out)
    if path:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f"Report written to {path}")
    else:
        print(text)

# ------------------------------
# CLI
# ------------------------------

def load_endpoints_yaml(path: str) -> Optional[Dict[str, Dict]]:
    if not os.path.isfile(path):
        return None
    try:
        import json
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if content.startswith('{'):
                return json.loads(content)
        out: Dict[str, Dict] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            key, rhs = line.split(':', 1)
            key = key.strip()
            rhs = rhs.strip()
            if rhs.startswith('{') and rhs.endswith('}'):
                rhs = rhs[1:-1]
                kv = {}
                for pair in rhs.split(','):
                    if not pair.strip():
                        continue
                    k, v = pair.split(':', 1)
                    kv[k.strip()] = v.strip()
                out[key] = kv
        return out
    except Exception as e:
        print(f"Failed to parse endpoints.yaml: {e}")
        return None

def main():
    ap = argparse.ArgumentParser(description="Cisco Networking Problem – Auto Topology, Validation, Optimization & Simulation")
    ap.add_argument('--confdir', required=True, help='Root directory containing Conf/<Device>/config.dump files')
    ap.add_argument('--simulate', choices=['none', 'day1', 'day2'], default='none', help='Run discovery/failure simulations')
    ap.add_argument('--fail-link', dest='fail_link', default=None, help='Device:Interface to fail for day2')
    ap.add_argument('--report', default=None, help='Write a text report to this path')
    ap.add_argument('--endpoints', default='endpoints.yaml', help='Optional endpoints YAML/JSON for load analysis')

    args = ap.parse_args()

    parser = ConfigParser(args.confdir)
    devices = parser.parse()

    topo = Topology(devices)
    topo.build()

    validator = Validator(topo)
    issues = validator.run_all()

    endpoints = load_endpoints_yaml(args.endpoints)
    advisor = LoadAdvisor(topo, endpoints)
    recs, util = advisor.evaluate()

    if args.simulate != 'none':
        sim = Simulator(topo)
        sim.start()
        try:
            if args.simulate == 'day1':
                print('[SIM] Day-1 boot: ARP/ND and OSPF hellos...')
                sim.day1_boot()
                time.sleep(1.0)
            elif args.simulate == 'day2':
                print('[SIM] Day-2 link failure scenario...')
                if args.fail_link:
                    sim.fail_link(args.fail_link)
                sim.day1_boot()
                time.sleep(1.0)
        finally:
            sim.stop()

    write_report(args.report, topo, issues, recs, util)

if __name__ == '__main__':
    main()
