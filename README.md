Overview

This project automates the parsing, validation, and simulation of Cisco router configurations.
It provides automated network topology generation, validation checks, load analysis, and simulation scenarios.

Features

Parse Cisco configuration files (config.dump) to auto-generate topology

Validate network (duplicate IPs, MTU mismatches, missing peers, loops)

Evaluate link utilization and provide load-balancing recommendations

Simulate Day-1 discovery (ARP/ND, OSPF Hello) and Day-2 link failures

Generate detailed reports

Requirements

Python 3.10+

Install dependencies:

pip install networkx

File Structure
nettool.py                          # Main Python script
configs/Conf/<Router>/config.dump   # Router configuration files
report.txt                          # Generated report
endpoints.yaml                      # (Optional) Endpoint traffic specification

Usage

Run the tool with the following options:

Example 1: Day-1 Discovery
python nettool.py --confdir ./configs --simulate day1 --report report.txt

Example 2: Day-2 Link Failure
python nettool.py --confdir ./configs --simulate day2 --fail-link R1:Gi0/1 --report report.txt

Example 3: Only Validation and Report
python nettool.py --confdir ./configs --report report.txt

Output

The generated report.txt contains:

Topology summary (nodes, links, bandwidth, MTU)

Validation results (issues if any)

Load utilization and recommendations

Link utilization statistics

Example Result
=== Topology Summary ===
Nodes: 2, Links: 1
 - R1<->R2 bw=1000Mbps mtu=(1500, 1500)

=== Validation Issues ===
No issues detected.

=== Load & Recommendations ===
No overutilized links detected.

=== Link Utilization (fraction of capacity) ===
 R1<->R2: 0.02
