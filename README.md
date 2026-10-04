# ingressd

ingressd is a passive intrusion detection daemon for Linux servers and cloud VMs
(AWS, GCP, Azure). It watches inbound traffic from globally routable IP addresses
and alerts on hostile behavior: port scans, SSH/RDP brute force, SYN/UDP/ICMP
floods, reflection and amplification, DNS and ICMP tunneling, and contact with
known-bad IPs from threat-intelligence feeds.

- Public-source filtering: private, CGNAT, link-local and reserved ranges are skipped
- Behavioral detection with bounded memory, safe against spoofed-source floods
- MITRE ATT&CK-tagged JSONL alerts, Prometheus metrics, webhook and syslog sinks
- Pcap replay mode for testing and tuning without privileges
- Optional, opt-in blocking through nftables (dry-run by default)
- Runs as an unprivileged service with only CAP_NET_RAW

ingressd never injects packets and never scans other hosts. Deploy it only on
infrastructure you own or are authorized to monitor.
