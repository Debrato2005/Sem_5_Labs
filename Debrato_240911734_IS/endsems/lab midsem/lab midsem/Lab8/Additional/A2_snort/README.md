# Lab 8 – Additional 2: Snort as a Network Intrusion Detection System (Linux)

Snort is a separate program, not a Python library. Install it **before** the internet is cut:

```bash
sudo apt update && sudo apt install snort     # asks for HOME_NET, e.g. 192.168.1.0/24
snort -V                                      # check it works (Ubuntu ships Snort 2.9)
```
Fedora/RHEL: `sudo dnf install snort`.

## 1. Find your interface and network
```bash
ip a              # interface name: eth0 / enp0s3 / ens33 / wlan0, and your IP/subnet
```
Below, replace `eth0` with your interface.

## 2. Add the rules
```bash
sudo cp local.rules /etc/snort/rules/local.rules
sudo nano /etc/snort/snort.conf
#   set:     ipvar HOME_NET 192.168.1.0/24
#   check:   include $RULE_PATH/local.rules      (is present / not commented out)
```

## 3. Test the configuration
```bash
sudo snort -T -c /etc/snort/snort.conf
```

## 4. Capture and monitor live traffic
```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0        # alerts on screen
sudo snort -A fast -c /etc/snort/snort.conf -i eth0 -l ./logs    # alerts to ./logs/alert
sudo snort -dev -i eth0 -l ./logs                                # packet logger mode (pcap)
sudo snort -r ./logs/snort.log.* -c /etc/snort/snort.conf -A console   # replay a capture
```
Default log folder is `/var/log/snort/` (alerts in `/var/log/snort/alert`).
Snort 3: `sudo snort -c /usr/local/etc/snort/snort.lua -R local.rules -i eth0 -A alert_fast`.

## 5. Generate traffic that fires the rules (from another machine/terminal)
```bash
ping <target-ip>                                   # rule 1000001
nc -zv <target-ip> 20-100                          # SYN scan, rules 1000002/4
curl "http://<target-ip>/?q=1%20union%20select%201"  # rule 1000005
curl "http://<target-ip>/../../etc/passwd"         # rule 1000006
```
(Testing on one PC: use `-i lo` and target `127.0.0.1`, with `HOME_NET any`.)

## 6. Analyse the logs
```bash
sudo chmod -R a+r ./logs                      # Snort writes logs as root
python3 analyze_alerts.py ./logs/alert       # or with no argument to use sample_alert.log
```

## Rule anatomy (for the viva)
`alert tcp any any -> $HOME_NET 22 (msg:"SSH attempt"; flags:S; sid:1000002; rev:1;)`
action · protocol · source IP/port · direction · destination IP/port · options
(`msg` text, `content` payload match, `flags` TCP flags, `sid` ≥ 1000000 for local rules).
