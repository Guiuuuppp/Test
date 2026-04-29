#!/bin/sh
###############################################################################
# OPNsense CLI Audit & Hardening Cheat Sheet
#
# Read-only audit commands and (clearly marked) write/hardening commands for
# an OPNsense firewall. Run via SSH or Interfaces -> Diagnostics -> Command
# Prompt. Most "set" commands are runtime-only -- persist them in the GUI
# (System -> Settings -> Tunables, Interface MSS, etc.) or they will be
# overwritten when configd regenerates /etc/sysctl.conf and pf.conf.
#
# Convention:
#   [AUDIT] safe, read-only
#   [SET]   modifies running state (runtime only unless persisted)
#   [PERSIST] writes to disk / config
#   [DANGER] disruptive -- read before running
###############################################################################


###############################################################################
# 0. QUICK ONE-SHOT HEALTH SUMMARY                                  [AUDIT]
###############################################################################
quick_summary() {
    echo "=== Hostname / version ===";   hostname; opnsense-version
    echo "=== Uptime / load ===";        uptime
    echo "=== PF debug level ===";       sysctl net.pf.debug
    echo "=== Hardening sysctls ===";    sysctl \
        net.inet.tcp.blackhole net.inet.udp.blackhole \
        net.inet.ip.random_id net.inet.icmp.drop_redirect \
        net.inet.tcp.drop_synfin net.inet.ip.redirect \
        net.inet.tcp.syncookies
    echo "=== Scrub rules ===";          pfctl -sr | grep -i scrub
    echo "=== PF info ===";              pfctl -s info | head -20
    echo "=== State count ===";          pfctl -s state | wc -l
    echo "=== Listening v4 ===";         sockstat -4l
    echo "=== SSH cfg ===";              sshd -T 2>/dev/null | \
        grep -Ei 'permitroot|passwordauth|port |pubkey|listenaddress'
    echo "=== Updates ===";              opnsense-update -c
    echo "=== pkg audit ===";            pkg audit -F | tail -5
}


###############################################################################
# 1. NORMALIZATION / SCRUB / FRAGMENT REASSEMBLY                    [AUDIT]
###############################################################################
pfctl -sr | grep -i scrub                       # active scrub rules
pfctl -s memory | grep -i frag                  # fragment table usage
pfctl -s info  | grep -iE 'fragment|state|debug'
pfctl -s Anchors                                # any nested anchors?


###############################################################################
# 2. PF DEBUG / LOGGING LEVEL                                       [AUDIT/SET]
###############################################################################
# Levels: 0 none, 1 urgent, 2 notice, 3 misc, 4 loud, 5 noisy
sysctl net.pf.debug                             # [AUDIT]
pfctl -x                                        # [AUDIT] symbolic form

sysctl net.pf.debug=1                           # [SET] runtime
pfctl -x urgent                                 # [SET] equivalent

# [PERSIST] add via GUI Tunables OR:
#   echo 'net.pf.debug=1' >> /etc/sysctl.conf

# Watch logs to confirm the spam stopped
clog -f /var/log/system/latest.log | grep pf_   # [AUDIT]
tail -f /var/log/filter/latest.log              # [AUDIT]


###############################################################################
# 3. KERNEL / NETWORK HARDENING SYSCTLS                             [AUDIT/SET]
###############################################################################
# [AUDIT] dump current values
sysctl \
    net.inet.tcp.blackhole \
    net.inet.udp.blackhole \
    net.inet.ip.random_id \
    net.inet.icmp.drop_redirect \
    net.inet.tcp.drop_synfin \
    net.inet.ip.redirect \
    net.inet.tcp.syncookies \
    net.inet6.icmp6.nodeinfo \
    net.inet6.ip6.redirect \
    net.inet.icmp.bmcastecho \
    net.inet.icmp.maskrepl \
    net.inet.tcp.icmp_may_rst \
    net.pf.debug

# [SET] runtime hardening (persist in GUI Tunables)
sysctl net.inet.tcp.blackhole=2                 # silently drop closed TCP
sysctl net.inet.udp.blackhole=1                 # silently drop closed UDP
sysctl net.inet.ip.random_id=1                  # randomize IP id
sysctl net.inet.icmp.drop_redirect=1            # ignore ICMP redirects
sysctl net.inet.tcp.drop_synfin=1               # drop SYN+FIN
sysctl net.inet.ip.redirect=0                   # do not send ICMP redirects
sysctl net.inet6.ip6.redirect=0                 # same for v6
sysctl net.inet.tcp.syncookies=1                # SYN flood protection
sysctl net.inet.icmp.bmcastecho=0               # ignore broadcast ping
sysctl net.inet.icmp.maskrepl=0                 # no ICMP mask replies


###############################################################################
# 4. FIREWALL RULESET / NAT / STATE                                 [AUDIT]
###############################################################################
pfctl -s rules                                  # all active filter rules
pfctl -s nat                                    # NAT rules
pfctl -s state | wc -l                          # state count
pfctl -s state | head                           # sample states
pfctl -s info                                   # global counters
pfctl -s timeouts                               # state timeouts
pfctl -s labels                                 # rule hit counters
pfctl -s Tables                                 # tables (aliases, bogons)
pfctl -t bogons     -T show | head              # IPv4 bogons populated?
pfctl -t bogonsv6   -T show | head              # IPv6 bogons populated?
pfctl -vsr | grep -E 'block|drop' | head -50    # block-rule hits
pfctl -ss | awk '{print $1}' | sort | uniq -c | sort -rn | head  # state breakdown

# Look in `pfctl -s info` for non-zero: memory, state-mismatch, bad-offset, short
# Those indicate dropped/malformed traffic worth investigating.


###############################################################################
# 5. BOGONS / WAN BLOCK VERIFICATION                                [AUDIT]
###############################################################################
grep -i bogon /var/log/system/latest.log
ls -l /usr/local/etc/bogons*
pfctl -sr | grep -iE 'block.*(bogons|rfc1918|private)'


###############################################################################
# 6. INTERFACES / MTU / MSS CLAMPING                                [AUDIT]
###############################################################################
ifconfig -a | grep -E 'flags|mtu|inet '
ifconfig                                        # full detail
ifconfig | grep -E 'wg|ipsec|gif|tun|pppoe'     # tunnels & PPPoE
netstat -rn4 | head -20                         # IPv4 routing table
netstat -rn6 | head -20                         # IPv6 routing table
pfctl -sr | grep 'max-mss'                      # MSS clamp present?
# Recommended MSS by link type:
#   PPPoE WAN .................... 1452  (MTU 1492)
#   Standard Ethernet WAN ........ blank (1500/1460)
#   IPsec tunnel ................. 1380-1400
#   WireGuard (MTU 1420) ......... 1380
#   OpenVPN UDP .................. 1380-1400
# Persist via GUI: Interfaces -> [WAN/VPN] -> MSS


###############################################################################
# 7. MANAGEMENT PLANE (GUI / SSH)                                   [AUDIT]
###############################################################################
sockstat -4l | grep -E ':22 |:80 |:443 |:8443'
sockstat -6l | grep -E ':22 |:80 |:443 |:8443'

sshd -T 2>/dev/null | grep -Ei \
    'permitrootlogin|passwordauth|port|listenaddress|pubkeyauth|kexalgorithms|ciphers|macs'

who                                             # current sessions
last -n 20                                      # recent logins
lastlogin 2>/dev/null | head

# Recommended SSH (persist via GUI: System -> Settings -> Administration):
#   PermitRootLogin            no
#   PasswordAuthentication     no
#   PubkeyAuthentication       yes
#   Listen on LAN/management VLAN ONLY  (never WAN)


###############################################################################
# 8. USERS / AUTH / 2FA                                             [AUDIT]
###############################################################################
configctl system list users
configctl auth list servers                     # auth backends (LDAP/RADIUS/TOTP)
pw groupshow -a | grep -E 'wheel|admins'        # local admins
grep -E '<(user|group|webgui|ssh)>' /conf/config.xml | head
# Sensitive: /conf/config.xml contains hashed passwords + secrets. chmod 600.


###############################################################################
# 9. SERVICES POSTURE                                               [AUDIT]
###############################################################################
service -e                                      # enabled services
sockstat -4l                                    # all v4 listeners
sockstat -6l                                    # all v6 listeners

# Unbound (DNS)
configctl unbound status
grep -E 'dnssec|tls-upstream|do-not-query-localhost|access-control' \
    /var/unbound/unbound.conf
# Recommended: DNSSEC on, DNS-over-TLS upstreams, rebind protection ON.

# NTP
sockstat -4l | grep ':123 '
configctl ntpd status 2>/dev/null

# UPnP / NAT-PMP -- should usually be OFF
service miniupnpd status 2>/dev/null

# DHCP
configctl dhcpd status 2>/dev/null


###############################################################################
# 10. IDS / IPS (SURICATA)                                          [AUDIT]
###############################################################################
configctl ids status
configctl ids list installablerulesets
tail -n 50 /var/log/suricata/suricata.log
tail -n 50 /var/log/suricata/eve.json | jq '.alert.signature' 2>/dev/null


###############################################################################
# 11. FIRMWARE / PACKAGES / CVE AUDIT                               [AUDIT]
###############################################################################
opnsense-version                                # current version
opnsense-update -c                              # any updates available?
opnsense-update -l                              # changelog
pkg audit -F                                    # fetch & check vulns DB
pkg version -vRL=                               # outdated packages
pkg check -da                                   # integrity of installed pkgs

# [DANGER] [PERSIST] apply updates -- expect reboot:
#   opnsense-update -ub        # base+kernel
#   opnsense-update -p         # packages only
#   pkg upgrade                # third-party pkgs


###############################################################################
# 12. BACKUPS / CONFIG INTEGRITY                                    [AUDIT]
###############################################################################
ls -lh /conf/backup/ | tail
md5 /conf/config.xml
stat /conf/config.xml

# Manual backup snapshot:
#   cp /conf/config.xml /conf/backup/config-$(date +%Y%m%d-%H%M%S).xml


###############################################################################
# 13. LOGS WORTH SKIMMING                                           [AUDIT]
###############################################################################
clog -f /var/log/filter/latest.log              # firewall log (live)
clog   /var/log/system/latest.log  | tail -100
clog   /var/log/audit/latest.log   | tail -50
clog   /var/log/configd/latest.log | tail -50
clog   /var/log/resolver/latest.log | tail -50  # Unbound
ls -lh /var/log/                                # all log categories
# Top talkers in firewall log
clog /var/log/filter/latest.log | awk '{print $NF}' | sort | uniq -c | sort -rn | head


###############################################################################
# 14. CONNECTIVITY / DIAGNOSTICS                                    [AUDIT]
###############################################################################
ping -c 3 1.1.1.1
ping -c 3 9.9.9.9
host opnsense.org
drill opnsense.org @127.0.0.1                   # local resolver test
traceroute -n 1.1.1.1
mtr -n -c 5 1.1.1.1 2>/dev/null
arp -an                                         # ARP table
ndp -an                                         # IPv6 neighbour table
netstat -m                                      # mbuf usage
netstat -i                                      # per-iface counters / errors
systat -ifstat 1                                # live iface throughput (q to quit)
top -SHIz                                       # CPU per-thread
vmstat 1 5                                      # mem/CPU
gstat -p                                        # disk I/O


###############################################################################
# 15. PACKET CAPTURE                                                [AUDIT]
###############################################################################
# Replace igb0 with your interface; Ctrl-C to stop.
tcpdump -ni igb0 -c 100 'not port 22'
tcpdump -ni igb0 -s0 -w /tmp/cap.pcap 'host 1.2.3.4'
tcpdump -ni pflog0                              # what PF is logging
tcpdump -ni pflog0 -e -ttt                      # with rule numbers + deltas


###############################################################################
# 16. CONFIGCTL -- SUPPORTED MANAGEMENT BRIDGE                      [AUDIT/SET]
###############################################################################
configctl                                       # list all targets
configctl filter list rules
configctl filter reload                         # [SET] reload pf
configctl interface list ifconfig
configctl interface reconfigure wan             # [SET] [DANGER] WAN flap
configctl unbound restart                       # [SET]
configctl ids reload                            # [SET]
configctl system list users
configctl webgui restart                        # [SET] [DANGER] kicks GUI sessions


###############################################################################
# 17. APPLY / RELOAD AFTER MANUAL CHANGES                           [SET]
###############################################################################
# Preferred: GUI "Apply" or `configctl filter reload`. The actual file PF
# loads is /tmp/rules.debug (regenerated from config.xml).
pfctl -nf /tmp/rules.debug                      # [AUDIT] syntax check only
pfctl -f  /tmp/rules.debug                      # [SET] reload rules
pfctl -F state                                  # [DANGER] flush all states
pfctl -d                                        # [DANGER] disable PF entirely
pfctl -e                                        # re-enable PF


###############################################################################
# 18. TUNABLES PERSISTENCE TEMPLATE (for GUI: System -> Tunables)
###############################################################################
# Add each as a Tunable so it survives reboot/regeneration:
#
#   net.pf.debug                  = 1
#   net.inet.tcp.blackhole        = 2
#   net.inet.udp.blackhole        = 1
#   net.inet.ip.random_id         = 1
#   net.inet.icmp.drop_redirect   = 1
#   net.inet.tcp.drop_synfin      = 1
#   net.inet.ip.redirect          = 0
#   net.inet6.ip6.redirect        = 0
#   net.inet.tcp.syncookies       = 1
#   net.inet.icmp.bmcastecho      = 0
#   net.inet.icmp.maskrepl        = 0


###############################################################################
# 19. SECURITY HOUSEKEEPING REMINDERS
###############################################################################
# - Default-deny inbound on WAN (verify -- no any/any sneaks in).
# - Block bogons + RFC1918 on WAN; enable monthly bogons update.
# - Egress filter on LAN: at least block 23/445/137-139 outbound.
# - Allow ICMP type 3 (unreachable) on WAN -- needed for PMTUD.
# - GUI: HTTPS only, custom port, TLS 1.2+, HSTS, anti-lockout ON.
# - 2FA/TOTP for GUI + privileged users.
# - Unbound: DNSSEC ON, rebind protection ON, restrict to LAN.
# - UPnP/NAT-PMP OFF unless explicitly required.
# - IDS/IPS: start in IDS mode, tune, then promote to IPS.
# - Suricata + ET Open / Abuse.ch rulesets enabled on WAN.
# - Encrypted config backups (Google Drive / Nextcloud).
# - Patch monthly: opnsense-update -ub && pkg upgrade.
# - Restrict GUI/SSH to mgmt VLAN; never expose to WAN.
# - Review /var/log/audit and /var/log/configd weekly.


###############################################################################
# END
###############################################################################
