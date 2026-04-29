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
    echo "=== Bare metal vs VM ===";     sysctl kern.vm_guest
    echo "=== PF debug level ===";       pfctl -x
    echo "=== Hardening sysctls ===";    sysctl \
        net.inet.tcp.blackhole net.inet.udp.blackhole \
        net.inet.ip.random_id net.inet.icmp.drop_redirect \
        net.inet.tcp.drop_synfin net.inet.ip.redirect \
        net.inet.tcp.syncookies
    echo "=== CPU mitigations ===";      dmesg | \
        grep -iE 'spectre|meltdown|pti|ibrs|retbleed|srso' | tail -10
    echo "=== Scrub rules ===";          pfctl -sr | grep -i scrub
    echo "=== PF info ===";              pfctl -s info | head -20
    echo "=== State count ===";          pfctl -s state | wc -l
    echo "=== Listening v4 ===";         sockstat -4l
    echo "=== SSH cfg ===";              sshd -T 2>/dev/null | \
        grep -Ei 'permitroot|passwordauth|port |pubkey|listenaddress'
    echo "=== System log tail ===";      tail -n 20 \
        /var/log/system/system_$(date +%Y%m%d).log 2>/dev/null
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
# NOTE: net.pf.debug was REMOVED in FreeBSD 14.x. Use pfctl -x only.
# Levels:  none | urgent | misc | loud
pfctl -x                                        # [AUDIT] current level
pfctl -x none                                   # [SET]   silence runtime
pfctl -x urgent                                 # [SET]   minimal output

# [PERSIST] no sysctl tunable on 14.x -- persist via GUI:
#   System -> Settings -> Logging  (firewall log level)

# Watch logs to confirm the spam stopped
# Modern OPNsense (23.x+) uses syslog-ng plain text files, not clog circular logs.
LD=$(date +%Y%m%d)
tail -f /var/log/system/system_${LD}.log | grep pf_   # [AUDIT]
tail -f /var/log/filter/filter_${LD}.log              # [AUDIT]


###############################################################################
# 3. KERNEL / NETWORK HARDENING SYSCTLS                             [AUDIT/SET]
###############################################################################
# IMPORTANT: the OPNsense Tunables GUI strips underscores from display
# names for compactness, but the ACTUAL FreeBSD sysctl OIDs (and the names
# stored in /conf/config.xml) use underscores. Use the underscored form
# below or `sysctl` will return "unknown oid".
# To self-discover real names on this box:
#   sysctl -a | grep -iE 'random.*id|drop.*synfin|see.*other|user.*open'

# [AUDIT] dump current values
sysctl \
    net.inet.tcp.blackhole          \
    net.inet.udp.blackhole          \
    net.inet.tcp.syncookies         \
    net.inet.tcp.drop_synfin        \
    net.inet.ip.random_id           \
    net.inet.ip.redirect            \
    net.inet6.ip6.redirect          \
    net.inet.icmp.drop_redirect     \
    net.inet.icmp.log_redirect      \
    net.inet.icmp.bmcastecho        \
    net.inet.icmp.maskrepl          \
    net.inet.tcp.icmp_may_rst       \
    net.inet6.icmp6.nodeinfo        \
    net.inet.ip.accept_sourceroute  \
    net.inet.ip.sourceroute         \
    net.inet6.ip6.forwarding        \
    net.link.tap.user_open          \
    net.inet.ip.portrange.first     \
    security.bsd.see_other_uids     \
    security.bsd.see_other_gids     \
    kern.coredump                   \
    kern.randompid

# [AUDIT] CPU side-channel mitigations actually applied
dmesg | grep -iE 'spectre|meltdown|mds|l1tf|pti|ibrs|stibp|ssbd|retbleed|srso'
sysctl hw.ibrs_active hw.ibrs_disable vm.pmap.pti hw.pti_enabled 2>/dev/null

# [SET] runtime hardening (persist via GUI Tunables, see section 18)
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
# OPNsense 23.x+ uses syslog-ng plain-text files (no `clog`). Filenames are
# /var/log/<category>/<category>_YYYYMMDD.log with older days .gz-compressed.
LD=$(date +%Y%m%d)
tail -f /var/log/filter/filter_${LD}.log              # firewall log (live)
tail -n 100 /var/log/system/system_${LD}.log
tail -n  50 /var/log/audit/audit_${LD}.log
tail -n  50 /var/log/configd/configd_${LD}.log
tail -n  50 /var/log/resolver/resolver_${LD}.log      # Unbound
ls -lh /var/log/                                       # all log categories

# Top talkers in firewall log
awk '{print $NF}' /var/log/filter/filter_${LD}.log | sort | uniq -c | sort -rn | head

# Search across all retained days (mix of .log and .log.gz)
zgrep -h 'pattern' /var/log/system/system_*.log.gz 2>/dev/null
 grep -h 'pattern' /var/log/system/system_*.log    2>/dev/null


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
# Use the actual FreeBSD sysctl OID names (with underscores). The OPNsense
# Tunables list view collapses underscores for display, but storage and the
# `sysctl` command both use the underscored form.
#
#   net.inet.tcp.blackhole          = 2
#   net.inet.udp.blackhole          = 1
#   net.inet.tcp.syncookies         = 1
#   net.inet.tcp.drop_synfin        = 1
#   net.inet.ip.random_id           = 1
#   net.inet.ip.redirect            = 0
#   net.inet6.ip6.redirect          = 0
#   net.inet.icmp.drop_redirect     = 1
#   net.inet.icmp.log_redirect      = 0
#   net.inet.icmp.bmcastecho        = 0
#   net.inet.icmp.maskrepl          = 0
#   net.inet.tcp.icmp_may_rst       = 0
#   net.inet6.icmp6.nodeinfo        = 0
#   net.inet.ip.accept_sourceroute  = 0
#   net.inet.ip.sourceroute         = 0
#   net.inet.ip.portrange.first     = 10000
#   net.link.tap.user_open          = 0   (only if no VPN client needs it)
#   security.bsd.see_other_uids     = 0
#   security.bsd.see_other_gids     = 0
#   kern.coredump                   = 0
#   kern.randompid                  = 1
#   kern.random.fortuna.minpoolsize = 128
#   hw.syscons.kbd_reboot           = 0
#   net.link.bridge.pfil_member     = 1
#
# REMOVE these if present without justification:
#   dev.netmap.bufnum                  (only needed by Zenarmor)
#   hw.vtnet.csumdisable               (only relevant inside a VM)
#   vm.numa.disabled                   (VM-template leftover)
#   hw.ixl.enableheadwriteback         (only for Intel XL710/X710 NICs)
#   net.inet.ip.fw.dynmax              (only for traffic shaping)
#   hw.ibrsdisable                     (turns OFF Spectre V2 mitigation)
#
# PF debug level: NOT a sysctl on 14.x. Use `pfctl -x none|urgent` (runtime)
# and lower the firewall log level in System -> Settings -> Logging.


###############################################################################
# 19. ENVIRONMENT SANITY (bare metal vs VM, leftover plugins)        [AUDIT]
###############################################################################
# Confirm what hardware/hypervisor you're really on
uname -a
opnsense-version
sysctl kern.vm_guest                              # "none" = bare metal
kenv smbios.bios.vendor 2>/dev/null
kenv smbios.system.product 2>/dev/null
dmidecode -s system-manufacturer 2>/dev/null
dmidecode -s system-product-name 2>/dev/null
sysctl hw.model hw.ncpu hw.physmem
pciconf -lv | grep -A1 -E 'class=0x020000'        # NIC list
ifconfig -l                                       # interface list
camcontrol devlist                                # storage

# Confirm Zenarmor / Sensei is fully gone (any output = leftover)
pkg info | grep -iE 'sensei|zenarmor'
ls /usr/local/sensei /usr/local/zenarmor 2>/dev/null
ls /usr/local/etc/rc.d/ | grep -iE 'sensei|zenarmor'
service -e | grep -iE 'sensei|zenarmor'
pgrep -lf 'sensei|zenarmor|nctd'

# Audit trail for stale/unexpected Tunables (who added them, when)
LD=$(date +%Y%m%d)
grep -B1 -A4 -E 'vtnet.csumdisable|netmap.bufnum|ibrsdisable|fw.dynmax|ixl.enableheadwriteback|portrange.first' /conf/config.xml
grep  -iE 'sysctl|tunable|netmap|vtnet|ibrs' /var/log/audit/audit_${LD}.log
grep  -iE 'sysctl|tunable'                   /var/log/configd/configd_${LD}.log
zgrep -iE 'sysctl|tunable' /var/log/audit/audit_*.log.gz 2>/dev/null | tail -50
ls -lt /conf/backup/ | head -20


###############################################################################
# 20. POST-CHANGE VERIFICATION                                      [AUDIT]
###############################################################################
# Stale tunables removed?
sysctl -a 2>/dev/null | grep -E 'netmap.bufnum|vtnet.csumdisable|ibrsdisable'

# Mitigations now applied?
dmesg | grep -iE 'spectre|meltdown|pti|ibrs|retbleed|srso'
sysctl hw.ibrs_active vm.pmap.pti 2>/dev/null

# Hardening still in effect?
sysctl net.inet.tcp.blackhole net.inet.udp.blackhole \
       net.inet.ip.randomid net.inet.tcp.syncookies \
       net.inet.tcp.dropsynfin net.inet.ip.portrange.first

# PF still scrubbing, log level low
pfctl -sr | grep -i scrub
pfctl -x

# No unexpected listeners
sockstat -4l
sockstat -6l

# Logs clean
LD=$(date +%Y%m%d)
tail -n 50 /var/log/system/system_${LD}.log
tail -n 20 /var/log/audit/audit_${LD}.log


###############################################################################
# 21. SECURITY HOUSEKEEPING REMINDERS
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
