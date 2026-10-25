##! Local site policy. Customize as appropriate.
##!
##! This file will not be overwritten when upgrading or reinstalling!
##!
##! LAB MERGE: this is san's stock local.zeek with changes for the blue-team
##! pipeline, each tagged `# [lab]` below:
##!   1. JSON log output (so Fluent Bit ships uniform NDJSON)
##!   2. ignore_checksums (required to log traffic captured on wg0)
##!   3. Weird noise stream disabled
##!   - file hashing + Malware Hash Registry turned OFF
##! Stock detections worth keeping are left ON: http/detect-sql-injection,
##! conn/known-hosts + known-services (asset inventory), ssh/detect-bruteforcing.

# Installation-wide salt value that is used in some digest hashes, e.g., for
# the creation of file IDs. Please change this to a hard to guess value.
redef digest_salt = "Please change this value.";

# This script logs which scripts were loaded during each run.
@load misc/loaded-scripts

# Estimate and log capture loss.
@load misc/capture-loss

# Enable logging of memory, packet and lag statistics.
@load misc/stats

# For TCP scan detection, we recommend installing the package from
# 'https://github.com/ncsa/bro-simple-scan'. E.g., by installing it via
#
#     zkg install ncsa/bro-simple-scan

# Detect traceroute being run on the network. This could possibly cause
# performance trouble when there are a lot of traceroutes on your network.
# Enable cautiously.
#@load misc/detect-traceroute

# Generate notices when vulnerable versions of software are discovered.
# The default is to only monitor software found in the address space defined
# as "local".  Refer to the software framework's documentation for more
# information.
@load frameworks/software/vulnerable

# Detect software changing (e.g. attacker installing hacked SSHD).
@load frameworks/software/version-changes

# This adds signatures to detect cleartext forward and reverse windows shells.
@load-sigs frameworks/signatures/detect-windows-shells

# Load all of the scripts that detect software in various protocols.
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
# The detect-webapps script could possibly cause performance trouble when
# running on live traffic.  Enable it cautiously.
#@load protocols/http/detect-webapps

# This script detects DNS results pointing toward your Site::local_nets
# where the name is not part of your local DNS zone and is being hosted
# externally.  Requires that the Site::local_zones variable is defined.
@load protocols/dns/detect-external-names

# Script to detect various activity in FTP sessions.
@load protocols/ftp/detect

# Scripts that do asset tracking.
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs

# This script enables SSL/TLS certificate validation.
@load protocols/ssl/validate-certs

# This script prevents the logging of SSL CA certificates in x509.log
@load protocols/ssl/log-hostcerts-only

# If you have GeoIP support built in, do some geographic detections and
# logging for SSH traffic.
@load protocols/ssh/geo-data
# Detect hosts doing SSH bruteforce attacks.
@load protocols/ssh/detect-bruteforcing
# Detect logins using "interesting" hostnames.
@load protocols/ssh/interesting-hostnames

# Detect SQL injection attacks.
@load protocols/http/detect-sql-injection

#### Network File Handling ####

# [lab] File hashing OFF: MD5/SHA1 over every file costs CPU + RAM and we don't
# do file/malware work in this lab. Re-enable if you add a files.log use case.
# @load frameworks/files/hash-all-files

# [lab] detect-MHR OFF: it queries Team Cymru's Malware Hash Registry over
# EXTERNAL DNS, which hangs/times out with the WAN unplugged during range runs.
# (Also depends on hash-all-files above.)
# @load frameworks/files/detect-MHR

# Extend email alerting to include hostnames
@load policy/frameworks/notice/extend-email/hostnames

# Extend the notice.log with Community ID hashes
# @load policy/frameworks/notice/community-id

# Enable logging of telemetry data into telemetry.log and telemetry_histogram.log.
# This can impact performance if periodic metrics collection makes up a large
# part of Zeek's work, such as with "sparse" long-running pcaps.
# @load policy/frameworks/telemetry/log

# Uncomment the following line to enable detection of the heartbleed attack. Enabling
# this might impact performance a bit.
# @load policy/protocols/ssl/heartbleed

# Uncomment the following line to enable logging of Community ID hashes in
# the conn.log file.
# @load policy/protocols/conn/community-id-logging

# Uncomment the following line to enable logging of connection VLANs. Enabling
# this adds two VLAN fields to the conn.log file.
# @load policy/protocols/conn/vlan-logging

# Uncomment the following line to enable logging of link-layer addresses. Enabling
# this adds the link-layer address for each connection endpoint to the conn.log file.
# @load policy/protocols/conn/mac-logging

# Uncomment this to source zkg's package state
# @load packages

#### [lab] blue-team pipeline additions ###########################################

# [lab] 1. JSON output so Fluent Bit ships uniform NDJSON (one record per line).
redef LogAscii::use_json = T;

# [lab] 2. Ignore bad checksums. On wg0 (a tunnel/virtual interface) and with NIC
#       offloading, L3/L4 checksums in captured packets are often "wrong", and Zeek
#       DROPS bad-checksum packets by default -- so it sees the traffic but logs
#       nothing (while Suricata, trusting the kernel, logs fine). This is THE usual
#       cause of "Suricata has hits but Zeek is silent" on the same interface.
#       Equivalent to running `zeek -C`.
redef ignore_checksums = T;

# [lab] 3. Drop high-noise, low-value streams for a lab (cuts log I/O; the
#          analyzers still run, we just stop logging these). Comment a line back
#          in if you decide you want that stream.
event zeek_init()
    {
    Log::disable_stream(Weird::LOG);
    # Note: recent Zeek (5.0+) removed the old DPD module -- dpd.log became
    # analyzer.log. To also silence that, add (verify the identifier on your
    # version first, or it won't load):
    #   Log::disable_stream(Analyzer::Logging::LOG);
    }

# [lab] RAM note (operational, not a setting): run Zeek SINGLE-NODE. `zeek -i
#       <iface> local`, or zeekctl with ONE worker in node.cfg. Cluster mode
#       (manager + proxy + N workers) multiplies memory for nothing at lab volumes.
#       Interface placement (see Telemetry_pipeline.md): wg0 for web/kube, the
#       VirtualBox host-only iface (e.g. vboxnet0) for GOAD/AD (replies are NAT'd
#       off wg0).
