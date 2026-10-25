##! local.zeek — lab tuning for the blue-team pipeline, runs on san (.1).
##! Goals: uniform JSON output, web + AD visibility, minimal footprint.
##!
##! Reality check on "streamlining" Zeek: unlike Suricata, Zeek has no big
##! rule-set RAM knob. Its footprint is driven by (1) node count, (2) traffic
##! volume / connection-table size, and (3) file analysis. So the levers are:
##! run single-node, skip file hashing, and drop noise streams. The protocol
##! logs you want (conn, dns, http, ssl, smb_*, kerberos, ntlm, dce_rpc, ldap,
##! rdp) come from Zeek's base scripts and are already on -- nothing to add for
##! the lab's web + AD coverage, and nothing kube-specific exists to add.

# 1. JSON output so Fluent Bit ships uniform NDJSON (one record per line).
redef LogAscii::use_json = T;

# 2. Don't hash or extract files -- saves CPU and memory. Re-enable if you later
#    want file.log hashes for malware work.
@unload frameworks/files/hash-all-files

# 3. Drop high-noise, low-value streams for a lab (cuts log I/O; keeps it lean).
#    Comment any back in if you want them.
event zeek_init()
    {
    Log::disable_stream(Weird::LOG);
    Log::disable_stream(DPD::LOG);
    }

# 4. RAM note (operational, not a setting): run Zeek SINGLE-NODE.
#    `zeek -i <iface> local`, or zeekctl with ONE worker. Cluster mode
#    (manager + proxy + N workers) multiplies memory and buys nothing at lab
#    traffic volumes.
#
# 5. Interface placement (see Telemetry_pipeline.md): point Zeek at the same
#    interface(s) as Suricata -- wg0 for web/kube, the VirtualBox host-only iface
#    (e.g. vboxnet0) for GOAD/AD, because AD replies are NAT'd off wg0. To watch
#    both at once, use a one-node zeekctl cluster listing both interfaces, or run
#    a second zeek instance.
