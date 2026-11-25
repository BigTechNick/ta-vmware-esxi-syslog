#!/usr/bin/env python3
"""
gen_conf.py <app dir> - writes default/props.conf and default/transforms.conf.

Splunk has no wildcard sourcetype stanzas, and ESXi produces one sourcetype per process
(vmware:esxlog:<process>), so props.conf repeats the same shared transforms for every
known process. This script is the source of truth for both files; edit it, not the output.
"""
import os
import sys

TS = r"(?:\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-]\d\d:?\d\d)?|[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d)"
LEVELS = r"(?:trivia|verbose|debug|info|warning|warn|error|critical|panic|quiet|alert|notice)"
HDR = r"^(?:<\d{1,3}>)?(?:" + TS + r" \S+ )?"   # [<PRI>][timestamp host ] (both optional)
BR = r"(?:[^\[\]]|\[[^\]]*\])"             # one character, or a [bracketed] part (sub=x[1])
SD = r"\[(?:Originator|vSAN)@\d+ " + BR + "*?"  # inside ESXi's [Originator@6876 ...] block
SDEND = r"(?= \w+=|\])"                       # an SD value ends at the next key= or ]

# name -> (regex, comment). Named groups become fields.
T = {}


def t(name, regex, comment):
    assert name not in T, name
    T[name] = (regex, comment)


# ---------------------------------------------------------------- every sourcetype
t("esxi_header",
  r"^(?:<(?<syslog_pri>\d{1,3})>)?(?:" + TS + r" \S+ )?"
  r"(?<process>[^\s\[:]+?(?: [A-Z][a-z]+)?)(?:\.\d+\.?)?"
  r"(?:\[(?<pid>\d+)(?:(?: [^\]\s]+)?\])?)?"
  r"(?(<pid>)(?: ?:)?(?:\s|$)| ?:(?:\s|$))\s*"
  r"(?:\"?\d{4}-\d\d-\d\dT\S+ )?(?:" + LEVELS + r" (?:-|[\w.-]+)\[\d+\] )?"
  r"(?:\[vmsyslogd@\d+[^\]]*\] )?(?:\[(?:Originator|vSAN)@\d+" + BR + r"*\] ?)?"
  r"(?<message>.*?)(?:#000)*$",
  "RFC 3164 style header: [<PRI>][time host ]process[pid]: message. The time may be classic or ISO;\n"
  "# PRI, time and host are optional, for syslog servers that write files without them.\n"
  "# Also handles ESXi 7/8's 'Process: level process[pid] [Originator@6876 ...]' layout, script\n"
  "# names with a pid suffix (backup.sh.123:) and 'Host Profiles[123 opID=x]:'.")
t("esxi_header_5424",
  r"^(?:<(?<syslog_pri>\d{1,3})>)?1 \d{4}-\S+ \S+ (?<process>\S+) (?:(?<pid>\d+)|-) (?:-|(?<esxi_msgid>\S+)) "
  r"(?:-|(?:\[" + BR + r"*\])+) ?(?:\[(?:Originator|vSAN)@\d+" + BR + r"*\] ?)?(?<message>.*?)(?:#000)*$",
  "RFC 5424 header (ESXi 8 can send this layout): <PRI>1 time host app procid msgid [SD] message")
t("esxi_level",
  HDR + r"[^\s\[:]+(?:\[\d+\])?: \"?(?:\d{4}-\d\d-\d\dT\S+ )?(?<log_level>" + LEVELS[3:-1] + r") (?:-|[\w.-]+)\[\d+\]",
  "Log level in the 'Process: level process[pid]' layout")
t("esxi_level_pid",
  HDR + r"[^\s\[:]+: \"?(?:\d{4}-\d\d-\d\dT\S+ )?" + LEVELS + r" [\w.-]+\[(?<pid>\d+)\]",
  "pid when it is only in the 'level process[pid]' part")
t("esxi_sd_sub", SD + r"\bsub=(?<esxi_sub>" + BR + "+?)" + SDEND, "Originator block: sub=")
t("esxi_sd_opid", SD + r"\bop[Ii][Dd]=(?<esxi_opid>" + BR + "+?)" + SDEND, "Originator block: opID=")
t("esxi_sd_sid", SD + r"\bsid=(?<esxi_sid>\w+)", "Originator block: sid= (session)")
t("esxi_sd_user",
  SD + r"\buser=(?<esxi_sd_user>(?<esxi_local_user>[^:\]\s]*)(?::(?<esxi_external_user>" + BR + "*?))?)" + SDEND,
  "Originator block: user=<ESXi user>[:<user it acts for, e.g. a vCenter user>]")
t("esxi_sd_reason", SD + r"\breason=(?<esxi_sd_reason>" + BR + "+?)" + SDEND, "Originator block: reason=")

# ---------------------------------------------------------------- shared by several
t("esxi_tcp_pair",
  r"<TCP '(?<local_ip>[^' ]+) : (?<local_port>\d+)'>, <TCP '(?<remote_ip>[^' ]+) : (?<remote_port>\d+)'>",
  "vmacore connection objects: <TCP 'local : port'>, <TCP 'remote : port'>")
t("esxi_vm_path", r"(?<vm_path>/vmfs/volumes/[^\s\"']+?\.vmx)\b", "Path of a VM's .vmx file")
t("esxi_device", r"\b(?<device>(?:naa|eui|t10)\.[0-9A-Za-z]+|mpx\.vmhba\d+:C\d+:T\d+:L\d+)",
  "First storage device ID in the message")
t("esxi_nic", r"\b(?<nic>vmnic\d+)\b", "First physical NIC in the message")
t("esxi_latency",
  r"latency (?:increased|reduced) from (?:average value of )?(?<latency_from_us>\d+) ?(?:microseconds|\(us\)) "
  r"to (?<latency_to_us>\d+)",
  "Storage latency change (microseconds)")
t("esxi_ssl_exception", r"SSL Exception: (?<ssl_error>[^)]+)\)", "vmacore SSL exception text")
t("esxi_ssl_errno", r", e: \d+\((?<ssl_error>[^)]+)\)", "vmacore 'e: <code>(<text>)' error")
t("esxi_firewall",
  r"Operation '(?<firewall_operation>\w+)' for rule set (?<firewall_ruleset>\S+?) succeeded",
  "Firewall rule set change (Hostd event and vobd)")
t("esxi_ssh_session_event",
  r"SSH session was (?<session_action>opened|closed) for '(?<user>[^@']+)@(?<src>[^']+)'",
  "SSH session opened/closed (Hostd event and vobd)")
t("esxi_lro",
  r"\[VpxLRO\] -- (?<esxi_lro_state>BEGIN|FINISH|ERROR|CANCEL\w*) (?<esxi_lro_id>\S+)"
  r"(?: -- (?<esxi_lro_object>\S*) -- (?<esxi_lro_method>\S+)(?: -- (?<esxi_lro_session>\S+))?)?",
  "Long-running operations (VpxLRO) in Vpxa, Fdm and Hostd")
t("esxi_return_code", r"completed with rc = (?<return_code>-?\d+)", "Backup return code")

# ---------------------------------------------------------------- Hostd
t("esxi_hostd_password",
  r"\b(?<esxi_auth_result>Accepted|Rejected) password for user (?<user>\S+) from (?<src>[^\s]+?)"
  r"(?: - session=(?<esxi_session>[\w-]+))?(?:#000)*$",
  "Hostd password login, accepted or rejected (Authentication)")
t("esxi_hostd_cannot_login",
  r"\] Event \d+ : (?<esxi_auth_result>Cannot login) (?<user>[^@\s]+)@(?<src>[^\s:]+)",
  "Hostd failed login event (Authentication)")
t("esxi_hostd_session",
  r"\] Event \d+ : User (?<user>[^@\s]+)@(?<src>\S+) logged (?<session_action>in|out)(?: as (?<user_agent>.+))?",
  "Hostd session login/logout event")
t("esxi_hostd_logout_detail",
  r"logged out \(login time: (?<login_time>.+?), number of API invocations: (?<api_invocations>[\d,]+), "
  r"user agent: (?<user_agent>.*)\)",
  "Hostd logout details")
t("esxi_hostd_event", r"\] Event (?<esxi_event_id>\d+) : (?<esxi_event_message>.*?)(?:#000)*$",
  "Hostd event: Event <n> : <text>")
t("esxi_hostd_task",
  r"\] Task (?<esxi_task_state>Created|Completed) : "
  r"(?<esxi_task_id>haTask-(?<esxi_task_entity>[\w-]*?)-(?<esxi_task_type>vim\.[\w.]+)\.(?<esxi_task_method>\w+)-\d+)"
  r"(?: Status (?<esxi_task_status>\w+))?",
  "Hostd task: Task Created|Completed : haTask-<entity>-<type>.<method>-<n> [Status <s>] (Change)")
t("esxi_hostd_vm_change", r"\] Event \d+ : (?<esxi_vm_action>Reconfigured|Registered|Removed) (?<vm_name>\S+) (?:on|from) ",
  "VM registered / removed / reconfigured")
t("esxi_hostd_vm_state",
  r"\] Event \d+ : (?<vm_name>\S+) on +\S+ in \S+ (?:has |is )"
  r"(?<esxi_vm_action>powered on|powered off|starting|stopping|suspended|resumed|reset)",
  "VM power state change")
t("esxi_hostd_vm_disks", r"\] Event \d+ : Virtual machine (?<vm_name>\S+) disks (?<esxi_vm_action>consolidated)",
  "VM disk consolidation")
t("esxi_hostd_guest_op",
  r"\] Event \d+ : Guest operation (?<guest_operation>.+?) performed on Virtual machine (?<vm_name>\S+?)\.?(?:#000)*$",
  "Guest operation on a VM")
t("esxi_hostd_vm_warning", r"\] Event \d+ : Warning message on (?<vm_name>\S+) on ", "Warning about a VM")
t("esxi_hostd_customization",
  r"\] Event \d+ : Customization of VM (?<vm_name>\S+) (?<esxi_vm_action>succeeded|failed)",
  "Guest customization result")
t("esxi_hostd_nfc",
  r"NFC operation '(?<nfc_operation>[^']+)' for path '(?<file_path>[^']+)' was initiated from '(?<src>[^']*)' "
  r"and completed with status '(?<nfc_status>[^']+)'",
  "NFC (file copy) operation")
t("esxi_hostd_file",
  r"File (?<nfc_operation>upload|download) (?:to|from) path '(?<file_path>[^']+)' was initiated from "
  r"'(?:(?<user_agent>[^'@]*)@)?(?<src>[^']*)' and completed with status '(?<nfc_status>[^']+)'",
  "Datastore file upload/download")

# ---------------------------------------------------------------- sshd and shell
t("esxi_sshd_auth",
  r"sshd\[\d+\]: (?<esxi_auth_result>Accepted|Failed) (?<authentication_method>[\w/-]+) for (?:invalid user )?"
  r"(?<user>\S+) from (?<src>\S+) port (?<src_port>\d+)",
  "SSH login accepted / failed (Authentication)")
t("esxi_sshd_invalid",
  r"sshd\[\d+\]: (?<esxi_auth_result>Invalid user) (?<user>\S*) ?from (?<src>\S+)(?: port (?<src_port>\d+))?",
  "SSH login with an unknown user (Authentication)")
t("esxi_sshd_pam_failure",
  r"sshd\[\d+\]: error: PAM: (?<esxi_auth_result>Authentication failure) for (?:illegal user )?(?<user>\S+) "
  r"from (?<src>\S+)",
  "SSH PAM authentication failure (Authentication)")
t("esxi_sshd_session",
  r"pam_unix\(sshd:session\): session (?<session_action>opened|closed) for user (?<user>\S+)",
  "SSH session opened / closed")
t("esxi_sshd_command", r"sshd\[\d+\]: User '(?<user>[^']+)' running command '(?<command>.*)'",
  "Command run over SSH")
t("esxi_sshd_connection", r"sshd\[\d+\]: Connection from (?<src>\S+) port (?<src_port>\d+)", "SSH connection")
t("esxi_sshd_disconnect",
  r"sshd\[\d+\]: (?:Disconnected from|Received disconnect from|Connection closed by)"
  r"(?: (?:authenticating |invalid )?user (?<user>\S+))? (?<src>[\da-fA-F.:]+) port (?<src_port>\d+)",
  "SSH disconnect")
t("esxi_shell_command", r"shell\[\d+\]: \[(?<user>[^\]]+)\]: (?<command>.+?)(?:#000)*$",
  "Command run in the ESXi Shell")

# ---------------------------------------------------------------- vobd
t("esxi_vob",
  r"vobd: +\[(?<vob_correlator>\w+)\] (?<vob_time_us>\d+)us: "
  r"\[(?<vob_id>(?<vob_source>esx|vob)\.(?<vob_type>\w+)\.[\w.]+)\] (?<vob_message>.*?)(?:#000)*$",
  "VMkernel observation: [correlator] <uptime>us: [esx.audit.x|esx.problem.x|vob.x] message")
t("esxi_vob_account",
  r"\] .*?(?:for|of) (?:ESXi local )?user (?:account )?'?(?<user>[\w.@\\-]+?)'?(?: has|\.|$| )",
  "User in account events (lockouts, login failures, password changes)")

# ---------------------------------------------------------------- envoy (reverse proxy)
t("esxi_envoy_access",
  r"envoy-access\[\d+\]: (?<http_method>[A-Z]+) (?<uri_path>[^\s?]+)(?:\?(?<uri_query>\S*))? (?<status>\d{3}) "
  r"(?<envoy_response_detail>\S+) (?<envoy_response_flags>\S+) (?<bytes_in>\d+) (?<bytes_out>\d+) "
  r"(?<envoy_content_encoding>\S+) (?<duration>\d+) (?<envoy_upstream_time>\S+) \S+ "
  r"(?<src>\[[^\]]+\]|[^\s:]+):(?<src_port>\d+) (?<http_version>\S+) (?<tls_version>\S+) "
  r"(?<dest_ip>\[[^\]]+\]|[^\s:]+):(?<dest_port>\d+) (?<envoy_upstream_local>\S+) (?<envoy_upstream_protocol>\S+) \S+ "
  r"(?<envoy_upstream_host>\S+)(?: \"(?<esxi_opid>[^\"]*)\"| -)?(?: \"(?<soap_action>[^\"]*)\"| -)?",
  "Envoy access log: method path status ... client:port protocol tls listener:port ... upstream \"opID\" \"SOAP action\" (Web)")
t("esxi_envoy_connection", r"\"ConnectionId\":\"(?<envoy_connection_id>\d+)\"", "Envoy connection ID")
t("esxi_envoy_tls",
  r"remote address:(?<remote_ip>[^,]+?):(?<remote_port>\d+),TLS_error:\|(?<tls_error>.*?):TLS_error_end",
  "Envoy TLS error with the client address")
t("esxi_envoy_closing",
  r"closing connection SSL<(?<remote_ip>[^,>]+?):(?<remote_port>\d+), (?<local_ip>[^,>]+?):(?<local_port>\d+)>",
  "Envoy closing a TLS connection")

# ---------------------------------------------------------------- other processes
t("esxi_rhttpproxy_endpoint",
  r"_serverNamespace = (?<rhttpproxy_namespace>\S+) action = (?<rhttpproxy_action>\S+) _port = (?<rhttpproxy_port>\d+)",
  "Reverse proxy route")
t("esxi_rhttpproxy_req", r"sub=Proxy Req (?<rhttpproxy_req>\d+)", "Reverse proxy request number")
t("esxi_fdm_cluster",
  r"hostId=(?<fdm_host_id>\S+) state=(?<fdm_state>\S+) master=(?<fdm_master>\S+) isolated=(?<fdm_isolated>\S+)",
  "vSphere HA (Fdm) cluster state")
t("esxi_vmkernel",
  r"vmk(?:ernel|warning): cpu(?<cpu>\d+):(?<world_id>\d+)(?: opID=(?<esxi_opid>[^)]+))?\)"
  r"(?:(?<log_level>WARNING): )?(?<vmk_module>[\w.-]+): (?:(?<vmk_function>[A-Za-z_]\w*):)?(?:(?<vmk_line>\d+): )?"
  r"(?<vmk_message>.*?)(?:#000)*$",
  "VMkernel: cpu<n>:<world>[ opID=x])[WARNING: ]Module: [function:]line: message")
t("esxi_crond",
  r"crond\[\d+\]: (?:crond: )?USER (?<user>\S+) pid (?<cron_pid>\d+) cmd (?<command>.+?)(?:#000)*$",
  "Cron job started")
t("esxi_heartbeat", r"heartbeat(?:\[\d+\])?: up (?<uptime>\w+), (?<vm_count>\d+) VMs?;", "Host uptime and VM count")
t("esxi_vmkmemstats", r"vmkmemstats\[\d+\]: (?<memstats_type>[\w-]+-stats): ", "Memory statistics type")
t("esxi_cluster_agent",
  r"clusterAgent\[\d+\]: (?:\d{4}-\S+?#011)?(?<log_level>[A-Z]+)#011(?:(?<cluster_agent_source>[\w./-]+:\d+)#011)?"
  r"(?<cluster_agent_message>[^#]+?)(?:#011(?<cluster_agent_detail>\{.*\}))?(?:#000)*$",
  "vSphere Cluster Services agent: LEVEL<tab>[source<tab>]message<tab>{json}")
t("esxi_cluster_agent_json",
  r"#011\{.*?\"opID\": \"(?<esxi_opid>[^\"]+)\"(?:.*?\"type\": \"(?<cluster_agent_type>[A-Z_]+)\")?",
  "opID and request type from the agent's JSON")
t("esxi_cluster_agent_error", r"\"error\": \"(?<cluster_agent_error>[^\"]*)\"", "Error text from the agent's JSON")
t("esxi_etcd_request",
  r"time spent = (?<etcd_time_spent>[^,]+), remote = (?<remote_ip>[^,]+?):(?<remote_port>\d+), "
  r"response type = (?<etcd_response_type>[^,]+)",
  "etcd request")
t("esxi_etcd_rejected",
  r"rejected connection from \"(?<remote_ip>[^\"]+?):(?<remote_port>\d+)\" \(error \"(?<etcd_error>[^\"]*)\"",
  "etcd rejected connection")
t("esxi_esxupdate",
  r"esxupdate: (?<pid>\d+): (?<esxupdate_module>[\w.]+): (?<log_level>[A-Z]+): ",
  "esxupdate: pid: module: LEVEL: message")
t("esxi_vib_hash", r"Verifying hash on vibid (?<vib_id>[^\s,]+)", "VIB being verified")
t("esxi_vib_signature", r"Verifying VIB (?<vib_id>\S+) signature", "VIB signature being verified")
t("esxi_vib_error",
  r"Failed to verify VIB signature #\d+: \('(?<vib_id>[^']+)', '(?<vib_error>[^']+)'\)",
  "VIB signature failure")
t("esxi_icm", r"\[MainProcess (?<log_level>[A-Z]+) '(?<icm_logger>[^']+)' (?<icm_thread>\w+)\]",
  "ImageConfigManager: [MainProcess LEVEL 'logger' thread]")
t("esxi_host_profiles", r"\[\d+ opID=(?<esxi_opid>[^\]]+)\]: (?<log_level>[A-Z]+): ",
  "Host Profiles[pid opID=x]: LEVEL: message")
t("esxi_hostprofiletrace", r"Command: (?<command>.+?), status: \((?<command_status>-?\d+)\)",
  "Host profile trace: command and exit status")
t("esxi_ucs_tool", r"ucs-tool-esxi-\w+ : (?<log_level>[A-Z]+)\s+: ", "UCS tool: name : LEVEL : message")
t("esxi_ucs_tool_command", r"Running command: (?<command>.+?)(?:#000)*$", "UCS tool command")
t("esxi_settingsd",
  r"settingsd\[\d+\]: (?<log_level>trivia|debug|info|warn|warning|error) \[(?<settingsd_component>[^:\]]+):",
  "settingsd: level [Component:thread] message")
t("esxi_lsud", r"lsud\[\d+\]: \[(?<log_level>\w+)\]", "lsud: [level] message")
t("esxi_scvmclient",
  r"scvmclient\[[\d:]+\]: (?<scvm_category>[A-Z]+): (?<log_level>[A-Z]+): (?<scvm_module>[\w.]+): ",
  "HyperFlex IO visor: CATEGORY: LEVEL: module: message")
t("esxi_healthd_plugin", r"healthdPlugins(?:\[\d+\])?: (?<healthd_plugin>vmw\.\w+) (?<log_level>[A-Z]+) ",
  "Health plug-in status")
t("esxi_vsand", r"vsand\[\d+\] \[opID=(?<esxi_opid>\S+) (?<esxi_function>[^\]]+)\]",
  "vSAN management service: [opID=x Class::Method]")
t("esxi_lwsmd_component", r"lwsmd(?:\[\d+\])?: \[(?<lwsmd_component>\w+)\] ", "Likewise (AD join) component")
t("esxi_ad_domain", r"domain '(?<ad_domain>[^']+)'", "Active Directory domain")
t("esxi_ad_password", r"machine password for (?<ad_domain>[\w.-]+) \(error = (?<ad_error>\d+)\)",
  "AD machine password change failure")
t("esxi_ad_dc_found", r"Found DC (?<ad_dc>\S+) \((?<ad_dc_ip>[^)]+)\)", "Domain controller found")
t("esxi_ad_dc_response", r"from DC response from (?<ad_dc>\S+) \((?<ad_dc_ip>[^)]+)\)", "Domain controller response")
t("esxi_nfcd", r"Accepted connection from \[(?<src>[^\]]+)\]:(?<src_port>\d+)", "NFC connection")
t("esxi_vmauthd_socket", r"Connect from remote socket \((?<src>[^)]+):(?<src_port>\d+)\)", "vmauthd connection")
t("esxi_vmauthd_connect", r"vmauthd\[\d+\]: Connect from (?<src>[^\s(]+)(?:#000)*$", "vmauthd connection")
t("esxi_vmauthd_proxy", r"Received PROXY command for (?<vmauthd_service>\w+), session = (?<esxi_session>\S+)",
  "vmauthd proxied service")
t("esxi_token_create",
  r"Creating token for \[(?<token_issuer>[^,\]]+), (?<token_domain>[^,\]]+), (?<user>[^\]]+)\]",
  "Token service: token created for a vCenter solution user")
t("esxi_token_user", r"Parsed authData\.username: \"(?<user>[^\"]+)\"", "Token service: user")
t("esxi_token_result", r"MethodResult: MR \[(?<result>\w+)\]", "Token service: result")
t("esxi_api_method", r"Invoke-MethodId: (?<api_method>\S+)", "API method")
t("esxi_api_forward", r"(?:Forwarding to|Invoke for|Forward response from) (?<api_service>\S+)", "API forwarder")
t("esxi_ism",
  r"(?<ism_message_id>ISM\d+) \[iSM@[\d.]+ EventID=\"(?<ism_event_id>\d+)\" EventCategory=\"(?<ism_category>[^\"]+)\" "
  r"EventSeverity=\"(?<ism_severity>[^\"]+)\"[^\]]*\] (?<ism_message>.*?)(?:#000)*$",
  "Dell iDRAC Service Module event")
t("esxi_ssl_conn_error", r"SSL Connection error (?<ssl_error_code>\d+) : (?<ssl_error>.+?)(?:#000)*$",
  "SSL connection error")
t("esxi_omsa",
  r"Server_Administrator: \d+ (?<omsa_event_id>\d+) - (?<omsa_service>.+?)  (?<omsa_message>.+?)"
  r"(?:\.:\s+(?<omsa_object>.+?))?(?:#000)*$",
  "Dell OpenManage Server Administrator: <n> <event ID> - <service>  <message>.:  <object>")
t("esxi_watchdog_started", r"Started (?<service>\S+) with PID=(?<service_pid>\d+)", "Watchdog started a service")
t("esxi_watchdog_restart", r"watchdog\[\d+\]: Restarting (?<service>\S+)", "Watchdog restarting a service")

# ---------------------------------------------------------------- props.conf
COMMON = ["esxi_header", "esxi_header_5424", "esxi_level", "esxi_level_pid",
          "esxi_sd_sub", "esxi_sd_opid", "esxi_sd_sid", "esxi_sd_user", "esxi_sd_reason"]
VMACORE = ["esxi_tcp_pair", "esxi_ssl_exception", "esxi_ssl_errno"]
STORAGE = ["esxi_device", "esxi_latency"]
HOSTD = ["esxi_hostd_password", "esxi_hostd_cannot_login", "esxi_hostd_session", "esxi_hostd_logout_detail",
         "esxi_hostd_event", "esxi_hostd_task", "esxi_hostd_vm_change", "esxi_hostd_vm_state",
         "esxi_hostd_vm_disks", "esxi_hostd_guest_op", "esxi_hostd_vm_warning", "esxi_hostd_customization",
         "esxi_hostd_nfc", "esxi_hostd_file", "esxi_firewall", "esxi_ssh_session_event", "esxi_vm_path",
         "esxi_lro", "esxi_nic"] + VMACORE + STORAGE

# process -> extra transforms. Processes not listed get COMMON only.
EXTRA = {
    "Hostd": HOSTD, "hostd": HOSTD,
    "Vpxa": ["esxi_lro", "esxi_vm_path"] + VMACORE, "vpxa": ["esxi_lro", "esxi_vm_path"] + VMACORE,
    "Fdm": ["esxi_lro", "esxi_vm_path", "esxi_fdm_cluster"] + VMACORE,
    "fdm": ["esxi_lro", "esxi_vm_path", "esxi_fdm_cluster"] + VMACORE,
    "Rhttpproxy": ["esxi_rhttpproxy_endpoint", "esxi_rhttpproxy_req"] + VMACORE,
    "rhttpproxy": ["esxi_rhttpproxy_endpoint", "esxi_rhttpproxy_req"] + VMACORE,
    "sshd": ["esxi_sshd_auth", "esxi_sshd_invalid", "esxi_sshd_pam_failure", "esxi_sshd_session",
             "esxi_sshd_command", "esxi_sshd_connection", "esxi_sshd_disconnect"],
    "shell": ["esxi_shell_command"],
    "vobd": ["esxi_vob", "esxi_vob_account", "esxi_firewall", "esxi_ssh_session_event", "esxi_nic"] + STORAGE,
    "vmkernel": ["esxi_vmkernel", "esxi_nic"] + STORAGE,
    "vmkwarning": ["esxi_vmkernel", "esxi_nic"] + STORAGE,
    "envoy-access": ["esxi_envoy_access"],
    "envoy": ["esxi_envoy_connection", "esxi_envoy_tls", "esxi_envoy_closing"],
    "crond": ["esxi_crond"],
    "heartbeat": ["esxi_heartbeat"],
    "vmkmemstats": ["esxi_vmkmemstats"],
    "clusterAgent": ["esxi_cluster_agent", "esxi_cluster_agent_json", "esxi_cluster_agent_error"],
    "etcd": ["esxi_etcd_request", "esxi_etcd_rejected"],
    "esxupdate": ["esxi_esxupdate", "esxi_vib_hash", "esxi_vib_signature", "esxi_vib_error"],
    "ImageConfigManager": ["esxi_icm"],
    "Host": ["esxi_host_profiles"],
    "hostprofiletrace": ["esxi_hostprofiletrace"],
    "ucs-tool-esxi-cfg": ["esxi_ucs_tool", "esxi_ucs_tool_command"],
    "ucs-tool-esxi-inv": ["esxi_ucs_tool", "esxi_ucs_tool_command"],
    "settingsd": ["esxi_settingsd"],
    "lsud": ["esxi_lsud", "esxi_device"],
    "scvmclient": ["esxi_scvmclient"],
    "healthdPlugins": ["esxi_healthd_plugin"] + VMACORE,
    "VSANMGMTSVC": ["esxi_vsand"],
    "vsansystem": VMACORE,
    "lwsmd": ["esxi_lwsmd_component", "esxi_ad_domain", "esxi_ad_password", "esxi_ad_dc_found",
              "esxi_ad_dc_response"],
    "nfcd": ["esxi_nfcd"],
    "vmauthd": ["esxi_vmauthd_socket", "esxi_vmauthd_connect", "esxi_vmauthd_proxy"],
    "esxtokend": ["esxi_token_create", "esxi_token_user", "esxi_token_result", "esxi_api_method"] + VMACORE,
    "apiForwarder": ["esxi_api_forward"] + VMACORE,
    "sandboxd": VMACORE,
    "hostd-probe": VMACORE,
    "sfcb-dcism": ["esxi_ism"],
    "iofiltervpd": ["esxi_ssl_conn_error"],
    "configStoreBackup": ["esxi_return_code"],
    "ConfigStore": ["esxi_return_code"],
    "watchdog": ["esxi_watchdog_started", "esxi_watchdog_restart"],
    "smartd": ["esxi_device"],
    # Dell OpenManage Server Administrator (process "Server_Administrator"). The usual sourcetype
    # rule stops at the underscore, so it arrives as vmware:esxlog:Server.
    "Server": ["esxi_omsa"],
    "Server_Administrator": ["esxi_omsa"],
}

# Other ESXi processes seen in the field or listed for the Splunk Add-on for VMware ESXi Logs.
OTHER = """
addvob apiForwarder attestd auto-backup backup backup-check backup-ssh boot cfgstore chronyd cimslp clomd cmmdsd
configStoreBackup ConfigStore crx-cli dcui DCUI dhclient-uw enum epd esxcli ESXShell healthd hostd-icm hostd-probe
hostdCgiServer indcfg infravisor Injector iofilterd-vmwarevmcrypt iofiltervpd jumpstart keypersist kmxa kmxd
lacp localcli net-dvs net-lacp netcpa nfcd nsx-opsagent nsx-proxy ntpd osfsd ptpd python root sandboxd sdrsInjector
secpolicytools sensord sfcb-CIMXML-Processor sfcb-HTTP-Daemon sfcb-ProviderManag sfcb-vmw sfcb-vmware sfcbd-init
slpd smbiosDump snmpd spherelet storageRM syslog tmpwatch trx-init usbarb vaainasd vdfsd vdtc vit-loader vmsyslogd
vmware-fdm vsandevicemonitord vsanmgmtd vsantraced vsfwd vsansystem VSANMGMTSVC watchdog watchdog-fdm
watchdog-hostd watchdog-vpxa watchdog-vsanperfsvc healthdPlugins
""".split()

# ---------------------------------------------------------------- EVALs
LEVEL_NORMALIZE = ('case(lower(log_level)=="warn", "warning", lower(log_level)=="err", "error", '
                   'lower(log_level)=="crit", "critical", true(), lower(log_level))')
COMMON_EVAL = {
    "vendor": '"VMware"',
    "product": '"ESXi"',
    "vendor_product": '"VMware ESXi"',
    "dvc": "host",
    "dest": "host",
    "app": "lower(process)",
    "log_level": LEVEL_NORMALIZE,
    "syslog_severity": 'mvindex(split("emergency,alert,critical,error,warning,notice,informational,debug", ","), '
                       'tonumber(syslog_pri) % 8)',
    "syslog_facility": 'mvindex(split("kern,user,mail,daemon,auth,syslog,lpr,news,uucp,cron,authpriv,ftp,ntp,'
                       'security,console,solaris-cron,local0,local1,local2,local3,local4,local5,local6,local7", ","), '
                       'floor(tonumber(syslog_pri) / 8))',
}
VM_NAME = {"vm_name": 'coalesce(vm_name, replace(vm_path, "^.*/([^/]+)\\.vmx$", "\\1"))'}

READ_METHODS = ("^(?:query|retrieve|find|list|get|search|acquire|refresh|validate|check|browse|read|fetch|export|"
                "download|login|logout|current|has[A-Z]|is[A-Z]|test|estimate|compute|wait|lookup|cancelWait|"
                "createFilter|createContainerView|createListView|destroyView|destroyPropertyFilter)")
TASK_ACTION = (
    'case(match(esxi_task_method, "' + READ_METHODS + '"), "read", '
    'match(esxi_task_type . "." . esxi_task_method, "(?i)permission|authorizationrole|\\.(?:add|remove|update)Role$"), '
    '"acl_modified", '
    'match(esxi_task_method, "^(?:reboot|reset|restart)"), "restarted", '
    'match(esxi_task_method, "^(?:powerOff|shutdown|standby|suspend|terminate|stop)"), "stopped", '
    'match(esxi_task_method, "^(?:powerOn|start|resume)"), "started", '
    'match(esxi_task_method, "^(?:clear|reset)"), "cleared", '
    'match(esxi_task_method, "^(?:remove|destroy|delete|unregister|uninstall|purge|erase)"), "deleted", '
    'match(esxi_task_method, "^(?:create|add|register|clone|deploy|import|install|new|copy|instantiate|make|upload)"), '
    '"created", '
    'true(), "modified")')
TASK_USER = ('if(isnotnull(esxi_external_user) AND esxi_external_user!="<no user>", '
             'esxi_external_user, esxi_local_user)')
TASK_CATEGORY = (
    'case(match(esxi_task_type, "^vim\\.vm\\.Snapshot"), "snapshot", '
    'match(esxi_task_type, "^vim\\.(?:VirtualMachine|vm\\.)"), "virtual_machine", '
    'match(esxi_task_type, "LocalAccountManager|UserDirectory"), "user", '
    'match(esxi_task_type, "AuthorizationManager"), "permission", '
    'match(esxi_task_type, "Datastore|StorageSystem|vslm|FileManager"), "storage", '
    'match(esxi_task_type, "(?i)dvs|Network|Firewall|VirtualNic"), "network", '
    'match(esxi_task_type, "ResourcePool"), "resource_pool", '
    'match(esxi_task_type, "SessionManager"), "session", '
    'match(esxi_task_type, "^vim\\.(?:HostSystem|host\\.)"), "host", '
    'true(), "other")')

HOSTD_EVAL = dict(VM_NAME, **{
    "action": 'case(esxi_auth_result=="Accepted", "success", '
              'esxi_auth_result=="Rejected" OR esxi_auth_result=="Cannot login", "failure", '
              'isnotnull(esxi_task_method), ' + TASK_ACTION + ', true(), null())',
    "status": 'case(esxi_task_status=="success", "success", isnotnull(esxi_task_status), "failure", true(), null())',
    "user": 'case(isnotnull(esxi_task_method), ' + TASK_USER + ', true(), user)',
    "esxi_task_readonly": 'case(isnull(esxi_task_method), null(), '
                          'match(esxi_task_method, "' + READ_METHODS + '"), "true", true(), "false")',
    "object": 'if(isnotnull(esxi_task_method), coalesce(esxi_task_entity, esxi_task_type), null())',
    "object_id": "esxi_task_entity",
    "object_category": 'if(isnotnull(esxi_task_method), ' + TASK_CATEGORY + ', null())',
    "command": 'esxi_task_type . "." . esxi_task_method',
    "change_type": 'if(isnotnull(esxi_task_method), "virtualization", null())',
    "authentication_method": 'if(esxi_auth_result=="Accepted" OR esxi_auth_result=="Rejected", "password", null())',
    "signature": 'case(esxi_auth_result=="Cannot login", "Cannot login", '
                 'isnotnull(esxi_auth_result), esxi_auth_result . " password", '
                 'isnotnull(esxi_task_method), esxi_task_type . "." . esxi_task_method, true(), null())',
})
SSHD_EVAL = {
    "action": 'case(esxi_auth_result=="Accepted", "success", isnotnull(esxi_auth_result), "failure", true(), null())',
    "signature": 'case(isnotnull(authentication_method), esxi_auth_result . " " . authentication_method, '
                 'true(), esxi_auth_result)',
}
VOB_ALERT = r"^esx\.problem\.|^esx\.audit\.account\.(?:locked|loginfailures)$"
VOB_SESSION = r"^esx\.audit\.\w+\.session\.|^esx\.audit\.dcui\.login\.failed$"
VOB_CHANGE = r"^esx\.audit\.(?!\w+\.session\.|dcui\.login\.failed$|account\.loginfailures$)"
VOBD_EVAL = {
    "signature": "vob_id",
    "signature_id": "vob_id",
    "description": "vob_message",
    "esxi_vob_category": 'case(match(vob_id, "' + VOB_ALERT + '"), "alert", '
                         'match(vob_id, "' + VOB_SESSION + '"), "session", '
                         'match(vob_id, "^esx\\.audit\\."), "change", true(), null())',
    # DCUI login failures count as Authentication (see eventtypes.conf)
    "esxi_auth_result": 'if(vob_id=="esx.audit.dcui.login.failed", "Failed", null())',
    "authentication_method": 'if(vob_id=="esx.audit.dcui.login.failed", "dcui", null())',
    "action": 'case(vob_id=="esx.audit.dcui.login.failed", "failure", '
              'vob_id=="esx.audit.account.locked", "lockout", '
              'NOT match(vob_id, "' + VOB_CHANGE + '"), null(), '
              'match(vob_id, "(?:reboot|restart)"), "restarted", '
              'match(vob_id, "(?:\\.disabled|\\.stop|poweroff|shutdown)"), "stopped", '
              'match(vob_id, "(?:\\.enabled|\\.boot|\\.start)"), "started", '
              'match(vob_id, "(?:remov|delet|uninstall|unmount|umount)"), "deleted", '
              'match(vob_id, "(?:creat|\\.add|install|\\.mount)"), "created", '
              'true(), "modified")',
    "status": 'case(NOT match(vob_id, "' + VOB_CHANGE + '"), null(), match(vob_id, "(?i)fail"), "failure", '
              'true(), "success")',
    "object": 'if(match(vob_id, "' + VOB_CHANGE + '"), coalesce(firewall_ruleset, mvindex(split(vob_id, "."), 2)), null())',
    "object_category": 'case(NOT match(vob_id, "' + VOB_CHANGE + '"), null(), '
                       'match(vob_id, "^esx\\.audit\\.(?:account|dcui\\.login)"), "user", '
                       'match(vob_id, "^esx\\.audit\\.net\\."), "network", true(), "host")',
    "change_type": 'if(match(vob_id, "' + VOB_CHANGE + '"), "host_configuration", null())',
    "severity": 'case(match(vob_id, "^esx\\.audit\\.account\\."), "high", '
                'match(vob_id, "^esx\\.problem\\."), "medium", true(), null())',
    "type": 'if(match(vob_id, "' + VOB_ALERT + '"), "alarm", null())',
}
ENVOY_ACCESS_EVAL = {
    # CIM Web action: blocked when the request was refused (401 / 403 / 407, or Envoy's external
    # authorization / rate limit rejection flags UAEX / RL), otherwise allowed (the proxy passed it
    # on; a 5xx is a server error, not a block)
    "action": 'case(in(status, "401", "403", "407") OR match(envoy_response_flags, "(^|,)(UAEX|RL)(,|$)"), "blocked", '
              'isnotnull(status), "allowed")',
    "bytes": "bytes_in + bytes_out",
    "url": "uri_path",
    "tls_version": 'if(tls_version=="-", null(), tls_version)',
}
EVAL_EXTRA = {
    "Hostd": HOSTD_EVAL, "hostd": HOSTD_EVAL,
    "Vpxa": VM_NAME, "vpxa": VM_NAME, "Fdm": VM_NAME, "fdm": VM_NAME,
    "sshd": SSHD_EVAL,
    "vobd": VOBD_EVAL,
    "envoy-access": ENVOY_ACCESS_EVAL,
}


def write(app):
    d = os.path.join(app, "default")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "transforms.conf"), "w", encoding="utf-8") as f:
        f.write("# Search-time field extractions for VMware ESXi syslog. Generated by tools/gen_conf.py.\n"
                "# Every regex uses named groups; each group becomes a field.\n")
        for name, (regex, comment) in T.items():
            f.write(f"\n# {comment}\n[{name}]\nREGEX = {regex}\n")
    names = sorted(set(EXTRA) | set(OTHER), key=lambda s: (s.lower(), s))
    with open(os.path.join(d, "props.conf"), "w", encoding="utf-8") as f:
        f.write("# Search-time settings for VMware ESXi syslog. Generated by tools/gen_conf.py.\n"
                "#\n"
                "# ESXi sends one log stream per process, and the usual parsing (for example the Splunk Add-on\n"
                "# for VMware ESXi Logs) names each sourcetype vmware:esxlog:<process>. Splunk has no wildcard\n"
                "# sourcetype stanzas, so each known process has its own stanza. To parse another process,\n"
                "# copy the [vmware:esxlog:syslog] stanza into local/props.conf under the new name.\n"
                "#\n"
                "# KV_MODE = none: the Originator block (sub=, opID=, user=) is parsed by name instead, so that\n"
                "# automatic key=value extraction does not create a conflicting 'user' field.\n")
        for st in ["vmw-syslog"] + [f"vmware:esxlog:{n}" for n in names]:
            proc = st.split(":")[-1] if st.startswith("vmware:esxlog:") else None
            reports = COMMON + [x for x in EXTRA.get(proc, []) if x not in COMMON]
            evals = dict(COMMON_EVAL)
            evals.update(EVAL_EXTRA.get(proc, {}))
            f.write(f"\n[{st}]\nKV_MODE = none\nREPORT-esxi = {', '.join(reports)}\n")
            for k in sorted(evals):
                f.write(f"EVAL-{k} = {evals[k]}\n")
    return names


if __name__ == "__main__":
    n = write(sys.argv[1])
    print(f"{len(T)} transforms, {len(n) + 1} sourcetypes")
