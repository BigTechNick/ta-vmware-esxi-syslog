"""
Synthetic ESXi syslog lines (invented host names, users, VMs and documentation IP ranges) in the
layouts ESXi 7 and 8 send, with the fields and tags the add-on must produce.

Each entry: (sourcetype, raw, expected fields, expected tags). Expected fields are a subset:
a value of None means the field must NOT exist. Tags are compared exactly.
"""
H = "<166>2026-11-16T16:36:55.524Z esxi01.example.com "      # ISO timestamp header
C = "<166>Nov 16 16:36:57 esxi02 "                             # classic header
ST = "vmware:esxlog:"

SAMPLES = [
    # ------------------------------------------------------------ Hostd: Authentication
    (ST + "Hostd",
     H + "Hostd: info hostd[2102858] [Originator@6876 sub=Default opID=d4a73cdd] "
         "Accepted password for user vpxuser from 192.0.2.10",
     {"process": "Hostd", "pid": "2102858", "log_level": "info", "esxi_sub": "Default", "esxi_opid": "d4a73cdd",
      "esxi_auth_result": "Accepted", "user": "vpxuser", "src": "192.0.2.10", "action": "success",
      "authentication_method": "password", "signature": "Accepted password", "app": "hostd",
      "dest": "esxi01.example.com", "vendor_product": "VMware ESXi", "syslog_severity": "informational",
      "syslog_facility": "local4", "message": "Accepted password for user vpxuser from 192.0.2.10"},
     ["authentication"]),
    (ST + "Hostd",
     C + "Hostd[2099077]: [Originator@6876 sub=Vimsvc.HaSessionManager opID=c9fcd2f0 sid=52c15d39] "
         "Accepted password for user root from 198.51.100.25 - session=52c15d39-60b0-a97a-c63e-9fca0d7aa543",
     {"pid": "2099077", "esxi_sid": "52c15d39", "user": "root", "src": "198.51.100.25",
      "esxi_session": "52c15d39-60b0-a97a-c63e-9fca0d7aa543", "action": "success", "log_level": None},
     ["authentication", "privileged"]),
    (ST + "Hostd",
     H + "Hostd: info hostd[2102858] [Originator@6876 sub=Default opID=aa11bb22] "
         "Rejected password for user root from 203.0.113.7",
     {"esxi_auth_result": "Rejected", "user": "root", "src": "203.0.113.7", "action": "failure",
      "signature": "Rejected password"},
     ["authentication", "privileged"]),
    (ST + "Hostd",
     H + "Hostd: info hostd[2100155] [Originator@6876 sub=Vimsvc.ha-eventmgr] "
         "Event 1043 : Cannot login admin@203.0.113.7",
     {"esxi_auth_result": "Cannot login", "user": "admin", "src": "203.0.113.7", "action": "failure",
      "signature": "Cannot login", "esxi_event_id": "1043", "authentication_method": None},
     ["authentication"]),
    (ST + "Hostd",
     C + "Hostd[2099077]: [Originator@6876 sub=Vimsvc.ha-eventmgr opID=c9fcd2f0 sid=52c15d39] "
         "Event 185477 : User svc-backup@198.51.100.30 logged in as VMware-client/8.0.3",
     {"session_action": "in", "user": "svc-backup", "src": "198.51.100.30", "user_agent": "VMware-client/8.0.3",
      "esxi_event_id": "185477", "action": None},
     []),
    (ST + "Hostd",
     C + "Hostd[2099065]: [Originator@6876 sub=Vimsvc.ha-eventmgr reason=Timeout expired] Event 185447 : "
         "User vpxuser@192.0.2.10 logged out (login time: Monday, 16 November, 2026 02:56:21 PM, number of API "
         "invocations: 1, user agent: pyvmomi Python/3.8.13 (VMkernel; 7.0.3; x86_64))",
     {"session_action": "out", "user": "vpxuser", "esxi_sd_reason": "Timeout expired",
      "login_time": "Monday, 16 November, 2026 02:56:21 PM", "api_invocations": "1",
      "user_agent": "pyvmomi Python/3.8.13 (VMkernel; 7.0.3; x86_64)"},
     []),
    # ------------------------------------------------------------ Hostd: Change (tasks)
    (ST + "Hostd",
     C + "Hostd[2099045]: [Originator@6876 sub=Vimsvc.TaskManager opID=37f2bc97-c1-894c sid=5257b91b "
         "user=vpxuser:VSPHERE.LOCAL\\Administrator] Task Created : haTask-81749-vim.vm.Snapshot.remove-31431253",
     {"esxi_task_state": "Created", "esxi_task_entity": "81749", "esxi_task_type": "vim.vm.Snapshot",
      "esxi_task_method": "remove", "esxi_task_id": "haTask-81749-vim.vm.Snapshot.remove-31431253",
      "esxi_sd_user": "vpxuser:VSPHERE.LOCAL\\Administrator", "esxi_local_user": "vpxuser",
      "esxi_external_user": "VSPHERE.LOCAL\\Administrator", "user": "VSPHERE.LOCAL\\Administrator",
      "action": "deleted", "object": "81749", "object_id": "81749", "object_category": "snapshot",
      "command": "vim.vm.Snapshot.remove", "esxi_task_readonly": "false", "status": None,
      "change_type": "virtualization"},
     ["change"]),
    (ST + "Hostd",
     H + "Hostd: info hostd[2278433] [Originator@6876 sub=Vimsvc.TaskManager opID=Abc-12 "
         "user=vpxuser:com.vmware.vim.eam] Task Created : haTask-18-vim.VirtualMachine.powerOn-1289081099",
     {"user": "com.vmware.vim.eam", "action": "started", "object_category": "virtual_machine"},
     ["change"]),
    (ST + "Hostd",
     H + "Hostd: info hostd[2278433] [Originator@6876 sub=Vimsvc.TaskManager opID=Abc-13] "
         "Task Completed : haTask-18-vim.VirtualMachine.powerOn-1289081099 Status error",
     {"esxi_task_state": "Completed", "esxi_task_status": "error", "status": "failure", "action": "started",
      "user": None},
     []),
    (ST + "Hostd",
     C + "Hostd[2099056]: [Originator@6876 sub=Vimsvc.TaskManager opID=8551a676 sid=52419829 user=vpxuser:<no user>] "
         "Task Created : haTask--vim.dvs.HostDistributedVirtualSwitchManager.retrieveDVPortgroupConfigSpec-31449239",
     {"esxi_task_entity": None, "action": "read", "esxi_task_readonly": "true", "user": "vpxuser",
      "object": "vim.dvs.HostDistributedVirtualSwitchManager", "object_category": "network"},
     []),
    (ST + "Hostd",
     H + "Hostd: info hostd[2278433] [Originator@6876 sub=Vimsvc.TaskManager opID=k1 user=root] "
         "Task Created : haTask-ha-host-vim.host.LocalAccountManager.createUser-4401",
     {"esxi_task_entity": "ha-host", "action": "created", "object_category": "user", "user": "root"},
     ["account", "change"]),
    (ST + "Hostd",
     H + "Hostd: info hostd[2278433] [Originator@6876 sub=Vimsvc.TaskManager opID=k2 user=root] "
         "Task Created : haTask--vim.AuthorizationManager.setEntityPermissions-4402",
     {"action": "acl_modified", "object_category": "permission"},
     ["account", "change"]),
    (ST + "Hostd",
     H + "Hostd: info hostd[2278433] [Originator@6876 sub=Vimsvc.TaskManager opID=k3 user=:EXAMPLE\\jdoe] "
         "Task Created : haTask-ha-host-vim.HostSystem.enterMaintenanceMode-4403",
     {"user": "EXAMPLE\\jdoe", "esxi_local_user": None, "action": "modified", "object_category": "host"},
     ["change"]),
    # ------------------------------------------------------------ Hostd: other events
    (ST + "Hostd",
     H + "Hostd: info hostd[2099417] [Originator@6876 sub=Vimsvc.ha-eventmgr opID=x1 user=vpxuser] "
         "Event 39123 : Registered app-vm-01 on esxi01.example.com in ha-datacenter",
     {"vm_name": "app-vm-01", "esxi_vm_action": "Registered", "esxi_event_id": "39123"}, []),
    (ST + "Hostd",
     C + "Hostd[2099049]: [Originator@6876 sub=Vimsvc.ha-eventmgr] Event 20354 : db-vm-02 on esxi02 in "
         "ha-datacenter has powered on",
     {"vm_name": "db-vm-02", "esxi_vm_action": "powered on"}, []),
    (ST + "Hostd",
     H + "Hostd: info hostd[2109014] [Originator@6876 sub=Vimsvc.ha-eventmgr opID=Unknown-0000004df5b6a660] "
         "Event 41095 : NFC operation 'Upload' for path '/var/log/vlf-ts' was initiated from '192.0.2.10' and "
         "completed with status 'Success'",
     {"nfc_operation": "Upload", "file_path": "/var/log/vlf-ts", "src": "192.0.2.10", "nfc_status": "Success"}, []),
    (ST + "Hostd",
     C + "Hostd[2099292]: [Originator@6876 sub=Vimsvc.ha-eventmgr] Event 442489 : File download from path "
         "'[datastore1]app-vm-01/app-vm-01.nvram' was initiated from 'gSOAP/2.8@198.51.100.30' and completed "
         "with status 'True'",
     {"nfc_operation": "download", "user_agent": "gSOAP/2.8", "src": "198.51.100.30",
      "file_path": "[datastore1]app-vm-01/app-vm-01.nvram"}, []),
    (ST + "Hostd",
     H + "Hostd: info hostd[2099729] [Originator@6876 sub=Vimsvc.ha-eventmgr] Event 40516 : Firewall configuration "
         "has changed. Operation 'enable' for rule set sshServer succeeded.",
     {"firewall_operation": "enable", "firewall_ruleset": "sshServer"}, []),
    (ST + "Hostd",
     C + "Hostd[2099059]: [Originator@6876 sub=VMXStatsProvider(000000a981f035b0)] "
         "/vmfs/volumes/6102d28f-0bb0e2a2/app-vm-01/app-vm-01.scoreboard file can not be opened",
     {"esxi_sub": "VMXStatsProvider(000000a981f035b0)", "vm_path": None}, []),
    (ST + "Hostd",
     "<166>1 2026-11-16T16:40:00.123Z esxi03.example.com Hostd 2100123 - - [Originator@6876 sub=Default "
     "opID=r5424] Accepted password for user root from 198.51.100.25",
     {"process": "Hostd", "pid": "2100123", "esxi_opid": "r5424", "user": "root",
      "message": "Accepted password for user root from 198.51.100.25"},
     ["authentication", "privileged"]),
    (ST + "Hostd",
     "<166>1 2026-11-16T16:40:00.123Z esxi03.example.com Hostd 2100124 - [Originator@6876 sub=Vimsvc.TaskManager "
     "opID=r5425 user=root] Task Created : haTask-5-vim.VirtualMachine.powerOff-77",
     {"process": "Hostd", "pid": "2100124", "esxi_msgid": None, "esxi_opid": "r5425", "user": "root",
      "action": "stopped", "message": "Task Created : haTask-5-vim.VirtualMachine.powerOff-77"},
     ["change"]),
    # written to a file by a syslog server: no PRI, or no PRI, time and host
    (ST + "Hostd",
     "Nov 16 16:36:57 esxi02 Hostd[2099077]: [Originator@6876 sub=Default opID=f1] Accepted password for user "
     "root from 198.51.100.25",
     {"process": "Hostd", "pid": "2099077", "syslog_pri": None, "syslog_severity": None, "user": "root"},
     ["authentication", "privileged"]),
    (ST + "Hostd",
     "Hostd: info hostd[2102858] [Originator@6876 sub=Vimsvc.TaskManager opID=f2 user=root] Task Created : "
     "haTask-7-vim.VirtualMachine.destroy-88",
     {"process": "Hostd", "pid": "2102858", "log_level": "info", "action": "deleted", "user": "root"},
     ["change"]),
    # ------------------------------------------------------------ sshd and shell
    (ST + "sshd",
     "<38>2026-11-16T08:35:13.802Z esxi01.example.com sshd[5717754]: Accepted keyboard-interactive/pam for root "
     "from 198.51.100.25 port 56328 ssh2",
     {"esxi_auth_result": "Accepted", "authentication_method": "keyboard-interactive/pam", "user": "root",
      "src": "198.51.100.25", "src_port": "56328", "action": "success",
      "signature": "Accepted keyboard-interactive/pam", "app": "sshd"},
     ["authentication", "privileged"]),
    (ST + "sshd",
     "<38>Nov 16 08:35:13 esxi02 sshd[5717755]: Failed password for root from 203.0.113.7 port 40022 ssh2",
     {"esxi_auth_result": "Failed", "action": "failure", "src": "203.0.113.7"},
     ["authentication", "privileged"]),
    (ST + "sshd",
     "<38>Nov 16 08:35:14 esxi02 sshd[5717756]: Invalid user oracle from 203.0.113.7 port 40024",
     {"esxi_auth_result": "Invalid user", "user": "oracle", "action": "failure", "src_port": "40024"},
     ["authentication"]),
    (ST + "sshd",
     "<38>Nov 16 08:35:15 esxi02 sshd[5717757]: error: PAM: Authentication failure for root from 203.0.113.7",
     {"esxi_auth_result": "Authentication failure", "action": "failure", "user": "root"},
     ["authentication", "privileged"]),
    (ST + "sshd",
     "<86>2026-11-16T08:35:13.815Z esxi01.example.com sshd[5717754]: pam_unix(sshd:session): session opened for "
     "user svc-backup by (uid=0)",
     {"session_action": "opened", "user": "svc-backup", "action": None}, []),
    (ST + "sshd",
     "<38>2026-11-16T08:35:13.859Z esxi01.example.com sshd[5717754]: User 'svc-backup' running command "
     "'pidof hostd'",
     {"user": "svc-backup", "command": "pidof hostd"}, []),
    (ST + "sshd",
     "<38>2026-11-16T08:35:13.643Z esxi01.example.com sshd[5717754]: Connection from 198.51.100.25 port 56328",
     {"src": "198.51.100.25", "src_port": "56328", "esxi_auth_result": None}, []),
    (ST + "shell",
     "<13>2026-11-16T16:12:04.000Z esxi01.example.com shell[2101200]: [root]: esxcli network firewall get",
     {"user": "root", "command": "esxcli network firewall get"}, []),
    # ------------------------------------------------------------ vobd
    (ST + "vobd",
     "<14>2026-11-16T08:35:13.900Z esxi01.example.com vobd:  [UserLevelCorrelator] 13431970850992us: "
     "[esx.audit.ssh.enabled] SSH access has been enabled.",
     {"vob_id": "esx.audit.ssh.enabled", "vob_type": "audit", "esxi_vob_category": "change", "action": "started",
      "status": "success", "object": "ssh", "object_category": "host", "signature": "esx.audit.ssh.enabled",
      "description": "SSH access has been enabled.", "vob_correlator": "UserLevelCorrelator"},
     ["change"]),
    (ST + "vobd",
     "<14>Nov 16 06:43:56 esxi02 vobd:  [UserLevelCorrelator] 118658210954553us: [esx.audit.shell.disabled] "
     "The ESXi command line shell has been disabled.",
     {"action": "stopped", "object": "shell"}, ["change"]),
    (ST + "vobd",
     "<14>2026-11-16T08:35:13.900Z esxi01.example.com vobd:  [UserLevelCorrelator] 13431970850992us: "
     "[esx.audit.net.firewall.config.changed] Firewall configuration has changed. Operation 'disable' for rule set "
     "sshServer succeeded.",
     {"action": "modified", "object": "sshServer", "object_category": "network", "firewall_operation": "disable"},
     ["change", "network"]),
    (ST + "vobd",
     "<14>2026-11-16T08:35:13.900Z esxi01.example.com vobd:  [UserLevelCorrelator] 13431970850992us: "
     "[esx.audit.account.locked] Remote access for ESXi local user account 'root' has been locked for 900 seconds "
     "after 5 failed login attempts.",
     {"user": "root", "action": "lockout", "esxi_vob_category": "alert", "severity": "high", "type": "alarm",
      "object_category": "user"},
     ["account", "alert", "change"]),
    (ST + "vobd",
     "<14>2026-11-16T08:35:13.900Z esxi01.example.com vobd:  [UserLevelCorrelator] 13431970850992us: "
     "[esx.audit.account.loginfailures] Multiple remote login failures detected for ESXi local user account 'root'.",
     {"user": "root", "action": None, "esxi_vob_category": "alert", "severity": "high"},
     ["alert"]),
    (ST + "vobd",
     "<14>2026-11-16T08:35:13.900Z esxi01.example.com vobd:  [UserLevelCorrelator] 13431970850992us: "
     "[esx.audit.dcui.login.failed] Authentication of user root has failed. Please consult ESXi Embedded and "
     "vCenter Server Setup Guide for how to reset the password.",
     {"user": "root", "action": "failure", "esxi_auth_result": "Failed", "esxi_vob_category": "session",
      "authentication_method": "dcui", "status": None},
     ["authentication", "privileged"]),
    (ST + "vobd",
     "<14>2026-11-16T08:35:13.900Z esxi01.example.com vobd:  [UserLevelCorrelator] 13431970850992us: "
     "[esx.audit.dcui.login.passwd.changed] Login password for user root has been changed.",
     {"user": "root", "action": "modified", "object_category": "user", "esxi_vob_category": "change"},
     ["account", "change"]),
    (ST + "vobd",
     "<14>2026-11-16T08:35:13.900Z esxi01.example.com vobd:  [vmfsCorrelator] 13431970850992us: "
     "[esx.problem.vmfs.heartbeat.timedout] 5f2b1c3a-0d1e2f3a-1b2c-3d4e5f6a7b8c datastore1",
     {"esxi_vob_category": "alert", "severity": "medium", "type": "alarm", "action": None,
      "signature": "esx.problem.vmfs.heartbeat.timedout"},
     ["alert"]),
    (ST + "vobd",
     "<14>2026-11-16T08:35:13.900Z esxi01.example.com vobd:  [UserLevelCorrelator] 13431970850992us: "
     "[esx.audit.ssh.session.opened] SSH session was opened for 'root@198.51.100.25'.",
     {"esxi_vob_category": "session", "session_action": "opened", "user": "root", "src": "198.51.100.25",
      "action": None, "status": None},
     []),
    (ST + "vobd",
     "<14>Nov 16 06:43:56 esxi02 vobd:  [scsiCorrelator] 118658210954553us: "
     "[esx.clear.scsi.device.io.latency.improved] Device naa.60000000000000000000000000000001 performance has "
     "improved. I/O latency reduced from 1446 microseconds to 480 microseconds.",
     {"esxi_vob_category": None, "device": "naa.60000000000000000000000000000001", "latency_from_us": "1446",
      "latency_to_us": "480"},
     []),
    # ------------------------------------------------------------ envoy
    (ST + "envoy-access",
     C + "envoy-access[2098750]: POST /hgw/host-69/vpxa 200 via_upstream - 1050 516 gzip 1 1 0 "
         "192.0.2.10:35204 HTTP/1.1 TLSv1.2 198.51.100.12:443 127.0.0.1:17969 HTTP/1.1 - 127.0.0.1:8089 "
         "\"HB-host-69@1052683-4cd1128d\" \"GetChangesVpxa\"",
     {"http_method": "POST", "uri_path": "/hgw/host-69/vpxa", "url": "/hgw/host-69/vpxa", "status": "200",
      "bytes_in": "1050", "bytes_out": "516", "bytes": "1566", "duration": "1", "src": "192.0.2.10",
      "src_port": "35204", "dest_ip": "198.51.100.12", "dest_port": "443", "tls_version": "TLSv1.2",
      "esxi_opid": "HB-host-69@1052683-4cd1128d", "soap_action": "GetChangesVpxa", "dest": "esxi01.example.com",
      "action": "allowed"},
     ["web"]),
    (ST + "envoy-access",
     C + "envoy-access[2098751]: GET /sdk 500 via_upstream - 0 87 - 3 3 0 192.0.2.11:41200 HTTP/1.1 TLSv1.3 "
         "198.51.100.12:443 127.0.0.1:17970 HTTP/1.1 - 127.0.0.1:8307 - -",
     {"status": "500", "envoy_response_flags": "-", "action": "allowed"},
     ["web"]),
    (ST + "envoy-access",
     C + "envoy-access[2098752]: GET /ui/ 403 ext_authz_denied UAEX 0 0 - 0 - 0 192.0.2.12:41201 HTTP/1.1 TLSv1.3 "
         "198.51.100.12:443 - - - - -",
     {"status": "403", "envoy_response_flags": "UAEX", "action": "blocked"},
     ["web"]),
    (ST + "envoy-access",
     C + "envoy-access[2098753]: POST /sdk 429 local_rate_limited RL 0 18 - 0 - 0 192.0.2.13:41202 HTTP/1.1 TLSv1.3 "
         "198.51.100.12:443 - - - - -",
     {"status": "429", "envoy_response_flags": "RL", "action": "blocked"},
     ["web"]),
    (ST + "envoy-access",
     C + "envoy-access[2098754]: GET /folder 401 via_upstream - 0 0 - 1 1 0 192.0.2.14:41203 HTTP/1.1 TLSv1.3 "
         "198.51.100.12:443 127.0.0.1:17971 HTTP/1.1 - 127.0.0.1:8307 - -",
     {"status": "401", "action": "blocked"},
     ["web"]),
    (ST + "envoy-access",
     C + "envoy-access[2098755]: GET /ws 101 via_upstream DC 0 0 - 5000 - 0 192.0.2.15:41204 HTTP/1.1 TLSv1.3 "
         "198.51.100.12:443 127.0.0.1:17972 HTTP/1.1 - 127.0.0.1:8307 - -",
     {"status": "101", "envoy_response_flags": "DC", "action": "allowed"},
     ["web"]),
    (ST + "envoy-access",
     C + "envoy-access[2098759]: GET /sdk/service?x=1 200 via_upstream - 0 118 - 0 0 0 127.0.0.1:33937 HTTP/1.1 - "
         "127.0.0.1:80 127.0.0.1:50481 HTTP/1.1 - 127.0.0.1:8307 - -",
     {"uri_path": "/sdk/service", "uri_query": "x=1", "tls_version": None, "esxi_opid": None,
      "soap_action": None},
     []),
    (ST + "envoy",
     C + "envoy[1049911]: \"2026-11-16T16:11:35.277Z info envoy[1050554] [Originator@6876 sub=connection] [Tags: "
         "\"ConnectionId\":\"1189503\"] remote address:198.51.100.40:63492,TLS_error:|33554536:system library:"
         "OPENSSL_internal:Connection reset by peer:TLS_error_end\"",
     {"log_level": "info", "esxi_sub": "connection", "envoy_connection_id": "1189503",
      "remote_ip": "198.51.100.40", "remote_port": "63492"},
     []),
    # ------------------------------------------------------------ other processes
    (ST + "vmkernel",
     "<182>Nov 16 16:42:12 esxi02 vmkernel: cpu58:4095810)NetPort: 708: Failed to acquire port non-exclusive lock "
     "0x400001a[Failure].",
     {"cpu": "58", "world_id": "4095810", "vmk_module": "NetPort", "vmk_function": None, "vmk_line": "708",
      "vmk_message": "Failed to acquire port non-exclusive lock 0x400001a[Failure]."}, []),
    (ST + "vmkernel",
     "<182>Nov 16 10:20:46 esxi02 vmkernel: cpu35:2098995 opID=d0c34f9c)CpuSched: 840: user latency changed",
     {"esxi_opid": "d0c34f9c", "vmk_module": "CpuSched"}, []),
    (ST + "vmkwarning",
     "<180>Nov 16 16:08:28 esxi02 vmkwarning: cpu35:2098127)WARNING: ixgben: ixgben_CheckTxHang:2181: "
     "0000:1a:00.1: TX hang detected on TX queue: 0",
     {"log_level": "warning", "vmk_module": "ixgben", "vmk_function": "ixgben_CheckTxHang", "vmk_line": "2181"}, []),
    (ST + "crond",
     "<78>Nov 16 16:01:01 esxi02 crond[2098138]: crond: USER root pid 33685270 cmd /sbin/auto-backup.sh",
     {"user": "root", "cron_pid": "33685270", "command": "/sbin/auto-backup.sh", "pid": "2098138"}, []),
    (ST + "heartbeat",
     "<14>Nov 16 16:00:01 esxi02 heartbeat: up 615d18h56m31s, 1 VM; [] []",
     {"uptime": "615d18h56m31s", "vm_count": "1", "pid": None}, []),
    (ST + "backup",
     "<13>Nov 16 16:01:01 esxi02 backup.sh.33685305: Creating archive",
     {"process": "backup.sh", "pid": None, "message": "Creating archive"}, []),
    (ST + "auto-backup",
     "<14>Nov 16 10:01:01 esxi02 auto-backup.sh.34127417.[3412743 ConfigStore has been modified since the last backup",
     {"process": "auto-backup.sh", "pid": "3412743", "message": "ConfigStore has been modified since the last backup"},
     []),
    (ST + "Host",
     "<12>2026-11-16T08:37:11Z esxi01.example.com Host Profiles[5718635 opID=MainThread]: WARNING: Adding missing "
     "key#000",
     {"process": "Host Profiles", "pid": "5718635", "esxi_opid": "MainThread", "log_level": "warning"}, []),
    (ST + "ucs-tool-esxi-cfg",
     "<14>2026-11-16T16:44:32Z esxi01.example.com ucs-tool-esxi-cfg : INFO     : Running command: /opt/tool read#000",
     {"process": "ucs-tool-esxi-cfg", "log_level": "info", "command": "/opt/tool read"}, []),
    (ST + "clusterAgent",
     "<5>Nov 16 15:12:06 esxi02 clusterAgent[2100340]: 2026-11-16T15:12:06.150Z#011WARN#011clientv3/retry_"
     "interceptor.go:62#011retrying of unary invoker failed#011{\"target\": \"endpoint://client/esxi02:2379\", "
     "\"attempt\": 0, \"error\": \"rpc error: code = Unauthenticated desc = etcdserver: invalid auth token\"}",
     {"log_level": "warning", "cluster_agent_source": "clientv3/retry_interceptor.go:62",
      "cluster_agent_message": "retrying of unary invoker failed",
      "cluster_agent_error": "rpc error: code = Unauthenticated desc = etcdserver: invalid auth token"}, []),
    (ST + "clusterAgent",
     "<5>Nov 16 16:44:36 esxi02 clusterAgent[2099045]: INFO#011Processed admin request#011{\"opID\": "
     "\"CSMM-domain-c8-59503\", \"type\": \"TYPE_HEALTH_REPLY\"}",
     {"esxi_opid": "CSMM-domain-c8-59503", "cluster_agent_type": "TYPE_HEALTH_REPLY", "log_level": "info"}, []),
    (ST + "etcd",
     "<6>Nov 16 16:38:34 esxi02 etcd[29231479]: rejected connection from \"198.51.100.35:58697\" (error \"EOF\", "
     "ServerName \"esxi02.example.com\")",
     {"remote_ip": "198.51.100.35", "remote_port": "58697", "etcd_error": "EOF"}, []),
    (ST + "esxupdate",
     "<11>2026-11-16T08:37:33Z esxi01.example.com esxupdate: 5718840: vmware.esximage.Vib: ERROR: Failed to verify "
     "VIB signature #2: ('VMW_bootbank_example_1.0-1vmw', 'Could not find a trusted signer: self signed "
     "certificate')",
     {"pid": "5718840", "esxupdate_module": "vmware.esximage.Vib", "log_level": "error",
      "vib_id": "VMW_bootbank_example_1.0-1vmw", "vib_error": "Could not find a trusted signer: self signed certificate"},
     []),
    (ST + "settingsd",
     "<12>Nov 16 16:03:34 esxi02 settingsd[1050457]: warn [ConfigStore:25d83d1700] No tasks generated.",
     {"log_level": "warning", "settingsd_component": "ConfigStore"}, []),
    (ST + "lwsmd",
     "<28>2026-11-14T02:04:45.955Z esxi01.example.com lwsmd[2099711]: [netlogon] Found DC dc01.example.com "
     "(198.51.100.5) where LDAP port 389 is not accessible.",
     {"lwsmd_component": "netlogon", "ad_dc": "dc01.example.com", "ad_dc_ip": "198.51.100.5"}, []),
    (ST + "Rhttpproxy",
     "<167>Nov 16 16:44:49 esxi02 Rhttpproxy: verbose rhttpproxy[2101118] [Originator@6876 sub=Proxy Req 49986] "
     "New proxy client SSL(<io_obj p:0x000000a48b12b658, h:14, <TCP '198.51.100.12 : 443'>, "
     "<TCP '192.0.2.10 : 59898'>>)",
     {"log_level": "verbose", "pid": "2101118", "esxi_sub": "Proxy Req 49986", "rhttpproxy_req": "49986",
      "local_ip": "198.51.100.12", "local_port": "443", "remote_ip": "192.0.2.10", "remote_port": "59898"}, []),
    (ST + "vsansystem",
     "<164>2026-11-13T06:11:17.985Z esxi01.example.com vsansystem: warning vsansystem[6025110] [vSAN@6876 "
     "sub=vmomi.soapStub[1] opId=46496e2c] SOAP request returned HTTP failure",
     {"esxi_sub": "vmomi.soapStub[1]", "esxi_opid": "46496e2c", "message": "SOAP request returned HTTP failure"}, []),
    (ST + "sandboxd",
     C + "sandboxd[2098727]: [vmsyslogd@6876 msgModified=\"sF+uT\" remoteHostMaxMsgLen=\"480\"] "
         "[Originator@6876 sub=Default.HTTPService.HttpConnection] HTTP Connection has timed out",
     {"esxi_sub": "Default.HTTPService.HttpConnection", "message": "HTTP Connection has timed out"}, []),
    (ST + "Fdm",
     C + "Fdm[2099659]: [Originator@6876 sub=Cluster opID=clusterManager.cpp:980-595b7f2e] hostId=host-1006 "
         "state=Slave master=host-57 isolated=false host-list-version=247",
     {"fdm_host_id": "host-1006", "fdm_state": "Slave", "fdm_master": "host-57", "fdm_isolated": "false",
      "esxi_opid": "clusterManager.cpp:980-595b7f2e"}, []),
    (ST + "Fdm",
     C + "Fdm[2099643]: [Originator@6876 sub=Policy opID=WorkQueue-793e7f45] Removed VM "
         "/vmfs/volumes/6102d28f-0bb0e2a2/app-vm-01/app-vm-01.vmx",
     {"vm_path": "/vmfs/volumes/6102d28f-0bb0e2a2/app-vm-01/app-vm-01.vmx", "vm_name": "app-vm-01"}, []),
    (ST + "Vpxa",
     C + "Vpxa: info vpxa[26675771] [Originator@6876 sub=vpxLro opID=41b7f1be-ff] [VpxLRO] -- BEGIN task-200001 -- "
         "catalogSyncManager -- vim.vslm.host.CatalogSyncManager.queryCatalogChange -- 52bc8192-5977",
     {"esxi_lro_state": "BEGIN", "esxi_lro_id": "task-200001", "esxi_lro_object": "catalogSyncManager",
      "esxi_lro_method": "vim.vslm.host.CatalogSyncManager.queryCatalogChange", "esxi_lro_session": "52bc8192-5977",
      "pid": "26675771"}, []),
    (ST + "vdtc",
     C + "vdtc[2098894]: 2026-11-16T16:31:08.162Z info vdtc[245933402880] [Originator@6876 sub=Default] Buffers "
         "allocated: 100",
     {"pid": "2098894", "log_level": "info", "message": "Buffers allocated: 100"}, []),
    (ST + "healthdPlugins",
     C + "healthdPlugins: vmw.vpxaStatus ERROR Failed to retrieve vpxa status#000",
     {"healthd_plugin": "vmw.vpxaStatus", "log_level": "error"}, []),
    (ST + "sfcb-dcism",
     "<25>Nov 15 22:23:11 esxi02 sfcb-dcism[2100961]: ISM0001 [iSM@674.10892.2 EventID=\"8257\" "
     "EventCategory=\"Audit\" EventSeverity=\"error\" IsPastEvent=\"false\"] The service module detected a change.",
     {"ism_event_id": "8257", "ism_category": "Audit", "ism_severity": "error",
      "ism_message": "The service module detected a change."}, []),
    (ST + "vmauthd",
     "<14>2026-11-16T15:47:16.763Z esxi01.example.com vmauthd[6102110]: Connect from remote socket "
     "(192.0.2.10:59384).",
     {"src": "192.0.2.10", "src_port": "59384"}, []),
    (ST + "nfcd",
     "<14>Nov 16 14:56:23 esxi02 nfcd[2098907]: Accepted connection from [192.0.2.10]:45628 on 4:defaultTcpipStack",
     {"src": "192.0.2.10", "src_port": "45628"}, []),
    (ST + "esxtokend",
     "<166>2026-11-16T16:41:55.357Z esxi01.example.com esxtokend: info esxtokend[2100624] [Originator@6876 sub=Libs "
     "opID=vStats-token-create-2026-11-16 16:41:55.346312692 +0000 UTC] Creating token for "
     "[https://vcenter.example.com/websso/SAML2/Metadata/vsphere.local, vsphere.local, vpxd-extension-1234]",
     {"esxi_opid": "vStats-token-create-2026-11-16 16:41:55.346312692 +0000 UTC",
      "token_issuer": "https://vcenter.example.com/websso/SAML2/Metadata/vsphere.local",
      "token_domain": "vsphere.local", "user": "vpxd-extension-1234"}, []),
    (ST + "watchdog",
     "<62>Nov 16 15:56:12 esxi02 watchdog[2100411]: Started etcdmain with PID=29231479",
     {"service": "etcdmain", "service_pid": "29231479"}, []),
    (ST + "Server",
     "<25>Nov 18 20:19:56 esxi02 Server_Administrator: 35784 2242 - Storage Service  The Patrol Read has "
     "started.:  Controller 0 (PERC 6/i Integrated)",
     {"process": "Server_Administrator", "app": "server_administrator", "omsa_event_id": "2242",
      "omsa_service": "Storage Service", "omsa_message": "The Patrol Read has started",
      "omsa_object": "Controller 0 (PERC 6/i Integrated)", "syslog_severity": "alert",
      "message": "35784 2242 - Storage Service  The Patrol Read has started.:  Controller 0 (PERC 6/i Integrated)"},
     []),
    (ST + "Server_Administrator",
     "<25>Nov 18 20:19:56 esxi02 Server_Administrator: 35785 2243 - Storage Service  The Patrol Read has "
     "stopped.",
     {"omsa_event_id": "2243", "omsa_service": "Storage Service", "omsa_message": "The Patrol Read has stopped.",
      "omsa_object": None}, []),
    ("vmw-syslog",
     "<14>2026-11-16T08:40:50.439Z esxi01.example.com /VDFSFetchContainerLogs.pyc[5719616]: Clean up CMMDS lib",
     {"process": "/VDFSFetchContainerLogs.pyc", "pid": "5719616", "message": "Clean up CMMDS lib"}, []),
]
