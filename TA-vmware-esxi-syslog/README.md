# VMware ESXi Syslog Fields and CIM Add-on

Version 1.0.0. App ID (folder name): `TA-vmware-esxi-syslog`.

Search-time fields and CIM mappings for VMware ESXi syslog, for Splunk Enterprise
Security and everyday searching. It works on the per-process sourcetypes
`vmware:esxlog:<process>` (`vmware:esxlog:Hostd`, `vmware:esxlog:sshd`, ...), the names
the Splunk Add-on for VMware ESXi Logs gives ESXi syslog.

| CIM data model | ESXi events |
|---|---|
| Authentication | Host agent password logins (vSphere API, Host Client), SSH logins, failed DCUI logins |
| Change | vSphere tasks that change something (snapshots, power, reconfigure, register, remove, maintenance mode, services, accounts, permissions); host audit records (`esx.audit.*`: SSH or shell enabled, firewall changes, password changes, account lockouts...) |
| Alerts | Host problems (`esx.problem.*`), account lockouts and repeated login failures |
| Web | Requests from other machines to the host's web services (`envoy-access`) |

It also parses more than 100 ESXi processes: the header (process, pid, log level, message),
the `[Originator@6876 sub=... opID=... user=...]` block, and process-specific fields
(vmkernel modules and devices, VM names, HA state, cron jobs, VIBs, ...).

> Independent project, not affiliated with or endorsed by Broadcom or VMware. VMware and
> ESXi are trademarks of Broadcom Inc. See NOTICE.

## Where to install

| Splunk instance | Install? |
|---|---|
| Search heads (including Splunk Cloud and Enterprise Security) | Yes |
| Heavy forwarders, indexers | No (search-time settings only) |

## Getting the data in

The add-on does not collect or parse data at index time. Each ESXi process needs its own
sourcetype, `vmware:esxlog:<process>`, which the Splunk Add-on for VMware ESXi Logs
(`Splunk_TA_esxilogs`) sets when it parses the data. Without it, you can set the host and
sourcetype on the heavy forwarder or indexers that parse your ESXi syslog (sourcetype
`vmw-syslog` on arrival):

```
# props.conf
[vmw-syslog]
SHOULD_LINEMERGE = false
TIME_PREFIX = ^<\d+>(?:1\s+)?
MAX_TIMESTAMP_LOOKAHEAD = 32
TRANSFORMS-esxi = esxi_set_host, esxi_set_sourcetype

# transforms.conf
[esxi_set_host]
REGEX = ^<\d+>(?:1\s+)?(?:\d{4}-\d{2}-\d{2}T\S+|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([\w.\-]+)\s
FORMAT = host::$1
DEST_KEY = MetaData:Host

[esxi_set_sourcetype]
REGEX = ^<\d+>(?:1\s+)?(?:\d{4}-\d{2}-\d{2}T\S+|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+([A-Za-z\-]+)[^:]*[:\[]
FORMAT = sourcetype::vmware:esxlog:$1
DEST_KEY = MetaData:Sourcetype
```

The add-on reads the raw syslog line. The `<PRI>`, timestamp and host at the start are
optional, so files written by a syslog server also work.

For Enterprise Security, add your ESXi index to the CIM index macros
`cim_Authentication_indexes`, `cim_Change_indexes`, `cim_Alerts_indexes` and
`cim_Web_indexes`.

## Fields on every event

| Field | Value |
|---|---|
| `process`, `pid` | ESXi process and process ID (`Hostd`, `2099077`) |
| `log_level` | `verbose`, `info`, `warning`, `error`, ... (lower case) |
| `message` | The message, without header, level and Originator block |
| `esxi_sub`, `esxi_opid`, `esxi_sid` | `sub=`, `opID=` and `sid=` from the Originator block |
| `esxi_sd_user` | `user=` from the Originator block, split into `esxi_local_user` (the ESXi account) and `esxi_external_user` (the account it acts for, such as a vCenter user) |
| `syslog_pri`, `syslog_severity`, `syslog_facility` | From the `<PRI>` |
| `app` | Process name in lower case |
| `dest`, `dvc` | The ESXi host (`host`) |
| `vendor`, `product`, `vendor_product` | `VMware`, `ESXi`, `VMware ESXi` |

## Authentication

| Source | Events | `action` |
|---|---|---|
| `Hostd` | `Accepted password for user X from Y`, `Rejected password ...`, `Event N : Cannot login X@Y` | `success` / `failure` |
| `sshd` | `Accepted <method> for X from Y port N` and `Failed ...`, `Invalid user`, `PAM: Authentication failure` | `success` / `failure` |
| `vobd` | `esx.audit.dcui.login.failed` | `failure` |

Fields: `user`, `src`, `src_port` (SSH), `authentication_method`, `signature`,
`esxi_auth_result`. Logins by `root` are also tagged `privileged`.

Host agent logins include vCenter's own connections (`vpxuser`) and local tools (`dcui`,
from `127.0.0.1`). Session start and end (`Event N : User X@Y logged in as <agent>` /
`logged out (...)`) are in event type `esxi_session` with `session_action`, `user_agent`,
`login_time` and `api_invocations`, and are not counted again as Authentication.

## Change

**vSphere tasks** (`Hostd`, `Task Created : haTask-<entity>-<type>.<method>-<n>`):

| Field | Value |
|---|---|
| `user` | Who started the task: the vCenter user from `user=vpxuser:<vCenter user>`, otherwise the ESXi account |
| `action` | From the method: `created`, `deleted`, `modified`, `started`, `stopped`, `restarted`, `acl_modified`, `cleared`, or `read` |
| `object`, `object_id` | The task's entity (a VM's ID, `ha-host`, `ha-root-pool`), or the type when there is none |
| `object_category` | `virtual_machine`, `snapshot`, `host`, `network`, `storage`, `resource_pool`, `user`, `permission`, `session`, `other` |
| `command` | `<type>.<method>`, such as `vim.VirtualMachine.powerOn` |
| `esxi_task_state`, `esxi_task_id`, `esxi_task_status` | `Created` / `Completed`, the task ID, and `success` / `error` |
| `status` | `success` / `failure` (`Task Completed` records) |

Only `Task Created` records of tasks that change something are tagged `change`; they carry
the user. The outcome is in the matching `Task Completed` record (same `esxi_task_id`).
Read-only API calls (`query*`, `retrieve*`, `find*`, `refresh`, ...) have `action=read`
and are not tagged. Account and permission tasks are also tagged `account`.

**Host audit records** (`vobd`, `esx.audit.*`): `action` from the record ID (`started` for
`*.enabled`, `stopped` for `*.disabled`, `lockout` for `esx.audit.account.locked`, otherwise
`modified`, `created` or `deleted`), `status`, `object` (`ssh`, `shell`, the firewall rule
set, ...), `object_category` (`host`, `network`, `user`), `signature`/`signature_id` (the
record ID) and `description` (its text). Firewall records are also tagged `network`,
account records `account`.

## Alerts

`vobd` records `esx.problem.*` (`severity=medium`), `esx.audit.account.locked` and
`esx.audit.account.loginfailures` (`severity=high`): `signature`, `signature_id`,
`description`, `type=alarm`, `user` for account records.

## Web

`envoy-access` (the host's reverse proxy) requests from other machines: `http_method`,
`uri_path`, `uri_query`, `url`, `status`, `bytes_in`, `bytes_out`, `bytes`, `duration`
(ms), `src`, `src_port`, `dest_ip`, `dest_port`, `tls_version`, `http_version`,
`soap_action`, `esxi_opid`. Requests from the host to itself (`127.0.0.1`) are parsed but
not tagged.

## Other fields

| Source | Fields |
|---|---|
| `Hostd` events | `esxi_event_id`, `esxi_event_message`, `vm_name`, `esxi_vm_action` (registered, removed, reconfigured, powered on/off, disks consolidated), `guest_operation`, `nfc_operation`, `file_path`, `nfc_status`, `firewall_operation`, `firewall_ruleset` |
| `vobd` | `vob_id`, `vob_source`, `vob_type`, `vob_correlator`, `vob_message`, `esxi_vob_category` (`change`, `alert`, `session`) |
| `vmkernel`, `vmkwarning` | `cpu`, `world_id`, `vmk_module`, `vmk_function`, `vmk_line`, `vmk_message` |
| storage messages | `device` (naa./eui./t10./mpx.), `latency_from_us`, `latency_to_us`, `nic` |
| `Vpxa`, `Fdm`, `Hostd` | `esxi_lro_state`, `esxi_lro_id`, `esxi_lro_object`, `esxi_lro_method` (VpxLRO), `vm_path`, `vm_name`; `Fdm`: `fdm_host_id`, `fdm_state`, `fdm_master`, `fdm_isolated` |
| `sshd`, `shell`, `crond` | `command`, `user`, `session_action`, `cron_pid` |
| `Rhttpproxy`, `envoy`, connection messages | `local_ip`, `local_port`, `remote_ip`, `remote_port`, `rhttpproxy_namespace`, `rhttpproxy_action`, `ssl_error`, `tls_error` |
| `clusterAgent`, `etcd` | `cluster_agent_message`, `cluster_agent_type`, `cluster_agent_error`, `etcd_response_type`, `etcd_error` |
| `esxupdate`, `ImageConfigManager` | `vib_id`, `vib_error`, `esxupdate_module`, `icm_logger` |
| `lwsmd` (Active Directory) | `ad_domain`, `ad_dc`, `ad_dc_ip`, `ad_error`, `lwsmd_component` |
| others | `heartbeat` (`uptime`, `vm_count`), `esxtokend` (`token_issuer`, `user`), `vmauthd`/`nfcd` (`src`), `sfcb-dcism` (`ism_*`), `Host Profiles`, `ucs-tool-*`, `settingsd`, `scvmclient` (`log_level`, `command`) |

## Event types and tags

| Event type | Tags | CIM |
|---|---|---|
| `esxi_authentication` | authentication | Authentication |
| `esxi_authentication_privileged` | privileged | Authentication.Privileged_Authentication |
| `esxi_session` | | (session start and end) |
| `esxi_task_change` | change | Change |
| `esxi_task_account_change` | account | Change.Account_Management |
| `esxi_audit_change` | change | Change |
| `esxi_audit_network_change` | network | Change.Network_Changes |
| `esxi_audit_account` | change, account | Change.Account_Management |
| `esxi_alert` | alert | Alerts |
| `esxi_web` | web | Web |
| `esxi_command` | | (commands run over SSH or in the ESXi Shell) |

## Notes

* Every known process has its own `[vmware:esxlog:<process>]` stanza. To parse another
  process, copy the `[vmware:esxlog:syslog]` stanza into `local/props.conf` under the new name.
* The stanzas set `KV_MODE = none`: the Originator block is parsed by name, so automatic
  key=value extraction does not create a second `user` field.

## Check after installing

```
index=<esxi index> sourcetype="vmware:esxlog:*" earliest=-4h
| stats count by sourcetype eventtype
```

```
| tstats count from datamodel=Authentication where nodename=Authentication sourcetype="vmware:esxlog:*" by Authentication.action Authentication.user
```

```
| tstats count from datamodel=Change where nodename=All_Changes sourcetype="vmware:esxlog:*" by All_Changes.action All_Changes.object_category All_Changes.user
```

## Release notes

### 1.0.0

* First release.

## Support

Community-supported, best effort, through Splunkbase. Licensed under Apache 2.0.
