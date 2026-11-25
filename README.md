# VMware ESXi Syslog Fields and CIM Add-on

Splunk add-on `TA-vmware-esxi-syslog`, version 1.0.2.

Search-time fields and CIM mappings for VMware ESXi syslog (sourcetypes `vmware:esxlog:<process>`): Authentication for host agent, SSH and DCUI logins, Change for vSphere tasks and host audit records, Alerts for host problems and account lockouts, and Web for remote requests to the host. Also parses the header, Originator block and messages of more than 100 ESXi processes. Not affiliated with Broadcom or VMware.

## Layout

- `TA-vmware-esxi-syslog/`: the app exactly as shipped to Splunkbase (unpacked from the release package)
- `tools/gen_conf.py`: writes `default/props.conf` and `default/transforms.conf` (one stanza per ESXi process; edit this, not the output)
- `tools/package.py`: builds the Splunkbase package and runs offline AppInspect-style checks
- `tools/make_icons.py`: draws the app icons in `static/`
- `tests/`: tests with synthetic data (no Splunk needed): `splunk_sim.py` stands in for Splunk's search-time field processing (REPORT, EVAL, event types, tags); `samples.py` has the sample events and expected fields

## Build

```
python3 tools/gen_conf.py TA-vmware-esxi-syslog
python3 tools/package.py TA-vmware-esxi-syslog dist --vendor vmware
```

Good: `RESULT: OK`. Then AppInspect:

```
splunk-appinspect inspect dist/TA-vmware-esxi-syslog-<version>.tgz --mode precert --included-tags cloud
```

## Tests

```
python3 tests/run_tests.py
```

Needs Perl (every regex is also compiled by Perl, close to Splunk's PCRE).

## Packages

`packages/` holds each version's package exactly as uploaded to Splunkbase, with `MD5SUMS`.
Each version is also its own commit (`git log`).

## License

Apache-2.0. Independent project, not affiliated with or endorsed by Broadcom or VMware.
