#!/usr/bin/env python3
"""
run_tests.py - checks the add-on with the offline Splunk stand-in (tests/splunk_sim.py):
  1. default/props.conf and transforms.conf match tools/gen_conf.py;
  2. every transform regex and EVAL match()/replace() regex compiles in Perl;
  3. every synthetic sample in tests/samples.py gets the expected fields and tags, and no field
     is set by two transforms;
  4. every event type search and tag stanza parses, and every tagged event type is used.

  python3 tests/run_tests.py [app dir]
"""
import filecmp
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import gen_conf  # noqa: E402
from samples import SAMPLES  # noqa: E402
from splunk_sim import AddOn  # noqa: E402

APP = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(ROOT, "TA-vmware-esxi-syslog")
fails = 0


def fail(msg):
    global fails
    fails += 1
    print("FAIL", msg)


# 1. generated files are current
tmp = tempfile.mkdtemp()
gen_conf.write(tmp)
for name in ("props.conf", "transforms.conf"):
    if not filecmp.cmp(os.path.join(tmp, "default", name), os.path.join(APP, "default", name), shallow=False):
        fail(f"default/{name} is out of date: run tools/gen_conf.py")

# 2-3. samples
app = AddOn(APP)
used_tags = set()
for i, (st, raw, want, tags) in enumerate(SAMPLES, 1):
    fields, got_tags, errors = app.process(st, raw, host="esxi01.example.com")
    for e in errors:
        fail(f"sample {i} ({st}): {e}")
    for k, v in want.items():
        have = fields.get(k)
        if have != v:
            fail(f"sample {i} ({st}): {k} = {have!r}, expected {v!r}")
    if sorted(tags) != got_tags:
        fail(f"sample {i} ({st}): tags {got_tags}, expected {sorted(tags)}")
    used_tags.update(fields["eventtype"])

# 4. every tagged event type is exercised by a sample
for stanza in app.tags:
    et = stanza.split("=", 1)[1]
    if et not in app.eventtypes:
        fail(f"tags.conf [{stanza}] has no event type")
    elif et not in used_tags:
        fail(f"event type {et} is not matched by any sample")

print(f"{len(SAMPLES)} samples, {len(app.transforms)} transforms, {len(app.props)} sourcetypes")
print("RESULT:", "OK" if not fails else f"{fails} failure(s)")
sys.exit(1 if fails else 0)
