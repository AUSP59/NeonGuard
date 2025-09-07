#!/usr/bin/env python3
import os, subprocess, sys, difflib
root = os.path.dirname(os.path.dirname(__file__))
binp = os.path.join(root, 'build', 'neonsec')
if not os.path.exists(binp):
  print("neonsec binary not found at", binp, file=sys.stderr)
  sys.exit(0)
def run(args):
  p = subprocess.Popen([binp]+args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  out, err = p.communicate()
  return p.returncode, out, err
code, out, err = run(['analyze','--input','tests/golden/sample.csv','--format','text','--stable-order'])
exp = open('tests/golden/expected_text.txt').read()
if out != exp:
  print("Mismatch text:\n" + ''.join(difflib.unified_diff(exp.splitlines(True), out.splitlines(True)))); sys.exit(1)
code, out, err = run(['analyze','--input','tests/golden/sample.ndjson','--format','csv','--stable-order','--ts-format','epoch'])
exp = open('tests/golden/expected_csv.csv').read()
if out != exp:
  print("Mismatch csv:\n" + ''.join(difflib.unified_diff(exp.splitlines(True), out.splitlines(True)))); sys.exit(1)
print("golden ok")


# Selector test: only portscan
code, out, err = run(['analyze','--input','tests/golden/sample_types.csv','--format','csv','--stable-order','--ts-format','epoch','--only-type','portscan'])
exp = open('tests/golden/expected_only_portscan.csv').read()
if out != exp:
  print("Mismatch only-type:\n" + ''.join(difflib.unified_diff(exp.splitlines(True), out.splitlines(True)))); sys.exit(1)


# CSV header test
code, out, err = run(['analyze','--input','tests/golden/sample.ndjson','--format','csv','--stable-order','--ts-format','epoch','--csv-header'])
exp = open('tests/golden/expected_csv_with_header.csv').read()
if out != exp:
  print("Mismatch csv-header:\n" + ''.join(difflib.unified_diff(exp.splitlines(True), out.splitlines(True)))); sys.exit(1)


# Text template test
code, out, err = run(['analyze','--input','tests/golden/sample.ndjson','--format','text','--stable-order','--ts-format','epoch','--text-template','{type}:{key}@{ts}'])
exp = open('tests/golden/expected_text_tmpl.txt').read()
if out != exp:
  print("Mismatch text-template:\n" + ''.join(difflib.unified_diff(exp.splitlines(True), out.splitlines(True)))); sys.exit(1)


# Dedupe-window (10s): drop middle record at ts=105
code, out, err = run(['analyze','--input','tests/golden/dup.csv','--format','csv','--stable-order','--ts-format','epoch','--dedupe-window','10'])
exp = open('tests/golden/expected_dedupe_window.csv').read()
if out != exp:
  print("Mismatch dedupe-window:\n" + ''.join(difflib.unified_diff(exp.splitlines(True), out.splitlines(True)))); sys.exit(1)

# Min-key-count=2 keeps only login_fail:u1
code, out, err = run(['analyze','--input','tests/golden/mincount.csv','--format','csv','--ts-format','epoch','--min-key-count','2'])
exp = open('tests/golden/expected_mincount.csv').read()
if out != exp:
  print("Mismatch min-key-count:\n" + ''.join(difflib.unified_diff(exp.splitlines(True), out.splitlines(True)))); sys.exit(1)


# Redaction via regexes
with open('tests/golden/redact.rules','w') as f:
  f.write('u[0-9]+\n')
  f.write('secret\n')
code, out, err = run(['analyze','--input','tests/golden/redact.ndjson','--format','text','--stable-order','--ts-format','epoch','--redact-patterns','tests/golden/redact.rules','--redact-repl','***'])
exp = open('tests/golden/redact.txt').read()
if out != exp:
  print("Mismatch redact:\n" + ''.join(difflib.unified_diff(exp.splitlines(True), out.splitlines(True)))); sys.exit(1)


# Split-output basic: csv header present in partition file
code, out, err = run(['analyze','--input','tests/golden/sample.csv','--format','csv','--stable-order','--ts-format','epoch','--csv-header','--split-output','tests/golden/out','--split-by','type'])
import os, glob
files = glob.glob('tests/golden/out/*.csv')
assert files, "no split files created"
hdr = open(files[0]).read().splitlines()[0].strip()
if hdr != "ts,type,key,details":
  print("Missing CSV header in split file"); sys.exit(1)


# CSV header gains 'chain' when --chain is used
code, out, err = run(['analyze','--input','tests/golden/sample.csv','--format','csv','--stable-order','--ts-format','epoch','--csv-header','--chain'])
first = out.splitlines()[0].strip()
if first != "ts,type,key,details,chain":
  print("CSV header did not include chain"); sys.exit(1)


# CSV header gains 'id' when --record-id is used
code, out, err = run(['analyze','--input','tests/golden/sample.csv','--format','csv','--stable-order','--ts-format','epoch','--csv-header','--record-id'])
first = out.splitlines()[0].strip()
if first != "ts,type,key,details,id":
  print("CSV header did not include id"); sys.exit(1)

# record-id increments
code, out, err = run(['analyze','--input','tests/golden/sample.csv','--format','csv','--stable-order','--ts-format','epoch','--record-id','--record-id-start','42'])
lines = out.strip().splitlines()
assert lines and lines[-1].endswith(",43"), "record-id did not increment as expected"


# CSV header gains 'hmac' when --hmac-secret is used
code, out, err = run(['analyze','--input','tests/golden/sample.csv','--format','csv','--stable-order','--ts-format','epoch','--csv-header','--hmac-secret','x'])
first = out.splitlines()[0].strip()
if first != "ts,type,key,details,hmac":
  print("CSV header did not include hmac"); sys.exit(1)
