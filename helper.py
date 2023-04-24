import re
import json

io = json.load(open("errors.json", "r"))
serialized = json.load(open("serialized.json", "r"))
# pattern = "^/Users/nima/Developer/BenchmarkJavaGradle/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest([0-9]+).java:([0-9]+): error: \[(\w*)\] (.+)"
pattern = "^org.owasp.benchmark.testcode.BenchmarkTest([0-9]+)"
serialized_errors = serialized["errors"]
comprehensive_errors = {}


def fetch_error_by_id(errors, errid):
    for e in errors:
        if e['id'] == errid:
            return e


for err in serialized_errors:
    encClass = err['region']['class']
    match = re.match(pattern, encClass)
    if match:
        errid = match.group(1)
        ioerror = fetch_error_by_id(io["errors"], errid)
        e = err.copy()
        io_copy = ioerror.copy()
        del io_copy['id']
        e['io'] = io_copy
        comprehensive_errors[errid] = e

# sort errors by id
comprehensive_errors = {k: v for k, v in sorted(comprehensive_errors.items(), key=lambda item: item[0])}
# output a json to file
with open('comprehensive.json', 'w') as f:
    json.dump(comprehensive_errors, f, indent=4)
