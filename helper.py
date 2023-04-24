import re
import json

lines = open("error.txt", "r").readlines()
pattern = "^/Users/nima/Developer/BenchmarkJavaGradle/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest([0-9]+).java:([0-9]+): error: \[(\w*)\] (.+)"
errors = []
for i, line in enumerate(lines):
    match = re.match(pattern, line)
    if match:
        error = {'id': match.group(1), 'line': match.group(2), 'type': match.group(3), 'message': match.group(4),
                 'code': lines[i + 1].strip()}
        errors.append(error)

# sort errors by id
errors = sorted(errors, key=lambda k: k['id'])
out = {"errors": errors}
# output a json to file
with open('errors.json', 'w') as f:
    json.dump(out, f, indent=4)

