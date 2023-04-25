import re
import json

io = json.load(open("errors.json", "r"))
serialized = json.load(open("serialized.json", "r"))


def fetch_error_by_id(errors, errid):
    for e in errors:
        if e['id'] == errid:
            return e


def unify():
    # pattern = "^/Users/nima/Developer/BenchmarkJavaGradle/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest(
    # [0-9]+).java:([0-9]+): error: \[(\w*)\] (.+)"
    pattern = "^org.owasp.benchmark.testcode.BenchmarkTest([0-9]+)"
    serialized_errors = serialized["errors"]
    comprehensive_errors = {}
    de_errors_id = {}

    for err in serialized_errors:
        encClass = err['region']['class']
        match = re.match(pattern, encClass)
        if match:
            errid = match.group(1)
            if errid not in de_errors_id.keys():
                de_errors_id[errid] = []
            de_errors_id[errid].append(err)

    io_errors_id = {}
    for err in io['errors']:
        if err['id'] not in io_errors_id.keys():
            io_errors_id[err['id']] = []
        io_errors_id[err['id']].append(err)

    combined = {}
    for errid in de_errors_id.keys():
        de_error = de_errors_id[errid]
        io_error = io_errors_id[errid]
        combined[errid] = {
            'serialized': de_error,
            'io': io_error
        }

    # sort combined by id
    combined = {k: v for k, v in sorted(combined.items(), key=lambda item: item[0])}
    # output a json to file
    with open('combined.json', 'w') as f:
        json.dump(combined, f, indent=4)


def filter_errors():
    errors = [e for e in io['errors'] if not (e['message'] == 'incompatible argument for parameter arg0 of setContentType.' and e['code'] == 'response.setContentType("text/html;charset=UTF-8");')]
    ans = {'errors': errors}
    # sort ans by id
    ans = {k: v for k, v in sorted(ans.items(), key=lambda item: item[0])}
    # output a json to file
    with open('filtered_errors.json', 'w') as f:
        json.dump(ans, f, indent=4)


unify()
