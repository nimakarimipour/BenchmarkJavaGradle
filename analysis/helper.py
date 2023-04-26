import re
import json

io = json.load(open("io.json", "r"))
serialized = json.load(open("serialized.json", "r"))


def fetch_error_by_id(errors, errid):
    for e in errors:
        if e['id'] == errid:
            return e


def error_is_unresovalbe(error):
    if error['message'] == 'incompatible argument for parameter arg0 of setContentType.' and error['code'] == 'response.setContentType("text/html;charset=UTF-8");':
        return True
    if error['message'] == 'incompatible argument for parameter arg0 of setHeader.' and error['code'] == 'response.setHeader("X-XSS-Protection", "0");':
        return True
    return False


def unify():
    # pattern = "^/Users/nima/Developer/BenchmarkJavaGradle/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest(
    # [0-9]+).java:([0-9]+): error: \[(\w*)\] (.+)"
    pattern = "^org.owasp.benchmark.testcode.BenchmarkTest([0-9]+)"
    serialized_errors = serialized["errors"]
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
    combined = json.load(open("combined.json", "r"))
    for key in combined.keys():
        de_errors = combined[key]['serialized']
        io_errors = combined[key]['io']
        cleaned_io = []
        cleaned_de = []
        for i, e in enumerate(io_errors):
            if error_is_unresovalbe(e):
                continue
            cleaned_io.append(io_errors[i])
            cleaned_de.append(de_errors[i])
        combined[key]['serialized'] = cleaned_de
        combined[key]['io'] = cleaned_io
    # sort combined by id
    combined = {k: v for k, v in sorted(combined.items(), key=lambda item: item[0])}
    # output a json to file
    with open('filtered.json', 'w') as f:
        json.dump(combined, f, indent=4)


def no_fixes():
    combined = json.load(open("filtered.json", "r"))
    to_delete = []
    for key in combined.keys():
        de_errors = combined[key]['serialized']
        io_errors = combined[key]['io']
        cleaned_io = []
        cleaned_de = []
        for i, e in enumerate(de_errors):
            if len(e['fixes']) != 0:
                continue
            cleaned_io.append(io_errors[i])
            cleaned_de.append(de_errors[i])
        if len(cleaned_de) != 0:
            del combined[key]['serialized']
            combined[key]['io'] = cleaned_io
        else:
            to_delete.append(key)
    for key in to_delete:
        del combined[key]
    # sort combined by id
    combined = {k: v for k, v in sorted(combined.items(), key=lambda item: item[0])}
    # output a json to file
    with open('no_fixes.json', 'w') as f:
        json.dump(combined, f, indent=4)


def google_sheet():
    DISP = "{}|{}|{}|{}|{}\n"
    URL = "https://github.com/nimakarimipour/BenchmarkJavaGradle/blob/af21eedf31cc9778b6daf9084c205cb8ccad018e/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest{}.java#L{}"
    HYPER_LINK = "\"=HYPERLINK(\"\"{}\"\",\"\"{}\"\")\""
    LINES = ['"ID"|"Line"|"Link"|"Type"|"Message"\n']
    all = json.load(open("no_fixes.json", "r"))
    for key in all.keys():
        errors = all[key]['io']
        for error in errors:
            id = error['id']
            line = error['line']
            type = error['type']
            message = error['message']
            url = HYPER_LINK.format(URL.format(id, line), "Github")
            LINES.append(DISP.format(id, line, url, type, message))
    with open('no_fix.csv', "w") as f:
        f.writelines(LINES)

google_sheet()
