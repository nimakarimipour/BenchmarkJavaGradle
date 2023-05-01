import subprocess

ANNOTATOR_JAR = "/Users/nima/.m2/repository/edu/ucr/cs/riple/annotator/annotator-core/1.3.7-SNAPSHOT/annotator-core-1.3.7-SNAPSHOT.jar"
REPO = subprocess.check_output(['git', 'rev-parse', '--show-toplevel']).strip().decode('utf-8')


def make_config_paths():
    with open('/tmp/ucr-tainting/paths.tsv', 'w') as o:
        o.write("{}\t{}\n".format('/tmp/ucr-tainting/taint.xml', '/tmp/ucr-tainting/scanner.xml'))


def run_annotator():
    make_config_paths()
    commands = []
    commands += ["java", "-jar", ANNOTATOR_JAR]
    commands += ['-d', '/tmp/ucr-tainting']
    commands += ['-bc', 'cd {} && ./gradlew compileJava'.format(REPO)]
    commands += ['-cp', '/tmp/ucr-tainting/paths.tsv']
    commands += ['-i', 'edu.ucr.Initializer']
    commands += ['-cn', 'UCRTaint']
    # Uncomment to see build output
    # commands += ['-rboserr']

    subprocess.call(commands)


run_annotator()
