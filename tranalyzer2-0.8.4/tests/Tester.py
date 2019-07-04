#!/usr/bin/env python3
#
# Toggle test.
# Use '--help' option for more information.
#
# TODO
#   - save all logs
#   - sequences to test: 0x3,0x4
#   - rerun-failed

import os
import platform
import shutil
import sys

from subprocess import Popen, PIPE


# Mac OS X
apple = bool(platform.mac_ver()[0])

T2HOME = os.path.dirname(os.path.realpath(__file__)) + '/..'
T2HOME = os.path.normpath(T2HOME)

autogen = {
    'exec': './autogen.sh',
    'opts': [],
}

sed = {
    'exec': ('/bin/sed', '/usr/local/bin/gsed')[apple],
    'opts': ['-ri'],
    'regex': r's/(^#define\s+{}\s+)[0-9](.*$)/\1{}\2/',
}

t2 = {
    'exec': T2HOME + '/tranalyzer2/src/tranalyzer',
    'opts': ['-l'],
    'pcap': 'wurst.dmp',
    'prefix': '/tmp/wurst',
}

valgrind = {
    'exec': '/usr/bin/valgrind',
    'opts': [
        '--tool=memcheck',
        '--leak-check=full',
        '--leak-resolution=high',
        '--trace-children=yes',
        '--num-callers=20',
        '--log-file=log-valgrind',
        '-v',
    ],
}

# For storing faulty configurations
toggle_err = {
    'build': [],
    'warn': [],
    't2': [],
    'leaks': [],
    'invrw': [],
}

VERBOSE_OUT = False
VERBOSE_ERR = False
FATAL_ERR = False
SILENT = False
FILES = set()  # List of files containing flags to toggle


def usage():
    print('Usage:')
    print('    {} [option...] -f <file>\n'.format(__file__))
    print('If no option is provided, check for build errors\n')
    print('Required arguments:')
    print('    -f file     the file containing the flags to toggle\n')
    print('Optional arguments:')
    print('    -w          check for compilation warnings')
    print('    -m          check for memory leaks (valgrind)')
    print('    -i          check for invalid read/write (valgrind)')
    print('    -t          check for runtime errors')
    print('                (if set, valgrind actions are ignored)\n')
    print('    -F          stop as soon as an error is encountered\n')
    print('    -r index    resume testing at index')
    print('    -s index    stop testing at index')
    print('    -c index    test configuration index\n')
    print('    -n          reduced output mode')
    print('    -v          verbose mode (errors only)')
    print('    -vv         verbose mode\n')
    print('    -d          build in debug mode')
    print('    -p folder   plugin folder\n')
    print('    -P pcap     pcap file to use')
    print('    -o out      tranalyzer output prefix\n')
    print('    -h, --help  show this help and exit')
    exit(0)


def set_pcap_file(pcap):
    if not os.path.isfile(pcap):
        fatal("'{}' is not a valid pcap file".format(pcap))
    t2['pcap'] = pcap


def set_output_prefix(prefix):
    t2['prefix'] = prefix


def set_plugin_folder(folder):
    opts = ['-p', folder]
    autogen['opts'].extend(opts)
    t2['opts'].extend(opts)


def printtxt(msg):
    if not SILENT:
        print(msg)


def printinf(msg):
    printtxt('\033[94m{}\033[0m'.format(msg))  # Blue


# Python 3.6
# def printerr(msg):
#    print(f'\033[91m{msg}\033[0m', file=sys.stderr)  # Red


def printerr(msg):
    print('\033[91m{}\033[0m'.format(msg))  # Red


def printok(msg):
    print('\033[92m{}\033[0m'.format(msg))  # Green


def printout(out, err):
    """Print stdout, stderr if required"""
    if VERBOSE_OUT:
        print(out.decode('utf-8'))
    if VERBOSE_ERR:
        print(err.decode('utf-8'))


def fatal(msg):
    printerr(msg)
    exit(1)


def backup_files(files):
    for f in files:
        backup_file(f)


def backup_file(f):
    shutil.copy(f, f + '.bak')


def restore_files(files):
    for f in files:
        restore_file(f)


def restore_file(f):
    bak = f + '.bak'
    if os.path.isfile(bak):
        shutil.move(bak, f)


def cleanup():
    """Rebuild the plugin with the default configuration"""
    restore_files(FILES)
    Popen(get_cmd_autogen(), stdout=PIPE, stderr=PIPE)


def arg_error(msg):
    printerr(msg)
    print("Try '{} --help' for more information.".format(__file__))
    exit(1)


def numeric_arg_error(opt):
    arg_error("Option '{}' requires a numeric argument".format(opt))


def missing_arg_error(opt):
    arg_error("Option '{}' requires an argument".format(opt))


def abort(msg, flags, flagsv):
    flagsv_hex = hex(int(flagsv, base=2))
    text = '\n{} with the following configuration ({}){}'
    printerr(text.format(msg, flagsv_hex, '' if SILENT else ':'))
    if not SILENT:
        text = '    {}: {}\t{}'
        for i, flag in enumerate(flags):
            printtxt(text.format(flag['file'], flag['name'], flagsv[i]))
    if FATAL_ERR:
        cleanup()
        exit(1)


def list_errors(msg, errors):
    if not errors:
        return False
    text = '\nThe following configurations {}:'.format(msg)
    if not SILENT:
        printerr(text)
    for err in errors:
        val = hex(int(err, base=2))
        if SILENT:
            text += ' ' + val
        else:
            printerr('    {}:'.format(val))
            txt = '        {}: {}\t{}'
            for i, flag in enumerate(flags):
                printtxt(txt.format(flag['file'], flag['name'], err[i]))
    if SILENT:
        printerr(text)
    return True


def list_all_errors():
    failed = False
    failed |= list_errors('failed to build', toggle_err['build'])
    failed |= list_errors('caused compilation warnings', toggle_err['warn'])
    failed |= list_errors('failed to run', toggle_err['t2'])
    failed |= list_errors('leaked memory', toggle_err['leaks'])
    failed |= list_errors('caused invalid read/write', toggle_err['invrw'])
    if failed:
        fatal('\nToggle test encountered errors\n')
    else:
        printok('\nToggle test successfully run\n')
    return failed


def patch_t2(flags, flagsv):
    for j, flag in enumerate(flags):
        printtxt('    {} {}'.format(flag['name'], flagsv[j]))
        run_sed(flag['name'], flagsv[j], flag['file'])


def build_plugin(flagsv, actions):
    cmd_autogen = get_cmd_autogen()
    printtxt('\nRunning {}\n'.format(' '.join(cmd_autogen)))
    proc = Popen(cmd_autogen, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate()
    printout(out, err)

    # Check for build errors
    if proc.returncode != 0:
        abort('Build error', flags, flagsv)
        toggle_err['build'].append(flagsv)
        return False

    # Check for compilation warnings
    if '-w' in actions and 'warning: ' in err.decode('utf-8'):
        abort('Compilation warnings', flags, flagsv)
        toggle_err['warn'].append(flagsv)
        return False

    return True


def get_cmd_autogen():
    cmd = list()
    cmd.append(autogen['exec'])
    cmd.extend(autogen['opts'])
    return cmd


def get_cmd_sed(flag, value, infile):
    cmd = list()
    cmd.append(sed['exec'])
    cmd.extend(sed['opts'])
    cmd.append(sed['regex'].format(flag, value))
    cmd.append(infile)
    return cmd


def get_cmd_t2():
    cmd = list()
    cmd.append(t2['exec'])
    cmd.append('-r')
    cmd.append(t2['pcap'])
    cmd.append('-w')
    cmd.append(t2['prefix'])
    cmd.extend(t2['opts'])
    return cmd


def get_cmd_valgrind():
    cmd = list()
    cmd.append(valgrind['exec'])
    cmd.extend(valgrind['opts'])
    cmd.extend(get_cmd_t2())
    return cmd


def run_sed(flag, value, infile):
    cmd_sed = get_cmd_sed(flag, value, infile)
    # printtxt('Running {}\n'.format(' '.join(cmd_sed)))
    if os.spawnv(os.P_WAIT, sed['exec'], cmd_sed) != 0:
        cleanup()
        fatal('Failed to change flags {} value to {}'.format(flag, value))


def run_tranalyzer(flagsv):
    cmd_t2 = get_cmd_t2()
    printtxt('Running {}\n'.format(' '.join(cmd_t2)))
    if run_cmd(cmd_t2) != 0:
        abort('Runtime error', flags, flagsv)
        toggle_err['t2'].append(flagsv)


def run_cmd(cmd):
    proc = Popen(cmd, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate()
    printout(out, err)
    return proc.returncode


def check_leaks():
    cmd = ('grep', 'definitely lost: [1-9]', 'log-valgrind')
    return run_cmd(cmd) == 0


def check_invalid_rw():
    cmd = ('grep', 'Invalid', 'log-valgrind')
    return run_cmd(cmd) == 0


def run_valgrind(flagsv, actions):
    cmd_valgrind = get_cmd_valgrind()
    printtxt('Running {}\n'.format(' '.join(cmd_valgrind)))
    # TODO check return value of spawnv?
    os.spawnv(os.P_WAIT, valgrind['exec'], cmd_valgrind)

    # Check for memory leaks
    if '-m' in actions and check_leaks():
        abort('Memory leaks', flags, flagsv)
        toggle_err['leaks'].append(flagsv)
        if '-i' not in actions:
            return

    # Check for invalid read/write
    if '-i' in actions and check_invalid_rw():
        abort('Invalid read/write', flags, flagsv)
        toggle_err['invrw'].append(flagsv)


def toggle_bits(start, stop, length):
    for i in range(start, stop):
        report_progress(start, stop, i)
        yield i, bin(i)[2:].zfill(length)


def report_progress(start, stop, curr):
    percent = 100.0 / (stop - start)
    msg = 'Current configuration: {} ({}%)'
    msg = msg.format(hex(curr), int((curr - start) * percent))
    if not SILENT:
        printinf('\n' + msg + ':')
    else:
        sys.stdout.write('\033[94m{}\033[0m\r'.format(msg))
        sys.stdout.flush()


def toggle(flags, start, stop, actions):
    for i, flagsv in toggle_bits(start, stop+1, len(flags)):
        patch_t2(flags, flagsv)

        if not build_plugin(flagsv, actions):
            continue

        if '-t' in actions:
            run_tranalyzer(flagsv)
        elif '-m' in actions or '-i' in actions:
            run_valgrind(flagsv, actions)


def read_file(filename):
    if not os.path.isfile(filename):
        fatal("File '{}' does not exist".format(filename))
    with open(filename) as f:
        flags = []
        for line in f:
            # skip comments and empty lines
            if line.isspace() or line.startswith('#'):
                continue
            line = line.split('#')[0]  # discard trailing comments
            try:
                name, infile = line.split()
            except ValueError:
                err = "Invalid line '{}' in '{}'"
                fatal(err.format(line.strip(), filename))
            if not os.path.isfile(infile):
                err = "Invalid line '{}' in '{}':"
                printerr(err.format(line.strip(), filename))
                printerr("    '{}' is not a valid file".format(infile))
                exit(1)
            cmd = ('grep', '^#define\s\+{}\s\+'.format(name), infile)
            proc = Popen(cmd, stdout=PIPE, stderr=PIPE)
            out, err = proc.communicate()
            if proc.returncode != 0:
                err = "Flag '{}' does not exist in '{}'"
                fatal(err.format(name, infile))
            FILES.add(infile)
            flags.append({'name': name, 'file': infile})
    if not flags:
        fatal("No flags defined in '{}'".format(filename))
    return flags


def validate_indices(start, stop, total):
    if start < 0:
        err = 'Start index {} is smaller than zero'
        fatal(err.format(start))
    if stop < 0:
        err = 'Stop index {} is smaller than zero'
        fatal(err.format(stop))
    if start > stop:
        err = 'Start index {} is bigger than stop index {}'
        fatal(err.format(start, stop))
    if start >= total:
        err = 'Start index {} is bigger than number of combinations {}'
        fatal(err.format(start, total-1))
    if stop >= total:
        err = 'Stop index {} is bigger than number of combinations {}'
        fatal(err.format(stop, total-1))


def print_estimated_runtime(flags, start, stop):
    if stop == start:
        # A single combination to test, print nothing
        return

    total = stop - start + 1

    msg = '{} flags, {} combinations{}'
    print(msg.format(len(flags), total, (' left.' if start > 0 else '.')))

    # Estimated runtime (based on a 1s execution time)
    days = int(total / 3600. / 24.)
    hours = int(total / 3600. - days * 24)
    minutes = int(total / 60. - hours * 60 - days * 24 * 60)
    seconds = int(total - minutes * 60 - hours * 3600 - days * 24 * 3600)
    seconds = int(total % 60.)

    msg = 'Estimated runtime: {} days {} hours {} minutes and {} seconds.\n'
    print(msg.format(days, hours, minutes, seconds))
    if days > 0:
        # let it sink in...
        import time
        time.sleep(2)


def SIGINT_handler(signum, frame):
    cleanup()
    list_all_errors()
    exit(1)


def setup_signal_handlers():
    import signal
    signal.signal(signal.SIGINT, SIGINT_handler)
    signal.signal(signal.SIGTERM, SIGINT_handler)


def parse_args(args):
    global FATAL_ERR
    global SILENT
    global VERBOSE_ERR
    global VERBOSE_OUT
    opts = {
        'actions': list(),
    }

    require_t2 = False
    skip_next = False
    argc = len(args)

    for i, a in enumerate(args):
        if i == 0 or skip_next:
            skip_next = False
            continue
        if a in ('-?', '-h', '--help'):
            usage()
        elif a in ('-f', '--file'):
            if (i+1) >= argc:
                missing_arg_error(a)
            opts['filename'] = args[i+1]
            skip_next = True
        elif a in ('-p', '--plugin-folder'):
            if i+1 >= argc:
                missing_arg_error(a)
            set_plugin_folder(args[i+1])
            skip_next = True
        elif a in ('-P', '--pcap'):
            if i+1 >= argc:
                missing_arg_error(a)
            set_pcap_file(args[i+1])
            skip_next = True
        elif a == '-o':
            if i+1 >= argc:
                missing_arg_error(a)
            set_output_prefix(args[i+1])
            skip_next = True
        elif a in ('-r', '--resume'):
            if i+1 >= argc:
                numeric_arg_error(a)
            try:
                opts['start'] = int(args[i+1], 0)
            except ValueError:
                numeric_arg_error(a)
            skip_next = True
        elif a in ('-s', '--stop'):
            if i+1 >= argc:
                numeric_arg_error(a)
            try:
                opts['stop'] = int(args[i+1], 0)
            except ValueError:
                numeric_arg_error(a)
            skip_next = True
        elif a in ('-c', '--check'):
            if i+1 >= argc:
                numeric_arg_error(a)
            try:
                opts['start'] = opts['stop'] = int(args[i+1], 0)
            except ValueError:
                numeric_arg_error(a)
            skip_next = True
        elif a == '-F':
            FATAL_ERR = True
        elif a == '-n':
            SILENT = True
        elif a == '-v':
            VERBOSE_ERR = True
        elif a == '-vv':
            VERBOSE_OUT = True
            VERBOSE_ERR = True
        elif a == '-w':
            opts['actions'].append(a)
        elif a in ('-t', '-m', '-i'):
            require_t2 = True
            opts['actions'].append(a)
        elif a == '-d':
            autogen['opts'].append(a)
        else:
            arg_error("Unknown option '{}'".format(a))

    if 'filename' not in opts:
        arg_error("Option '-f' is required")

    pname = os.path.basename(opts['filename'])
    if require_t2 and pname.startswith('tranalyzer2'):
        require_t2 = False

    if require_t2 and not os.path.isfile(t2['exec']):
        msg = 'Tranalyzer executable not found in {}'
        fatal(msg.format(os.path.dirname(t2['exec'])))

    return opts


if __name__ == '__main__':
    opts = parse_args(sys.argv)

    flags = read_file(opts['filename'])
    total = 1 << len(flags)

    start = opts.get('start', 0)
    stop = opts.get('stop', total-1)

    validate_indices(start, stop, total)

    print_estimated_runtime(flags, start, stop)

    setup_signal_handlers()

    backup_files(FILES)

    toggle(flags, start, stop, opts['actions'])

    list_all_errors()

    cleanup()
