#!/usr/bin/env python3
################################################################################
#
#    script:   sermon.py
#    author:   sunckell <sunckell@gmail.com>
#    date:     Sept 21, 2012
#    descr:    sermon.py - runs either as a daemon or from cron.  If
#              run in daemon mode it will snapshot various statistics regarding
#              performance and benchmarks on a linux system.  This was written
#              to overcome the missing information from current "monitoring" 
#              tools that are used.  If run from cron or in non-daemon mode,
#              it will only execute one series of tests and exit.
#    notes:    March 20, 2014 Change config parse to iniparse. (fedora 21 doesn't
#              have configobj in the repose.)
#
#    updates:
#
#    TODO:
#
################################################################################
import os
import socket
import errno
import configparser
import logging.handlers
from optparse import OptionParser
from datetime import timedelta

# --- custom classes
import monitor.system
import common.utilities

__VERSION__ = '0.2.1'


# ---
# ---  Function:
# ---    parse_commandline_args()
# ---
# ---  Description:
# ---    Certain command line options are needed.  This will find out what command line
# ---    options were passed and resolve any conflicts pertaining to them
# ---
# ---  Parameters:
# ---    NONE
# ---
# ---  Returns:
# ---    an object containing the command line parameters.
# ---


def parse_commandline_args():

    desc = """To snapshot various statistics regarding performance and benchmarks on
              a Linux host.  This was written to overcome the lack of information from
              current monitoring solutions."""

    parser = OptionParser(description=desc, version=__VERSION__)
    parser.add_option("-q", "--quiet", dest="quiet", default=False,
                      action="store_true", help="don't print status messages to stdout")
    parser.add_option("-d", "--daemon", dest="daemon",
                      help="run in daemon mode")
    parser.add_option("-c", "--config", dest="config", default="sermon.config",
                      help="location of the configuration file")
    parser.add_option("-s", "--syslog", dest="syslog", default=False,
                      action="store_true", help="log to syslog instead of log file")

    (opts, args) = parser.parse_args()

    if len(args) == 1:
        parser.error("incorrect number of arguments")

    return opts

# ---
# ---  Function:
# ---    read_config_file()
# ---
# ---  Description:
# ---    reads the configuration file that was passed via the command line.
# ---
# ---  Parameters:
# ---    The location of the configuration file.
# ---
# ---  Returns:
# ---    the config object with the values of the configuration file
# ---


def read_config_file(config_file):
    parser = configparser.ConfigParser()
    parser.read(config_file)

    return parser

# ---
# ---  Function:
# ---    initialize_logger()
# ---
# ---  Descriptions:
# ---    sets up the logging for the application.
# ---
# ---  PARAMETERS:
# ---    NONE
# ---
# ---  RETURNS:
# ---    NONE - but sets a global variable called my_logger
# ---


def initialize_logger():

    """
        initialize_logger() - set up the logging environment
    """
    global my_logger

    log_filename = configs.get('config', 'workingdir') + '/' + configs.get('config', 'loggingdir') + '/' + configs.get('config', 'logfilename')
    max_bytes = int(configs.get('config', 'logsize'))
    backup_count = configs.get('config', 'filestokeep')
    levels = {'debug': logging.DEBUG,
              'info': logging.INFO,
              'warning': logging.WARNING,
              'error': logging.ERROR,
              'critical': logging.CRITICAL}
    log_level = levels.get(configs.get('config', 'loglevel').lower(), logging.DEBUG)

    # --- setup logger for this program.
    my_logger = logging.getLogger('sermon')
    my_logger.setLevel(log_level)

    # --- log to syslog if asked.  If not to a file
    if options.syslog:
        handler = logging.handlers.SysLogHandler(address='/dev/log')
        formatter = logging.Formatter('%(name)s [%(process)s]: %(message)s')
        handler.setFormatter(formatter)
        my_logger.addHandler(handler)
    else:
        if log_filename != 0 and log_filename != '':
            handler = logging.handlers.RotatingFileHandler(log_filename, maxBytes=max_bytes, backupCount=backup_count)
            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            my_logger.addHandler(handler)

    # --- do not print to standard out if not asked to.
    if not options.quiet:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        my_logger.addHandler(handler)

# ---
# ---  Function:
# ---    check_environment()
# ---
# ---  Description:
# ---    Looks at where we are running and verifies that the needed
# ---    OS environmental conditions are present to successfully execute.
# ---
# ---  Parameters:
# ---    NONE
# ---
# ---  Returns:
# ---    NONE - but sets a global string called environment and platform
# ---


def check_environment():
    """
        check_environment() - make sure the host and environment is suited for us to run cleanly.
    """

    global environment

    working_dir = configs.get('config', 'workingdir') + '/' + configs.get('config', 'loggingdir')

    # --- create a working directory to work in
    try:
        os.makedirs(working_dir)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
    # --- where are we running
    hostname = socket.gethostbyaddr(socket.gethostname())
    env_abbreviation = hostname[0]
    # --- set the ENV based on the hostname
    if env_abbreviation.upper() == 'D':
        environment = 'DEV'
    elif env_abbreviation.upper() == 'Q':
        environment = 'QUAL'
    elif env_abbreviation.upper() == 'P':
        environment = 'PROD'
    else:
        environment = 'SANDBOX'

# ---
# ---  Function:
# ---    record_general_system_info()
# ---
# ---  Description:
# ---    gather general information of the system. 
# ---
# ---  Parameters:
# ---    NONE
# ---
# ---  Returns:
# ---    NONE -
# ---


def record_general_system_info():
    """
        record_general_system_info() - gather general information about the system we are running on.
    """

    ms = monitor.system.System()
    pi = ms.get_platform_info
    ut = ms.get_uptime
    ips = ms.get_ip_addresses()

    my_logger.info('system node:        %s ' % pi['node'])
    my_logger.info('system arch:        %s ' % pi['machine'])
    my_logger.info('system kernel:      %s ' % pi['release'])
    my_logger.info('linux distribution: %s ' % str(pi['distribution']))
    my_logger.info('IP Address(s)       %s ' % str(ips))
    my_logger.info('system uptime:      %s ' % ut)

# ---
# ---  Function:
# ---    record_general_cpu_info()
# ---
# ---  Description:
# ---    gather general information about the CPU
# ---
# ---  Parameters:
# ---    NONE
# ---
# ---  Returns:
# ---    NONE -
# ---


def record_general_cpu_info(ms):
    """
        record_general_cpu_info() - gather general CPU information about the system we are running on.
    """

    #ms = monitor.system.System()
    cpu_ct = ms.get_cpu_count
    cpu_info = ms.get_cpu_util_per_cpu

    my_logger.info('CPU Count:          %s ' % cpu_ct)
    my_logger.info('Utilization Per CPU: non-blocking, ie.  percentage since last check.')
    for cpu_num, perc in enumerate(cpu_info):
        my_logger.info("              \_CPU%-2s      %5s%%" % (cpu_num, perc))

    load_average = '1min: {la[0]}  5mins: {la[1]}  15mins: {la[2]}'.format(la=os.getloadavg())
    my_logger.info('Load Averages: %s ' % load_average)


# ---
# ---  Function:
# ---    record_logged_in_user_info
# ---
# ---  Description:
# ---    gather information pertaining to the logged in users
# ---
# ---  Parameters:
# ---    NONE
# ---
# ---  Returns:
# ---    NONE -
# ---


def record_logged_in_user_info(ms):
    """
        record_logged_in_user_info() - gather information pertaining to the logged in users
    """

    lu = ms.get_users()

    my_logger.info('Logged In User Info:')
    my_logger.info('  Number of users logged in: %s' % str(len(lu)))

    count = 0
    for user in lu:
        count += 1
        my_logger.info('  User[' + str(count) + ']: %s' % user.name)
        my_logger.info(r'              \_ terminal: %s' % user.terminal)
        my_logger.info(r'              \_ host:     %s' % user.host)
        since = cu.convert_time_from_epoch(user.started)
        my_logger.info(r'              \_ since:    %s' % since)

# ---
# ---  Function:
# ---    record_memory_state()
# ---
# ---  Description:
# ---    gather and record information pertaining to the memory resources of the system
# ---
# ---  Parameters:
# ---    NONE
# ---
# ---  Returns:
# ---    NONE - 
# ---


def record_memory_state(ms):
    """
        record_memory_state() - when the script starts, it will gather information pertaining to the
                                  state of the system.
    """

    vm = ms.get_memory_info()
    sm = ms.get_swap_info()

    my_logger.info('Virtual Memory Stats:')
    my_logger.info(r'              \_ vm Total bytes:  %s' % vm[0])
    my_logger.info(r'              \_ vm Avail bytes:  %s' % vm[1])
    my_logger.info(r'              \_ vm Percent used: %s' % vm[2])
    my_logger.info(r'              \_ vm Total used:   %s' % vm[3])
    my_logger.info(r'              \_ vm Total free:   %s' % vm[4])
    my_logger.info(r'              \_ vm Active:       %s' % vm[5])
    my_logger.info(r'              \_ vm Inactive:     %s' % vm[6])
    my_logger.info(r'              \_ vm Buffered:     %s' % vm[7])
    my_logger.info(r'              \_ vm Cached:       %s' % vm[8])
    my_logger.info('Swap Memory Stats:')
    my_logger.info(r'              \_ sw Total bytes:    %s' % sm[0])
    my_logger.info(r'              \_ sw Used bytes:     %s' % sm[1])
    my_logger.info(r'              \_ sw Free bytes:     %s' % sm[2])
    my_logger.info(r'              \_ sw Percent Used:   %s' % sm[3])
    my_logger.info(r'              \_ sw Swap in bytes:  %s' % sm[4])
    my_logger.info(r'              \_ sw Swap out bytes: %s' % sm[5])

# ---
# ---  Function:
# ---    record_disk_state()
# ---
# ---  Description:
# ---    gather and record information pertaining to the disk resources of the system
# ---
# ---  Parameters:
# ---    NONE
# ---
# ---  Returns:
# ---    NONE -
# ---


def record_disk_state(ms):
    """
        record_disk_state() - gather and record information pertaining to the disk resources of the system
    """

    my_logger.info('Disk Usage Stats:')
    usage_templ = "  %-15s %8s %8s %8s %5s%% %9s  %s"
    my_logger.info(usage_templ % (" Device", "Total", "Used", "Free", "Use ", "Type", "Mount"))

    dp = ms.get_disk_partitions()
    for part in dp:
        usage = ms.get_disk_usage(part.mountpoint)
        my_logger.info(usage_templ % (part.device,
                                   cu.bytes2human(usage.total),
                                   cu.bytes2human(usage.used),
                                   cu.bytes2human(usage.free),
                                   int(usage.percent),
                                   part.fstype,
                                   part.mountpoint))

    my_logger.info('Disk IO Counters:')
    disk_io_ct_templ = "  %-8s %10s %10s %10s %10s %10s  %s"
    my_logger.info(disk_io_ct_templ % (" Device", "Read_Ct", "Write_Ct", "Read_Bytes", "Write_Bytes", "Read_Time ", "Write_Time"))
    dc = ms.get_disk_io_counters()
    for k, v in dc.items():
        my_logger.info(disk_io_ct_templ % (k,
                                    v.read_count,
                                    v.write_count,
                                    v.read_bytes,
                                    v.write_bytes,
                                    v.read_time,
                                    v.write_time))

# ---
# ---  Function:
# ---    record_network_io_counters()
# ---
# ---  Description:
# ---    gather and record information pertaining to the Network IO of the system
# ---
# ---  Parameters:
# ---    NONE
# ---
# ---  Returns:
# ---    NONE -
# ---


def record_network_io_counters(ms):

    my_logger.info('Network IO Counters:')
    nc = ms.get_net_io_counters()
    for k, v in nc.items():
        my_logger.info('  Network Device Name: %s ' % k)
        my_logger.info(r'              \_ ' + k + ' Total bytes sent:   %s' % v.bytes_sent)
        my_logger.info(r'              \_ ' + k + ' Total bytes recv:   %s' % v.bytes_recv)
        my_logger.info(r'              \_ ' + k + ' Total packets sent: %s' % v.packets_sent)
        my_logger.info(r'              \_ ' + k + ' Total packets recv: %s' % v.packets_recv)
        my_logger.info(r'              \_ ' + k + ' Total errors in:    %s' % v.errin)
        my_logger.info(r'              \_ ' + k + ' Total errors out:   %s' % v.errout)
        my_logger.info(r'              \_ ' + k + ' Total dropped in:   %s' % v.dropin)
        my_logger.info(r'              \_ ' + k + ' Total dropped out:  %s' % v.dropout)

# ---
# ---  Function:
# ---    record_disk_io_counters()
# ---
# ---  Description:
# ---    gather and record information pertaining to the disk IO of the processes on the system
# ---
# ---  Parameters:
# ---    NONE
# ---
# ---  Returns:
# ---    NONE -
# ---


def record_disk_io_counters(ms, interval, count):
    """
        record_disk_io_counters() -  gather and record information pertaining to the disk IO of the processes on the system
    """

    my_logger.info('Disk IO Counters per process:')

    disk_io_templ = "%-5s %-7s %8s %8s  %s"

    procs, total_read, total_write = ms.poll_io_stats_per_proc(interval)
    my_logger.info("Total DISK READ: " + cu.bytes2human(total_read) + " | Total DISK WRITE: " + cu.bytes2human(total_write))
    my_logger.info(disk_io_templ % (" PID", "USER", "READ", "WRITE", "COMMAND"))

    count = int(count)
    for p in procs:
        my_logger.info(disk_io_templ % (p.pid,
                            p._username[:8],
                            cu.bytes2human(p._read_per_sec),
                            cu.bytes2human(p._write_per_sec),
                            p._cmdline[:60]))
        count -= 1
        if count <= 0:
            return

# ---
# ---  Function:
# ---    record_process_cpu_info()
# ---
# ---  Description:
# ---    gather and record information pertaining to process cpu usage on a system 
# ---
# ---  Parameters:
# ---    NONE
# ---
# ---  Returns:
# ---    NONE -
# ---


def record_process_cpu_info(ms, count):
    """
        record_process_cpu_info() - gather and record information pertaining to process cpu usage on a system
    """

    my_logger.info('Process CPU Utilization: sort by CPU%')
    processes, procs_status = ms.poll_cpu_info_per_process()

    # processes number and status
    st = []
    for x, y in procs_status.items():
        if y:
            st.append("%s=%s" % (x, y))
    st.sort(key=lambda x: x[:3] in ('run', 'sle'), reverse=1)
    my_logger.info("Processes: %s (%s)" % (len(processes), ' '.join(st)))

    cpu_templ = "%-5s %-7s %4s %8s %8s %6s   %4s %9s  %2s"
    my_logger.info(cpu_templ % (" PID", "USER", "NICE", "VIRT", "RES", "CPU%", "MEM%", "TIME+", "NAME" ))
    count = int(count)

    for p in processes:
        # TIME+ column shows process CPU cumulative time and it is expressed as: "mm:ss.ms"
        ctime = timedelta(seconds=sum(p._cpu_times))
        ctime = "%s:%s.%s" % (ctime.seconds // 60 % 60,
                            str((ctime.seconds % 60)).zfill(2),
                            str(ctime.microseconds)[:2])

        my_logger.info(cpu_templ % (p.pid,
                                p._username[:8],
                                p._nice,
                                cu.bytes2human(p._meminfo.vms),
                                cu.bytes2human(p._meminfo.rss),
                                p._cpu_percent,
                                round(p._mempercent, 1),
                                ctime,
                                p._name[:15]))
        count -= 1

        if count <= 0:
            return

# ---
# ---  FUNCTION:
# ---    main()
# ---
# ---  DESCRIPTION:
# ---    There is the starting point for the linuxBenchmarkTool.
# ---
# ---  PARAMETERS:
# ---    NONE
# ---
# ---  RETURNS:
# ---    NONE - may exit with a status code.
# ---


def main():
    global options
    global configs
    global cu

    # --- before we do any benchmarking, we need some information.
    options = parse_commandline_args()
    configs = read_config_file(options.config)

    initialize_logger()
    check_environment()

    my_logger.info('starting %s' % os.path.basename(__file__) + " ver. " + __VERSION__)
    my_logger.info('environment level:  %s' % environment)

    ms = monitor.system.System()
    cu = common.utilities.Utilities()

    record_general_system_info()
    record_general_cpu_info(ms)
    record_logged_in_user_info(ms)
    record_memory_state(ms)
    record_disk_state(ms)
    record_network_io_counters(ms)

    io_interval = configs.get('disk', 'io_counter_interval')
    io_display_count = configs.get('disk', 'display_count')
    record_disk_io_counters(ms, float(io_interval), io_display_count )

    cpu_display_count = configs.get('cpu', 'display_count')
    record_process_cpu_info(ms,cpu_display_count)

    my_logger.info('ending %s' % os.path.basename(__file__) + " ver. " +  __VERSION__)

if __name__ == '__main__':
    main()
