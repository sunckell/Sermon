'''
Created on Sep 24, 2012

@author: ckell
'''
from datetime import timedelta
import socket
import platform
import psutil
import time


class System(object):
    """
    System Class - provides definitions that relate to system readings.
    """

    def __init__(self):
        """
        Constructor
        """

    @property
    def get_uptime(self):
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
            uptime_string = str(timedelta(seconds = uptime_seconds))
            return uptime_string

    @property
    def get_platform_info(self):
        """
        getPlatformInfo = returns a dictionary filled with platform specific information.
        """

        p = {'machine': platform.machine(), 'node': platform.node(), 'release': platform.release(),
             'distribution': platform.linux_distribution()}

        return p

    @property
    def get_cpu_count(self):
        return psutil.NUM_CPUS

    @property
    def get_cpu_util_per_cpu(self):
        return psutil.cpu_percent(interval=0, percpu=True)

    def get_memory_info(self):
        return psutil.virtual_memory()

    def get_swap_info(self):
        return psutil.swap_memory()

    def get_disk_partitions(self):
        return psutil.disk_partitions(all=False)

    def get_disk_usage(self,m):
        return psutil.disk_usage(m)

    @staticmethod
    def get_disk_io_counters():
        return psutil.disk_io_counters(perdisk=True)

    def get_net_io_counters(self):
        return psutil.network_io_counters(pernic=True)

    def get_users(self):
        return psutil.get_users()

    def get_ip_addresses(self):
        return [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1]

    def poll_io_stats_per_proc(self,interval):
        """
            Calculate IO usage by comparing IO statics before and after the interval.
            Return a tuple including all currently running processes Return a tuple 
            including all currently running processes
        """

        # first get a list of all processes and disk io counters
        procs = [p for p in psutil.process_iter()]
        for p in procs[:]:
            try:
                p._before = p.get_io_counters()
            except psutil.Error:
                procs.remove(p)
                continue
        disks_before = psutil.disk_io_counters()

        # sleep some time
        time.sleep(interval)

        # then retrieve the same info again
        for p in procs[:]:
            try:
                p._after = p.get_io_counters()
                p._cmdline = ' '.join(p.cmdline)
                if not p._cmdline:
                    p._cmdline = p.name
                p._username = p.username
            except psutil.NoSuchProcess:
                procs.remove(p)
        disks_after = psutil.disk_io_counters()

        # finally calculate results by comparing data before and after the interval
        for p in procs:
            p._read_per_sec  = p._after.read_bytes - p._before.read_bytes
            p._write_per_sec = p._after.write_bytes - p._before.write_bytes
            p._total = p._read_per_sec + p._write_per_sec

        disks_read_per_sec  = disks_after.read_bytes - disks_before.read_bytes
        disks_write_per_sec = disks_after.write_bytes - disks_before.write_bytes

        # sort processes by total disk IO so that the more intensive ones get listed first
        processes = sorted(procs, key=lambda p: p._total, reverse=True)

        return (processes, disks_read_per_sec, disks_write_per_sec)

    def poll_cpu_info_per_process(self):
        """
            Gather CPU usages via TOP style.
        """

        procs = [p for p in psutil.process_iter()]  # the current process list
        #cpids = [p.pid for p in procs]     
        #for p in psutil.process_iter():         
        #    if p.pid not in cpids:             
        #        procs.append(p)      
        # sleep some time     
        time.sleep(2) 

        procs_status = {}

        for p in procs[:]:
            try:
                p._username    = p.username
                p._nice        = p.nice
                p._meminfo     = p.get_memory_info()
                p._mempercent  = p.get_memory_percent()
                p._cpu_percent = p.get_cpu_percent(interval=0)
                p._cpu_times   = p.get_cpu_times()
                p._name        = p.name
                try:
                    procs_status[str(p.status)] += 1
                except KeyError:
                    procs_status[str(p.status)] = 1
            except psutil.NoSuchProcess:
                procs.remove(p)

        # return processes sorted by CPU percent usage
        processes = sorted(procs, key=lambda p: p._cpu_percent, reverse=True)
        return (processes, procs_status) 
