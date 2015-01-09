
from logging.handlers import TimedRotatingFileHandler
from logging.handlers import MemoryHandler
from subprocess import Popen, PIPE
from datetime import datetime
import traceback as tb
import logging
import sys
import os
import re

from polymer.abc_task import BaseTask
import graphitesend

""" Snmp.py - Snmp module for graphite-gardener
Copyright (C) 2014-2015 David Michael Pennington
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
If you need to contact the author, you can do so by emailing:
mike [~at~] pennington [/dot\] net
"""

class SnmpWalkTask(BaseTask):
    def __init__(self, addr, community, mib, oid, value_type=str, 
        use_netsnmp=True, index=False, row_prune_value='', snmpdata=''):

        super(SnmpWalkTask, self).__init__()
        self.addr = addr
        self.community = community
        self.mib = mib
        self.oid = oid
        self.value_type = value_type
        self.index = index
        self.row_prune_value = row_prune_value
        self.snmpdata = snmpdata    # Name (str) of the snmpdata object
        self.result = {}

    def __eq__(self, other):
        if (other is None):
            return False
        if (self.addr==other.addr) and (self.oid==other.oid) and \
            (self.community==other.community):
            return True
        return False

    def __repr__(self):
        shim = ''
        if self.index:
            shim += ' index'
        if str(self.row_prune_value)!='':
            
            shim += ' prune: "{0}"'.format(getattr(self.row_prune_value, 'pattern', self.row_prune_value))
        return """<SnmpWalkTask: {0} {1} {2}{3}>""".format(self.addr, self.mib,
            self.oid, shim)

    def run(self):
        snmp = NetSnmp(self.addr, self.community)
        return snmp.walktable(self.mib, self.oid, value_type=self.value_type)

class NetSnmp(object):
    def __init__(self, addr, community): 
        self.addr = addr
        self.community = community
        self.TABLE_RE = re.compile(r'^(\S+?)\[(\S+?)\]\s+(.+?)\s*$')

    def walktable(self, mib, oid, value_type=str):
        (addr, community, TABLE_RE) = (self.addr, self.community, self.TABLE_RE)
        if (value_type is int):
            options = "OXsqe"
        else:
            options = "OXsq"
        cmd = "snmpbulkwalk -{0} -v2c -c {1} -m {2} {3} {4}".format(options,
            community, mib, addr, oid)
        proc = Popen(cmd, shell=True, executable='/bin/bash', 
            stdout=PIPE, stderr=PIPE)
        proc_exit = proc.wait()

        if proc_exit>0:
            raise ValueError(''.join(proc.stderr.readlines()))
        retval = {oid:{}}
        for line in proc.stdout.readlines():
            mm = TABLE_RE.search(line.strip())
            if not (mm is None):
                try:
                    retval[mm.group(1)][mm.group(2)] = value_type(mm.group(3))
                except (Exception) as e:
                    raise ValueError("NetSnmp.walktable: Could not finish parsing {0}::{1} on {2}.  Error processing '{3}'".format(mib, oid, addr, line))
        return retval
                
class GraphiteSnmpData(object):
    def __init__(self, host, snmpdata, data, 
        server = "localhost", port=2003,
        escape_character="_", 
        prefix="", dry_run=False):

        self.host = host                   # host name for the stats we send
        self.snmpdata = snmpdata
        self.data = data                   # list of SnmpWalkTask objects
        self.server = server               # Hostname of our graphite server
        self.port = port                   # TCP port to use for updates
        self.escape_character = escape_character
        self.prefix = prefix
        self.dry_run = dry_run
        self.index = None
        self.index_oid = ''                # oid used for indexing the data
        self.row_prune_value = None

        socket = graphitesend.init(graphite_server=self.server,
            graphite_port=self.port,
            prefix=self.prefix, 
            system_name=self.host.name, 
            group='snmp', 
            dryrun=self.dry_run)

        self.parse_index()
        stats_list = self.build_results()

        print socket.send_list(stats_list)


        ## TODO: start here... sort into a dict, rename paths, and send to 
        ##        graphite

    def escape_string(self, value):
        return value.replace('/', self.escape_character)

    def parse_index(self):
        for obj in self.data:
            if getattr(obj, 'index', ''):
                self.index = obj
                self.index_oid = obj.result.keys()[0]
            elif getattr(obj, 'row_prune_value', ''):
                self.row_prune_value = obj

    def build_results(self):
        row_prune_obj = self.row_prune_value
        row_prune_oid = row_prune_obj.result.keys()[0]
        ## Parse data objects into values
        graphite_list = list()
        for obj in self.data:
            ## Reject row prune oid, or the index
            if (obj==self.index) or (obj==row_prune_obj):
                continue

            for oid in obj.result.keys():
                ## oid_alias is what graphite should call the oid
                oid_suffix = self.snmpdata[obj.snmpdata].oids[oid]
                oid_class = self.snmpdata[obj.snmpdata].type_alias
                oid_by_ifindex = obj.result[oid]  # the oid, keyed by ifindex
                for ifindex in oid_by_ifindex.keys():
                    ifname = self.index.result[self.index_oid][ifindex]
                    oid_alias = "{0}.{1}.{2}".format(oid_class, ifname, 
                        oid_suffix)
                    oidvalue = oid_by_ifindex[ifindex]

                    ## reject any rows that match the row_prune_re
                    if not (row_prune_obj is None):
                        prune_val = row_prune_obj.result[row_prune_oid][ifindex]
                        prune_re = self.snmpdata[obj.snmpdata].prune_re
                        match = prune_re.search(prune_val)
                        if not (match is None):
                            # We can safely skip this value... because it should
                            #    be pruned
                            continue
                        else:
                            #print self.prefix, self.host.name, oid, self.index.result[self.index_oid][ifindex], oid_class, oid_alias, oidvalue
                            graphite_list.append((oid_alias, oidvalue, 
                                obj.task_stop))
        return graphite_list
