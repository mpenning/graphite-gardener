from multiprocessing import Process, Queue
from Queue import Empty, Full
from datetime import datetime
from copy import deepcopy
import json
import time
import re

from Snmp import SnmpWalkTask, GraphiteSnmpData
from polymer.Polymer import ControllerQueue, TaskMgr

""" Gardener.py - Prune unwanted interfaces from your graphite polls
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

class SnmpData(object):
    def __init__(self, input):
        self.name = input.get('name', "")
        self.mib = input.get('mib', "")
        self.table = input.get('table', False)
        self.index = input.get('index', "")
        self.row_prune_oid = input.get('row_prune_oid', "")
        self.row_prune_value = input.get('row_prune_value', "")
        self.type_alias = input.get('type_alias', "")
        self.oids = input.get('oids', "")
        self.instance_prefix = input.get('instance_prefix', "")

        self.prune_re = re.compile(self.row_prune_value, re.I)
        self.config = {'name': self.name,
            'mib': self.mib,
            'table': self.table,
            'index': self.index,
            'row_prune_oid': self.row_prune_oid,
            'row_prune_value': self.row_prune_value,
            'type_alias': self.type_alias,
            'oids': self.oids,
            'instance_prefix': self.instance_prefix,
        }

    def __repr__(self):
        return """<SnmpData '{0}' index: {1}>""".format(self.name, self.index)

    def __eq__(self, other):
        ## Consider 'other' the same object, if index is the same
        if (self.index.lower()==other.index.lower()):
            return True
        return False

class Host(object):
    def __init__(self, input):
        self.name = input.get('name', "")
        self.addr = input.get('addr', "")
        self.community = input.get('community', "")
        self.interval = input.get('interval', 0)
        self.snmpdata_names = input.get('snmpdata_names', [])
        assert self.snmpdata_names!=[]

        self.state = "__INIT__"
        self.snmptasks = set([])                 # Allocate task objs here
        self.metrics = dict()
        self.last_poll = datetime(1970, 1, 1)    # last poll cycle start
        self.config = {'name': self.name,
            'addr': self.addr,
            'community': self.community,
            'interval': self.interval,
            'snmpdata_names': self.snmpdata_names}

    def __repr__(self):
        return """<Host '{0}'>""".format(self.name)

    def __eq__(self, other):
        ## Consider 'other' the same object, if names are the same
        if (self.name.lower()==other.name.lower()):
            return True
        return False

    @property
    def _hash_value(self):
        return self.name.lower()

    def __hash__(self):
        return hash(self._hash_value)

class Controller(object):
    """Read graphite poll data from config file, and poll devices.  This
       uses several specialized processes.

                               poll
                               tasks            task
        poll_all_snmp_tasks() <-----> TaskMgr()<----> Worker()
         ^                      c_q   |
         |                            | task
         |                            +<----> Worker()
         |
     Controller()

    1.  One processes acts as a controller, reads the config, and spawns
        poll_all_snmp_tasks()
    2.  poll_all_snmp_tasks() builds
    """
    def __init__(self, configfile='graphitepoll.json'):
        assert configfile!=''
        try:
            config = json.load(open(configfile))
        except (Exception) as e:
            raise ValueError, "Cannot open '{0}': {1}".format(configfile, e)

        ## Read json configuration file
        self.config = config
        self.worker_count       = config['worker_count']         # Required
        self.worker_cycle_sleep = config['worker_cycle_sleep']   # Required
        self.escape_character   = config['escape_character']     # Required
        self.graphite_prefix    = config['graphite_prefix']      # Required
        self.graphite_server    = config['graphite_server']      # Required
        self.graphite_port      = config['graphite_port']        # Required

        self.hosts = self._init_hosts()       # dict of Host objs, keyed by addr
        self.snmpdata = self._init_snmpdata() # convert to SnmpData objects

        ## Spawn Polymer's TaskMgr in a hot loop
        c_q = ControllerQueue()
        task_proc = Process(target=TaskMgr, 
            kwargs={'queue':c_q, 'hot_loop':True, 'log_level': 2,
            'log_interval': 60,
            'worker_count': self.worker_count, 
            'worker_cycle_sleep': self.worker_cycle_sleep,
            })
        task_proc.start()

        ## Send poll tasks to Polymer's TaskMgr
        tasks = self.build_snmp_tasks()
        poll_proc = Process(target=self.poll_all_snmp_tasks, 
            kwargs={'c_q': c_q, 'tasks': tasks})
        poll_proc.start()

        poll_proc.join()
        task_proc.join()

    def poll_all_snmp_tasks(self, c_q, tasks):
        exec_times = list()                # Keep execution time stats
        finished_tasks = deepcopy(tasks)   # Built an object to keep track of
                                           #    this poll
        while True:
            ## Send tasks to the task manager on a schedule
            for host_addr in tasks.keys():
                interval = self.hosts[host_addr].interval
                delta_last_poll = (datetime.now() -
                    self.hosts[host_addr].last_poll).seconds

                ## Is it time to run the task?
                if delta_last_poll>=interval:
                    ## Queue a task list to the TaskMgr process
                    c_q.from_q.put(finished_tasks[host_addr])
                    ## Reset all known tasks for this host...
                    finished_tasks[host_addr] = list() # reset results
                    finished = False
                else:
                    finished = True
                    time.sleep(self.calc_wait_time(c_q, exec_times, 
                        finished_tasks))

            ## Read tasks from the task manager
            while not finished:
                try:
                    ## Poll queue for completed task
                    task = c_q.to_q.get_nowait()
                    finished_tasks[task.addr].append(task)
                    exec_times.append(task.task_stop - task.task_start)

                    ## Check whether we are finished with this host...
                    num_tasks_required = len(tasks[task.addr])
                    num_tasks_finished = len(finished_tasks[task.addr])
                    if num_tasks_finished==num_tasks_required:
                        ## Record time of this poll
                        self.hosts[task.addr].last_poll = datetime.now()

                        ## Write to graphite
                        GraphiteSnmpData(self.hosts[task.addr],
                            self.snmpdata,
                            finished_tasks[task.addr],
                            server=self.graphite_server,
                            port=self.graphite_port,
                            prefix=self.graphite_prefix,
                            escape_character=self.escape_character,
                            dry_run=True)

                        ## Reset finished_tasks
                        finished_tasks[task.addr] = deepcopy(tasks[task.addr])
                        finished = True
                except Empty:
                    exec_times = exec_times[-400:]  # Only keep the last 400
                    time.sleep(self.calc_wait_time(c_q, exec_times, 
                        finished_tasks))


    def calc_wait_time(self, c_q, exec_times, finished_tasks):
        """Calculate the loop wait time"""
        num_samples = float(len(exec_times))
        num_tasks = sum([len(finished_tasks[addr]) for addr in finished_tasks.keys()])
        if num_samples>0.0:
            queue_size = max(c_q.from_q.qsize(),1.0)
            min_task_time = min(exec_times)
            try:
                wait_time = min_task_time/(num_tasks*queue_size)
            except:
                wait_time = 0.00001   # Default to 10us
        else:
            wait_time = 0.00001       # Default to 10us
      
        return wait_time

    def _init_snmpdata(self):
        """Return a dictionary of SnmpData objects, keyed by their name"""
        snmpdata = dict()
        for vals in self.config.get('snmpdata', {}):
            obj = SnmpData(vals)
            if snmpdata.get(obj.name, False):
                # We already have an entry for this ...
                raise ValueError
            snmpdata[obj.name] = obj
        assert snmpdata!={}, "FATAL: 'snmpdata' was not specified correctly in the config"
        return snmpdata

    def _init_hosts(self):
        """Return a dictionary of Host objects, keyed by their addr"""
        hosts = dict()
        for vals in self.config.get('hosts', {}):
            obj = Host(vals)
            if hosts.get(obj.addr, False):
                # We already have an entry for this host...
                raise ValueError
            hosts[obj.addr] = obj
        return hosts

    def build_snmp_tasks(self):
        """return a dict of host tasks, tiered by poll interval and host addr"""
        ## Algorithm: allocate hosts on a schedule
        ##            allocate tasks for each host
        all_tasks = dict()
        all_hosts = self.hosts.keys()
        for host_addr in all_hosts:
            host_tasks = list()
            # host_name will be a string key into the self.hosts dict
            for snmpdata_name in self.hosts[host_addr].config['snmpdata_names']:
                # snmpdata_name is a string key into the 
                host_obj = self.hosts[host_addr]
                snmpdata_obj = self.snmpdata[snmpdata_name]

                ## Append an index task
                index_task = SnmpWalkTask(host_addr,
                    host_obj.community,
                    snmpdata_obj.mib,
                    snmpdata_obj.index,
                    index = True,
                    snmpdata=snmpdata_name,
                    value_type=str)
                host_tasks.append(index_task)

                ## Append a task to find values that we use for pruning
                prune_task = SnmpWalkTask(host_addr,
                    host_obj.community,
                    snmpdata_obj.mib,
                    snmpdata_obj.row_prune_oid,
                    row_prune_value = snmpdata_obj.row_prune_value,
                    snmpdata=snmpdata_name,
                    value_type=str)
                host_tasks.append(prune_task)

                ## Append one task per oid
                for oid in snmpdata_obj.oids:
                    task = SnmpWalkTask(host_addr,
                        host_obj.community,
                        snmpdata_obj.mib, 
                        oid,
                        snmpdata=snmpdata_name,
                        value_type=str)
                    host_tasks.append(task)

                all_tasks[host_addr] = host_tasks
        return all_tasks

if __name__=="__main__":
    Controller()
