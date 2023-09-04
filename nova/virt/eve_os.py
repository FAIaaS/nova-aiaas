# Copyright (c) 2023 Oleg Sadov <oleg dot sadov at gmail dot com>
# Copyright (c) 2023 Petr Fedchenkov <giggsoff at gmail dot com>
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
A EVE-OS hypervisor
"""

import collections
import contextlib
import time
import uuid
import re
import os
import paramiko
import pexpect
import time
from scp import SCPClient

import fixtures
import os_resource_classes as orc
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils.fixture import uuidsentinel as uuids
from oslo_utils import versionutils

from nova.compute import power_state
from nova.compute import task_states
from nova.compute import vm_states
import nova.conf
from nova.console import type as ctype
from nova import context as nova_context
from nova import objects as nova_objects
from nova import exception
from nova import objects
from nova.objects import diagnostics as diagnostics_obj
from nova.objects import fields as obj_fields
from nova.objects import migrate_data
from nova.virt import driver
from nova.virt import hardware
from nova.virt import images
from nova.virt.ironic import driver as ironic
import nova.virt.node
from nova.virt import virtapi

CONF = nova.conf.CONF

LOG = logging.getLogger(__name__)

def eden_ssh():
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pkey = paramiko.RSAKey.from_private_key_file(CONF.eve_os.eden_key_file)
    client.connect(hostname=CONF.eve_os.eden_host,
                   port=int(CONF.eve_os.eden_port),
                   username=CONF.eve_os.eden_user,
                   pkey=pkey)
        
    return client

def eden_connect():
    LOG.debug("EDEN eden_connect")
    LOG.debug('EDEN CONF: ')
    for i in CONF.eve_os.items():
        LOG.debug(i)

    try:
        client = eden_ssh()
    except:
        if not os.path.isfile(CONF.eve_os.eden_key_file):
            # Generate SSH key for EDEN host connection
            cmd = "ssh-keygen -P '' -N '' -f " + CONF.eve_os.eden_key_file
            LOG.debug('EDEN cmd: ' + cmd)
            res = os.system(cmd)

            if res != 0:
                raise exception.HypervisorUnavailable()
        # Copy SSH key to EDEN host
        cmd = "ssh-copy-id -f -p %s -i %s %s@%s" % \
            (CONF.eve_os.eden_port,
             CONF.eve_os.eden_key_file,
             CONF.eve_os.eden_user,
             CONF.eve_os.eden_host)
        LOG.debug('EDEN cmd: ' + cmd)
        child = pexpect.spawn(cmd)
        try:
            child.expect('password:')
            child.sendline(CONF.eve_os.eden_password)
            time.sleep(2)
        except:
            raise exception.HypervisorUnavailable()
        try:
            client = eden_ssh()
        except:
            raise exception.HypervisorUnavailable()
        
    return client

def eden_start():
    LOG.debug("EDEN eden_start")
    connect = eden_connect()
    with connect:
        stdin, stdout, stderr = connect.exec_command(
            'cd ' + CONF.eve_os.eden_dir + '; ./eden start')
        if stdout:
            out = stdout.read().decode("utf-8")
            LOG.debug('EDEN stdout: ' + out)
        if stderr:
            out = stderr.read().decode("utf-8")
            LOG.debug('EDEN stderr: ' + out)
            
        return(stdout.channel.recv_exit_status())

def eden_stop():
    LOG.debug("EDEN eden_stop")
    connect = eden_connect()
    with connect:
        stdin, stdout, stderr = connect.exec_command(
            'cd ' + CONF.eve_os.eden_dir + '; ./eden stop')
        if stdout:
            out = stdout.read().decode("utf-8")
            LOG.debug('EDEN stdout: ' + out)
        if stderr:
            out = stderr.read().decode("utf-8")
            LOG.debug('EDEN stderr: ' + out)
            
        return(stdout.channel.recv_exit_status())

def eden_status():
    LOG.debug("EDEN eden_status")
    state = power_state.SHUTDOWN
    connect = eden_connect()
    with connect:
        stdin, stdout, stderr = connect.exec_command(
            'cd ' + CONF.eve_os.eden_dir + '; ./eden status')
        if stdout:
            out = stdout.read().decode("utf-8")
            LOG.debug('EDEN stdout: ' + out)
            state = 'EVE on Qemu status: running with pid ' in out \
                if power_state.RUNNING else power_state.SHUTDOWN
        if stderr:
            out = stderr.read().decode("utf-8")
            LOG.debug('EDEN stderr: ' + out)
            
    LOG.debug('EDEN status: ' + power_state.STATE_MAP[state])
    return(state)

def eden_uuids_list():
    LOG.debug("EDEN eden_uuids_list")    
    uuids = []
    connect = eden_connect()
    with connect:
        stdin, stdout, stderr = connect.exec_command(
            'cd ' + CONF.eve_os.eden_dir + '; ./eden pod ps')
        if stdout:
            out = stdout.read().decode("utf-8").split('\n')
            LOG.debug('EDEN stdout: ' + str(out))
            for app in out[1:]:
                app = app.split()
                print("EDEN app: " + str(app))
                if len(app):
                    uuids.append(app[0])
        if stderr:
            out = stderr.read().decode("utf-8")
            LOG.debug('EDEN stderr: ' + out)

    LOG.debug('EDEN uuids: ' + str(uuids))
    return(uuids)

def eden_state(name):
    LOG.debug("EDEN eden_state")    
    state = None
    connect = eden_connect()
    with connect:
        stdin, stdout, stderr = connect.exec_command(
            'cd ' + CONF.eve_os.eden_dir + '; ./eden pod ps')
        if stdout:
            out = stdout.read().decode("utf-8")
            LOG.debug('EDEN stdout: ' + out)
            search = re.search("^%s\s.*(RUNNING)$" % name, out, re.MULTILINE)
            LOG.debug('EDEN search: ' + str(search))
            if search:
                ename = search.group(0)
                state = power_state.RUNNING
            else:
                state = power_state.SHUTDOWN
        if stderr:
            out = stderr.read().decode("utf-8")
            LOG.debug('EDEN stderr: ' + out)

    LOG.debug('EDEN "%s" state: %s' % (name, power_state.STATE_MAP[state]))
    return(state)

def eden_pod_deploy(name, vcpus, mem, disk, image):
    LOG.debug("EDEN eden_pod_deploy")
    ename=''
    connect = eden_connect()
    eden_cmd = './eden pod deploy --name=' + name + \
        ' --cpus=' + str(vcpus) + ' --memory=' + str(mem)+'MB' + \
        ' --disk-size=' + str(disk)+'GB ' + image
    
    LOG.debug('EDEN cmd: ' + str(eden_cmd))
    
    with connect:
        stdin, stdout, stderr = connect.exec_command(
            'cd ' + CONF.eve_os.eden_dir + '; ' + eden_cmd)
        if stdout:
            out = stdout.read().decode("utf-8")
            LOG.debug('EDEN stdout: ' + out)
            search = re.search("INFO\[\d*\] deploy pod (.*) with .* request sent", out)
            if search:
                ename = search.group(1)
                return(name)
        if stderr:
            out = stderr.read().decode("utf-8")
            LOG.debug('EDEN stderr: ' + out)

    return ename

def eden_pod_delete(name):
    LOG.debug("EDEN eden_pod_delete")
    ename=''
    connect = eden_connect()
    eden_cmd = './eden pod delete ' + name

    LOG.debug('EDEN cmd: ' + str(eden_cmd))
    
    with connect:
        stdin, stdout, stderr = connect.exec_command(
            'cd ' + CONF.eve_os.eden_dir + '; ' + eden_cmd)
        if stdout:
            out = stdout.read().decode("utf-8")
            LOG.debug('EDEN stdout: ' + out)
            search = re.search("INFO\[\d*\] app (.*) delete done",out)
            if search:
                ename = search.group(1)
                return(name)
        if stderr:
            out = stderr.read().decode("utf-8")
            LOG.debug('EDEN stderr: ' + out)

    return ename

def eden_pod_start(name):
    LOG.debug("EDEN eden_pod_start")    
    ename=''
    connect = eden_connect()
    eden_cmd = './eden pod start ' + name

    LOG.debug('EDEN cmd: ' + str(eden_cmd))
    
    with connect:
        stdin, stdout, stderr = connect.exec_command(
            'cd ' + CONF.eve_os.eden_dir + '; ' + eden_cmd)
        if stdout:
            out = stdout.read().decode("utf-8")
            LOG.debug('EDEN stdout: ' + out)
            search = re.search("INFO\[\d*\] app (.*) start done",out)
            if search:
                ename = search.group(1)
                return(name)
        if stderr:
            out = stderr.read().decode("utf-8")
            LOG.debug('EDEN stderr: ' + out)

    return ename

def eden_pod_stop(name):
    LOG.debug("EDEN eden_pod_stop")
    ename=''
    connect = eden_connect()
    eden_cmd = './eden pod stop ' + name

    LOG.debug('EDEN cmd: ' + str(eden_cmd))
    
    with connect:
        stdin, stdout, stderr = connect.exec_command(
            'cd ' + CONF.eve_os.eden_dir + '; ' + eden_cmd)
        if stdout:
            out = stdout.read().decode("utf-8")
            LOG.debug('EDEN stdout: ' + out)
            search = re.search("INFO\[\d*\] app (.*) stop done",out)
            if search:
                ename = search.group(1)
                return(name)
        if stderr:
            out = stderr.read().decode("utf-8")
            LOG.debug('EDEN stderr: ' + out)

    return ename


class EVEInstance(object):

    def __init__(self, name, ename, state, uuid):
        self.name = name
        self.ename = ename
        self.state = state
        self.uuid = uuid

    def __getitem__(self, key):
        return getattr(self, key)


class Resources(object):
    vcpus = 0
    memory_mb = 0
    local_gb = 0
    vcpus_used = 0
    memory_mb_used = 0
    local_gb_used = 0

    def __init__(self, vcpus=8, memory_mb=8000, local_gb=500):
        self.vcpus = vcpus
        self.memory_mb = memory_mb
        self.local_gb = local_gb

    def claim(self, vcpus=0, mem=0, disk=0):
        self.vcpus_used += vcpus
        self.memory_mb_used += mem
        self.local_gb_used += disk

    def release(self, vcpus=0, mem=0, disk=0):
        self.vcpus_used -= vcpus
        self.memory_mb_used -= mem
        self.local_gb_used -= disk

    def dump(self):
        return {
            'vcpus': self.vcpus,
            'memory_mb': self.memory_mb,
            'local_gb': self.local_gb,
            'vcpus_used': self.vcpus_used,
            'memory_mb_used': self.memory_mb_used,
            'local_gb_used': self.local_gb_used
        }


class EVEDriver(driver.ComputeDriver):
    # These must match the traits in
    # nova.tests.functional.integrated_helpers.ProviderUsageBaseTestCase
    capabilities = {
        "has_imagecache": False,
        "supports_evacuate": False,
        "supports_migrate_to_same_host": False,
        "supports_attach_interface": True,
        "supports_device_tagging": True,
        "supports_tagged_attach_interface": True,
        "supports_tagged_attach_volume": True,
        "supports_extend_volume": False,
        "supports_multiattach": True,
        "supports_trusted_certs": True,
        "supports_pcpus": False,
        "supports_accelerators": True,
        "supports_remote_managed_ports": True,

        # Supported image types
        "supports_image_type_raw": True,
        "supports_image_type_qcow2": True,
        "supports_image_type_vmdk": True,
        "supports_image_type_vhdx": True,
        "supports_image_type_docker": True,
        "supports_image_type_vhd": False,
        }

    # Just defaults
    vcpus = 10
    memory_mb = 8000
    local_gb = 100

    """EVE hypervisor driver."""

    def __init__(self, virtapi, read_only=False):
        super(EVEDriver, self).__init__(virtapi)
        self.instances = {}
        self.resources = Resources(
            vcpus=self.vcpus,
            memory_mb=self.memory_mb,
            local_gb=self.local_gb)
        self.host_status_base = {
            'hypervisor_type': 'eve_os',
            'hypervisor_version': versionutils.convert_version_to_int('1.0'),
            'hypervisor_hostname': CONF.host,
            'cpu_info': {},
            'disk_available_least': 0,
            'supported_instances': [(
                obj_fields.Architecture.X86_64,
                obj_fields.HVType.EVE,
                obj_fields.VMMode.HVM)],
            'numa_topology': None,
          }
        self._mounts = {}
        self._interfaces = {}
        self._host = None
        self._nodes = None

    def init_host(self, host):
        LOG.debug("EDEN init_host: " + str(host))
        self._host = host
        # NOTE(gibi): this is unnecessary complex and fragile but this is
        # how many current functional sample tests expect the node name.
        self._set_nodes(['eve-mini'] if self._host == 'compute'
                        else [self._host])
        eden_start()

    def _set_nodes(self, nodes):
        # NOTE(gibi): this is not part of the driver interface but used
        # by our tests to customize the discovered nodes by the eve
        # driver.
        self._nodes = nodes

    def get_info(self, instance, use_cache=True):
        LOG.debug("EDEN get_info %s (%s)" % (instance.display_name, instance.uuid))
        state = eden_state(instance.uuid)
        return hardware.InstanceInfo(state=state)

    def list_instances(self):
        LOG.debug("EDEN list_instances: ")
        ctx = nova_context.get_admin_context()
        for uuid in eden_uuids_list():
            instance = nova_objects.Instance.get_by_uuid(ctx, uuid)
            LOG.debug("%s: %s" % (uuid, instance.name))
        instances = [nova_objects.Instance.get_by_uuid(ctx, uuid).name for uuid in eden_uuids_list()]
        LOG.debug("EDEN instances: " + str(instances))
        
        return instances

    def list_instance_uuids(self):
        LOG.debug("EDEN list_instance_uuids")
        return eden_uuids_list()

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        LOG.debug("EDEN plug_vifs")

    def unplug_vifs(self, instance, network_info):
        """Unplug VIFs from networks."""
        LOG.debug("EDEN unplug_vifs")

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, allocations, network_info=None,
              block_device_info=None, power_on=True, accel_info=None):

        if network_info:
            for vif in network_info:
                # simulate a real driver triggering the async network
                # allocation as it might cause an error
                vif.fixed_ips()
                # store the vif as attached so we can allow detaching it later
                # with a detach_interface() call.
                self._interfaces[vif['id']] = vif

        uuid = instance.uuid
        ename = instance.uuid
        LOG.debug("EDEN spawn %s (%s)" % (ename, uuid))

        flavor = instance.flavor
        self.resources.claim(
            vcpus=flavor.vcpus,
            mem=flavor.memory_mb,
            disk=flavor.root_gb)

        # Download image
        LOG.debug("EDEN Image META: " + str(image_meta))
        image_path = os.path.join(os.path.normpath(CONF.eve_os.image_tmp_path),
                                  image_meta.id)
        eden_image_path = os.path.join(
            os.path.normpath(CONF.eve_os.eden_tmp_path), image_meta.name)
        LOG.debug("EDEN image_path: " + image_path)
        LOG.debug("EDEN eden_image_path: " + eden_image_path)
        if not os.path.exists(image_path):
            LOG.debug("Downloading the image %s from glance to nova compute "
                      "server", image_path)
            images.fetch(context, image_meta.id, image_path)

        # Copy image to EDEN host
        connect = eden_connect()
        scp = SCPClient(connect.get_transport())
        scp.put(image_path, eden_image_path)
            
        ename = eden_pod_deploy(ename, flavor.vcpus, flavor.memory_mb,
                                flavor.root_gb, eden_image_path)

        state = eden_state(ename)
        
        eve_instance = EVEInstance(instance.name, ename, state, uuid)
        self.instances[uuid] = eve_instance
        
    def destroy(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, destroy_secrets=True):
        key = instance.uuid
        name = instance.uuid
        LOG.debug("EDEN destroy %s (%s)" % (name, key))
        if key in self.instances:
            name = eden_pod_delete(name)
            flavor = instance.flavor
            self.resources.release(
                vcpus=flavor.vcpus,
                mem=flavor.memory_mb,
                disk=flavor.root_gb)
            del self.instances[key]
        else:
            LOG.warning("Key '%(key)s' not in instances '%(inst)s'",
                        {'key': key,
                         'inst': self.instances}, instance=instance)

    def reboot(self, context, instance, network_info, reboot_type,
               block_device_info=None, bad_volumes_callback=None,
               accel_info=None):
        LOG.debug("EDEN reboot")
        LOG.debug("EDEN instance: " + str(instance.uuid))
        LOG.debug("EDEN instances: " + str(self.instances.keys()))
        # If the guest is not on the hypervisor and we're doing a hard reboot
        # then mimic the libvirt driver by spawning the guest.
        if (instance.uuid not in self.instances and
                reboot_type.lower() == 'hard'):
            injected_files = admin_password = allocations = None
            self.spawn(context, instance, instance.image_meta, injected_files,
                       admin_password, allocations,
                       block_device_info=block_device_info)
        else:
            # Just try to power on the guest.
            self.power_on(context, instance, network_info,
                          block_device_info=block_device_info)

    def get_host_ip_addr(self):
        return CONF.my_ip

    def poll_rebooting_instances(self, timeout, instances):
        LOG.debug("EDEN poll_rebooting_instances")

    def power_off(self, instance, timeout=0, retry_interval=0):
        LOG.debug("EDEN power_off")
        eden_pod_stop(instance.uuid)

    def power_on(self, context, instance, network_info,
                 block_device_info=None, accel_info=None):
        LOG.debug("EDEN power_on")
        eden_pod_start(instance.uuid)

    def pause(self, instance):
        LOG.debug("EDEN pause")
        eden_pod_stop(instance.uuid)

    def unpause(self, instance):
        LOG.debug("EDEN unpause")
        eden_pod_start(instance.uuid)

    def suspend(self, context, instance):
        LOG.debug("EDEN suspend")
        eden_pod_stop(instance.uuid)

    def resume(self, context, instance, network_info, block_device_info=None):
        LOG.debug("EDEN resume")
        eden_pod_start(instance.uuid)

    def cleanup(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None, destroy_vifs=True,
                destroy_secrets=True):
        # cleanup() should not be called when the guest has not been destroyed.
        LOG.debug("EDEN cleanup")

    def attach_volume(self, context, connection_info, instance, mountpoint,
                      disk_bus=None, device_type=None, encryption=None):
        """Attach the disk to the instance at mountpoint using info."""
        instance_name = instance.name
        if instance_name not in self._mounts:
            self._mounts[instance_name] = {}
        self._mounts[instance_name][mountpoint] = connection_info

    def detach_volume(self, context, connection_info, instance, mountpoint,
                      encryption=None):
        """Detach the disk attached to the instance."""
        try:
            del self._mounts[instance.name][mountpoint]
        except KeyError:
            pass

    def swap_volume(self, context, old_connection_info, new_connection_info,
                    instance, mountpoint, resize_to):
        """Replace the disk attached to the instance."""
        instance_name = instance.name
        if instance_name not in self._mounts:
            self._mounts[instance_name] = {}
        self._mounts[instance_name][mountpoint] = new_connection_info

    def extend_volume(self, context, connection_info, instance,
                      requested_size):
        """Extend the disk attached to the instance."""
        pass

    def attach_interface(self, context, instance, image_meta, vif):
        if vif['id'] in self._interfaces:
            raise exception.InterfaceAttachFailed(
                    instance_uuid=instance.uuid)
        self._interfaces[vif['id']] = vif

    def detach_interface(self, context, instance, vif):
        try:
            del self._interfaces[vif['id']]
        except KeyError:
            raise exception.InterfaceDetachFailed(
                    instance_uuid=instance.uuid)

    def get_diagnostics(self, instance):
        return {'cpu0_time': 17300000000,
                'memory': 524288,
                'vda_errors': -1,
                'vda_read': 262144,
                'vda_read_req': 112,
                'vda_write': 5778432,
                'vda_write_req': 488,
                'vnet1_rx': 2070139,
                'vnet1_rx_drop': 0,
                'vnet1_rx_errors': 0,
                'vnet1_rx_packets': 26701,
                'vnet1_tx': 140208,
                'vnet1_tx_drop': 0,
                'vnet1_tx_errors': 0,
                'vnet1_tx_packets': 662,
        }

    def get_instance_diagnostics(self, instance):
        diags = diagnostics_obj.Diagnostics(
            #state=power_state.STATE_MAP[eden_state(instance.display_name)],
            state=power_state.STATE_MAP[eden_state(instance.uuid)],
            driver='eve_os', hypervisor='eve_os',
            hypervisor_os='ubuntu', uptime=46664, config_drive=True)
        diags.add_cpu(id=0, time=17300000000, utilisation=15)
        diags.add_nic(mac_address='01:23:45:67:89:ab',
                      rx_octets=2070139,
                      rx_errors=100,
                      rx_drop=200,
                      rx_packets=26701,
                      rx_rate=300,
                      tx_octets=140208,
                      tx_errors=400,
                      tx_drop=500,
                      tx_packets = 662,
                      tx_rate=600)
        diags.add_disk(read_bytes=262144,
                       read_requests=112,
                       write_bytes=5778432,
                       write_requests=488,
                       errors_count=1)
        diags.memory_details = diagnostics_obj.MemoryDiagnostics(
            maximum=524288, used=0)
        return diags

    def get_all_volume_usage(self, context, compute_host_bdms):
        """Return usage info for volumes attached to vms on
           a given host.
        """
        volusage = []
        if compute_host_bdms:
            volusage = [{'volume': compute_host_bdms[0][
                                       'instance_bdms'][0]['volume_id'],
                         'instance': compute_host_bdms[0]['instance'],
                         'rd_bytes': 0,
                         'rd_req': 0,
                         'wr_bytes': 0,
                         'wr_req': 0}]

        return volusage

    def get_host_cpu_stats(self):
        stats = {'kernel': 5664160000000,
                'idle': 1592705190000000,
                'user': 26728850000000,
                'iowait': 6121490000000}
        stats['frequency'] = 800
        return stats

    def block_stats(self, instance, disk_id):
        return [0, 0, 0, 0, None]

    def get_console_output(self, context, instance):
        return 'EVE CONSOLE OUTPUT\nANOTHER\nLAST LINE'

    def get_vnc_console(self, context, instance):
        return ctype.ConsoleVNC(internal_access_path='FAKE',
                                host='evevncconsole.com',
                                port=6969)
    def get_serial_console(self, context, instance):
        return ctype.ConsoleSerial(internal_access_path='FAKE',
                                   host='everdpconsole.com',
                                   port=6969)

    def get_available_resource(self, nodename):
        """Updates compute manager resource info on ComputeNode table.

           Since we don't have a real hypervisor, pretend we have lots of
           disk and ram.
        """
        cpu_info = collections.OrderedDict([
            ('arch', 'x86_64'),
            ('model', 'Nehalem'),
            ('vendor', 'Intel'),
            ('features', ['pge', 'clflush']),
            ('topology', {
                'cores': 1,
                'threads': 1,
                'sockets': 4,
                }),
            ])
        if nodename not in self.get_available_nodes():
            return {}

        host_status = self.host_status_base.copy()
        host_status.update(self.resources.dump())
        host_status['hypervisor_hostname'] = nodename
        host_status['host_hostname'] = nodename
        host_status['host_name_label'] = nodename
        host_status['cpu_info'] = jsonutils.dumps(cpu_info)
        # NOTE(danms): Because the eve driver runs on the same host
        # in tests, potentially with multiple nodes, we need to
        # control our node uuids. Make sure we return a unique and
        # consistent uuid for each node we are responsible for to
        # avoid the persistent local node identity from taking over.
        host_status['uuid'] = str(getattr(uuids, 'node_%s' % nodename))
        return host_status

    def update_provider_tree(self, provider_tree, nodename, allocations=None):
        # NOTE(yikun): If the inv record does not exists, the allocation_ratio
        # will use the CONF.xxx_allocation_ratio value if xxx_allocation_ratio
        # is set, and fallback to use the initial_xxx_allocation_ratio
        # otherwise.
        inv = provider_tree.data(nodename).inventory
        ratios = self._get_allocation_ratios(inv)
        inventory = {
            'VCPU': {
                'total': self.vcpus,
                'min_unit': 1,
                'max_unit': self.vcpus,
                'step_size': 1,
                'allocation_ratio': ratios[orc.VCPU],
                'reserved': CONF.reserved_host_cpus,
            },
            'MEMORY_MB': {
                'total': self.memory_mb,
                'min_unit': 1,
                'max_unit': self.memory_mb,
                'step_size': 1,
                'allocation_ratio': ratios[orc.MEMORY_MB],
                'reserved': CONF.reserved_host_memory_mb,
            },
            'DISK_GB': {
                'total': self.local_gb,
                'min_unit': 1,
                'max_unit': self.local_gb,
                'step_size': 1,
                'allocation_ratio': ratios[orc.DISK_GB],
                'reserved': self._get_reserved_host_disk_gb_from_config(),
            },
        }
        provider_tree.update_inventory(nodename, inventory)

    def get_instance_disk_info(self, instance, block_device_info=None):
        return

    def host_power_action(self, action):
        """Reboots, shuts down or powers up the host."""
        LOG.debug("EDEN host_power_action: " + str(action))
        return action

    def host_maintenance_mode(self, host, mode):
        """Start/Stop host maintenance window. On start, it triggers
        guest VMs evacuation.
        """
        if not mode:
            return 'off_maintenance'
        return 'on_maintenance'

    def set_host_enabled(self, enabled):
        """Sets the specified host's ability to accept new instances."""
        if enabled:
            return 'enabled'
        return 'disabled'

    def get_volume_connector(self, instance):
        return {'ip': CONF.my_block_storage_ip,
                'initiator': 'eve',
                'host': self._host}

    def get_available_nodes(self, refresh=False):
        return self._nodes

    def get_nodenames_by_uuid(self, refresh=False):
        return {str(getattr(uuids, 'node_%s' % n)): n
                for n in self.get_available_nodes()}

    def instance_on_disk(self, instance):
        return False

class EVEDriverWithoutEVENodes(EVEDriver):
    """EVEDriver that behaves like a real single-node driver.

    This behaves like a real virt driver from the perspective of its
    nodes, with a stable nodename and use of the global node identity
    stuff to provide a stable node UUID.
    """

    def get_available_resource(self, nodename):
        resources = super().get_available_resource(nodename)
        resources['uuid'] = nova.virt.node.get_local_node_uuid()
        return resources

    def get_nodenames_by_uuid(self, refresh=False):
        return {
            nova.virt.node.get_local_node_uuid(): self.get_available_nodes()[0]
        }
