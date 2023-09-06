# Copyright (c) 2023 Oleg Sadov <oleg dot sadov at gmail dot com>
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
# Copyright (c) 2010 Citrix Systems, Inc.
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
A EVE-OS hypervisor+api.
"""

import collections
import contextlib
import os
import re
import time

import os_resource_classes as orc
import os_vif
import paramiko
import pexpect
import vif_plug_ovs.linux_net
import vif_plug_ovs.linux_net
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import versionutils
from oslo_utils.fixture import uuidsentinel as uuids
from scp import SCPClient

import nova.conf
import nova.virt.node
from nova import context as nova_context
from nova import exception
from nova import objects
from nova.compute import power_state
from nova.compute import task_states
from nova.console import type as ctype
from nova.i18n import _
from nova.network import model
from nova.network import os_vif_util
from nova.objects import diagnostics as diagnostics_obj
from nova.objects import fields as obj_fields
from nova.objects import migrate_data
from nova.virt import driver
from nova.virt import hardware
from nova.virt import images
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


# https://github.com/lf-edge/eden/blob/master/docs/tap.md#create-network-and-application
EVE_TAP_NET = "tap-net"

# bridge has connectivity with EVE-OS tap-net
EVE_LOCAL_BRIDGE = "br-eve"

EVE_VETH_MTU = 1450


def eden_connect():
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


def eden_status():
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

    LOG.debug('EDEN status: ' + str(state))
    return (state)


def eden_start():
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

        return (stdout.channel.recv_exit_status())


def eden_stop():
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

        return (stdout.channel.recv_exit_status())


def eden_state(name):
    state = None
    connect = eden_connect()
    with connect:
        stdin, stdout, stderr = connect.exec_command(
            'cd ' + CONF.eve_os.eden_dir + '; ./eden pod ps')
        if stdout:
            out = stdout.read().decode("utf-8")
            LOG.debug('EDEN stdout: ' + out)
            search = re.search("^%s " % name, out, re.MULTILINE)
            if search:
                ename = search.group(1)
                state = power_state.RUNNING
            else:
                state = power_state.SHUTDOWN
        if stderr:
            out = stderr.read().decode("utf-8")
            LOG.debug('EDEN stderr: ' + out)

    return (state)


def eden_pod_deploy(name, vcpus, mem, disk, image, mac_addresses=None):
    ename = ''
    connect = eden_connect()
    network_line = " ".join(["--networks=" + EVE_TAP_NET + ":" + mac for mac in mac_addresses])
    eden_cmd = './eden pod deploy --name=' + name + \
               ' --cpus=' + str(vcpus) + ' --memory=' + str(mem) + 'MB ' + \
               network_line + \
               ' --disk-size=' + str(disk) + 'GB ' + image

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
                return (name)
        if stderr:
            out = stderr.read().decode("utf-8")
            LOG.debug('EDEN stderr: ' + out)

    return ename


def eden_pod_delete(name):
    ename = ''
    connect = eden_connect()
    eden_cmd = './eden pod delete ' + name

    LOG.debug('EDEN cmd: ' + str(eden_cmd))

    with connect:
        stdin, stdout, stderr = connect.exec_command(
            'cd ' + CONF.eve_os.eden_dir + '; ' + eden_cmd)
        if stdout:
            out = stdout.read().decode("utf-8")
            LOG.debug('EDEN stdout: ' + out)
            search = re.search("INFO\[\d*\] app (.*) delete done", out)
            if search:
                ename = search.group(1)
                return (name)
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


class EVEVIFDriver(object):
    def __init__(self):
        pass

    def plug(self, instance, vif):
        vif_type = vif['type']
        if vif_type == model.VIF_TYPE_OVS:
            vif = os_vif_util.nova_to_osvif_vif(vif)
            instance = os_vif_util.nova_to_osvif_instance(instance)
            LOG.warning("Plugging vif %(vif)s to %(instance)s", {'vif': vif, 'instance': instance})
            os_vif.plug(vif, instance)
            veth_1 = ("ev1%s" % vif.id)[:model.NIC_NAME_LEN]
            veth_2 = ("ev2%s" % vif.id)[:model.NIC_NAME_LEN]
            LOG.warning("Creating veth pair %(v1)s to %(v2)s",
                        {'v1': veth_1, 'v2': veth_2})
            vif_plug_ovs.linux_net.create_veth_pair(veth_1, veth_2, EVE_VETH_MTU)
            vif_plug_ovs.linux_net.add_bridge_port(vif.bridge_name, veth_1)
            vif_plug_ovs.linux_net.add_bridge_port(EVE_LOCAL_BRIDGE, veth_2)
            LOG.warning("Plugging vif %(vif)s to %(instance)s done", {'vif': vif, 'instance': instance})
        else:
            reason = _("Failed to plug virtual interface: "
                       "unexpected vif_type=%s") % vif_type
            raise exception.VirtualInterfacePlugException(reason)

    def unplug(self, instance, vif):
        vif_type = vif['type']
        if vif_type == model.VIF_TYPE_OVS:
            vif = os_vif_util.nova_to_osvif_vif(vif)
            instance = os_vif_util.nova_to_osvif_instance(instance)
            veth_1 = ("ev1%s" % vif.id)[:model.NIC_NAME_LEN]
            veth_2 = ("ev2%s" % vif.id)[:model.NIC_NAME_LEN]
            vif_plug_ovs.linux_net.delete_net_dev(veth_1)
            vif_plug_ovs.linux_net.delete_net_dev(veth_2)
            os_vif.unplug(vif, instance)
        else:
            reason = _("unexpected vif_type=%s") % vif_type
            raise exception.VirtualInterfaceUnplugException(reason=reason)


class EVEDriver(driver.ComputeDriver):
    # These must match the traits in
    # nova.tests.functional.integrated_helpers.ProviderUsageBaseTestCase
    capabilities = {
        "has_imagecache": True,
        "supports_evacuate": True,
        "supports_migrate_to_same_host": False,
        "supports_attach_interface": True,
        "supports_device_tagging": True,
        "supports_tagged_attach_interface": True,
        "supports_tagged_attach_volume": True,
        "supports_extend_volume": True,
        "supports_multiattach": True,
        "supports_trusted_certs": True,
        "supports_pcpus": False,
        "supports_accelerators": True,
        "supports_remote_managed_ports": True,

        # Supported image types
        "supports_image_type_raw": False,
        "supports_image_type_qcow2": True,
        "supports_image_type_docker": True,
        "supports_image_type_vhd": False,
    }

    # Since we don't have a real hypervisor, pretend we have lots of
    # disk and ram so this driver can be used to test large instances.
    vcpus = 1000
    memory_mb = 800000
    local_gb = 600000

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
        self.active_migrations = {}
        self._host = None
        self._nodes = None
        self._vif_driver = EVEVIFDriver()

    def init_host(self, host):
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
        if instance.uuid not in self.instances:
            raise exception.InstanceNotFound(instance_id=instance.uuid)
        i = self.instances[instance.uuid]
        # return hardware.InstanceInfo(state=i.state)
        state = eden_state(i.ename)
        return hardware.InstanceInfo(state=state)

    def list_instances(self):
        return [self.instances[uuid].name for uuid in self.instances.keys()]

    def list_instance_uuids(self):
        return list(self.instances.keys())

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        LOG.warning("plug_vifs Plugging network_info %(network_info)s to %(instance)s",
                    {'network_info': network_info, 'instance': instance})
        if network_info:
            for vif in network_info:
                self._vif_driver.plug(instance, vif)

    def unplug_vifs(self, instance, network_info):
        """Unplug VIFs from networks."""
        LOG.warning("unplug_vifs unPlugging network_info %(network_info)s to %(instance)s",
                    {'network_info': network_info, 'instance': instance})
        if network_info:
            for vif in network_info:
                self._vif_driver.unplug(instance, vif)

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, allocations, network_info=None,
              block_device_info=None, power_on=True, accel_info=None):

        mac_addresses = []

        if network_info:
            for vif in network_info:
                # simulate a real driver triggering the async network
                # allocation as it might cause an error
                vif.fixed_ips()
                # store the vif as attached so we can allow detaching it later
                # with a detach_interface() call.
                self._interfaces[vif['id']] = vif
                mac_addresses.append(vif['address'])

        uuid = instance.uuid
        ename = instance.display_name
        state = power_state.RUNNING if power_on else power_state.SHUTDOWN

        flavor = instance.flavor
        self.resources.claim(
            vcpus=flavor.vcpus,
            mem=flavor.memory_mb,
            disk=flavor.root_gb)
        eve_instance = EVEInstance(instance.name, ename, state, uuid)
        self.instances[uuid] = eve_instance

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

        self.plug_vifs(instance, network_info)

        ename = eden_pod_deploy(ename, flavor.vcpus, flavor.memory_mb,
                                flavor.root_gb, eden_image_path, mac_addresses)

    def destroy(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, destroy_secrets=True):
        key = instance.uuid
        name = instance.display_name
        self.unplug_vifs(instance, network_info)
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

    def snapshot(self, context, instance, image_id, update_task_state):
        if instance.uuid not in self.instances:
            raise exception.InstanceNotRunning(instance_id=instance.uuid)
        update_task_state(task_state=task_states.IMAGE_UPLOADING)

    def reboot(self, context, instance, network_info, reboot_type,
               block_device_info=None, bad_volumes_callback=None,
               accel_info=None):
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
        return '192.168.0.1'

    def set_admin_password(self, instance, new_pass):
        pass

    def resume_state_on_host_boot(self, context, instance, network_info,
                                  block_device_info=None):
        pass

    def rescue(self, context, instance, network_info, image_meta,
               rescue_password, block_device_info):
        pass

    def unrescue(
            self,
            context: nova_context.RequestContext,
            instance: 'objects.Instance',
    ):
        self.instances[instance.uuid].state = power_state.RUNNING

    def poll_rebooting_instances(self, timeout, instances):
        pass

    def migrate_disk_and_power_off(self, context, instance, dest,
                                   flavor, network_info,
                                   block_device_info=None,
                                   timeout=0, retry_interval=0):
        pass

    def finish_revert_migration(self, context, instance, network_info,
                                migration, block_device_info=None,
                                power_on=True):
        state = power_state.RUNNING if power_on else power_state.SHUTDOWN
        self.instances[instance.uuid] = EVEInstance(
            instance.name, ename, state, instance.uuid)

    def post_live_migration_at_destination(self, context, instance,
                                           network_info,
                                           block_migration=False,
                                           block_device_info=None):
        # Called from the destination host after a successful live migration
        # so spawn the instance on this host to track it properly.
        image_meta = injected_files = admin_password = allocations = None
        self.spawn(context, instance, image_meta, injected_files,
                   admin_password, allocations)

    def power_off(self, instance, timeout=0, retry_interval=0):
        if instance.uuid in self.instances:
            self.instances[instance.uuid].state = power_state.SHUTDOWN
        else:
            raise exception.InstanceNotFound(instance_id=instance.uuid)

    def power_on(self, context, instance, network_info,
                 block_device_info=None, accel_info=None, should_plug_vifs=True):
        if instance.uuid in self.instances:
            self.instances[instance.uuid].state = power_state.RUNNING
        else:
            raise exception.InstanceNotFound(instance_id=instance.uuid)
        if should_plug_vifs:
            self.plug_vifs(instance, network_info)

    def trigger_crash_dump(self, instance):
        pass

    def soft_delete(self, instance):
        pass

    def restore(self, instance):
        pass

    def pause(self, instance):
        pass

    def unpause(self, instance):
        pass

    def suspend(self, context, instance):
        pass

    def resume(self, context, instance, network_info, block_device_info=None):
        pass

    def cleanup(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None, destroy_vifs=True,
                destroy_secrets=True):
        # cleanup() should not be called when the guest has not been destroyed.
        if instance.uuid in self.instances:
            raise exception.InstanceExists(
                "Instance %s has not been destroyed." % instance.uuid)

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
            state='running', driver='libvirt', hypervisor='kvm',
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
                      tx_packets=662,
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

    def get_spice_console(self, context, instance):
        return ctype.ConsoleSpice(internal_access_path='FAKE',
                                  host='evespiceconsole.com',
                                  port=6969,
                                  tlsPort=6970)

    def get_rdp_console(self, context, instance):
        return ctype.ConsoleRDP(internal_access_path='FAKE',
                                host='everdpconsole.com',
                                port=6969)

    def get_serial_console(self, context, instance):
        return ctype.ConsoleSerial(internal_access_path='FAKE',
                                   host='everdpconsole.com',
                                   port=6969)

    def get_mks_console(self, context, instance):
        return ctype.ConsoleMKS(internal_access_path='FAKE',
                                host='evemksconsole.com',
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

    def live_migration(self, context, instance, dest,
                       post_method, recover_method, block_migration=False,
                       migrate_data=None):
        post_method(context, instance, dest, block_migration,
                    migrate_data)
        return

    def live_migration_force_complete(self, instance):
        return

    def live_migration_abort(self, instance):
        return

    def cleanup_live_migration_destination_check(self, context,
                                                 dest_check_data):
        return

    def check_can_live_migrate_destination(self, context, instance,
                                           src_compute_info, dst_compute_info,
                                           block_migration=False,
                                           disk_over_commit=False):
        data = migrate_data.LibvirtLiveMigrateData()
        data.filename = 'eve'
        data.image_type = CONF.libvirt.images_type
        data.graphics_listen_addr_vnc = CONF.vnc.server_listen
        data.graphics_listen_addr_spice = CONF.spice.server_listen
        data.serial_listen_addr = None
        # Notes(eliqiao): block_migration and disk_over_commit are not
        # nullable, so just don't set them if they are None
        if block_migration is not None:
            data.block_migration = block_migration
        if disk_over_commit is not None:
            data.disk_over_commit = disk_over_commit
        data.disk_available_mb = 100000
        data.is_shared_block_storage = True
        data.is_shared_instance_path = True

        return data

    def check_can_live_migrate_source(self, context, instance,
                                      dest_check_data, block_device_info=None):
        return dest_check_data

    def finish_migration(self, context, migration, instance, disk_info,
                         network_info, image_meta, resize_instance,
                         allocations, block_device_info=None, power_on=True):
        injected_files = admin_password = None
        # Finish migration is just like spawning the guest on a destination
        # host during resize/cold migrate, so re-use the spawn() eve to
        # claim resources and track the instance on this "hypervisor".
        self.spawn(context, instance, image_meta, injected_files,
                   admin_password, allocations,
                   block_device_info=block_device_info, power_on=power_on)

    def confirm_migration(self, context, migration, instance, network_info):
        # Confirm migration cleans up the guest from the source host so just
        # destroy the guest to remove it from the list of tracked instances
        # unless it is a same-host resize.
        if migration.source_compute != migration.dest_compute:
            self.destroy(context, instance, network_info)

    def pre_live_migration(self, context, instance, block_device_info,
                           network_info, disk_info, migrate_data):
        return migrate_data

    def rollback_live_migration_at_destination(self, context, instance,
                                               network_info,
                                               block_device_info,
                                               destroy_disks=True,
                                               migrate_data=None):
        return

    def _test_remove_vm(self, instance_uuid):
        """Removes the named VM, as if it crashed. For testing."""
        self.instances.pop(instance_uuid)

    def host_power_action(self, action):
        """Reboots, shuts down or powers up the host."""
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

    def quiesce(self, context, instance, image_meta):
        pass

    def unquiesce(self, context, instance, image_meta):
        pass


class EVEVirtAPI(virtapi.VirtAPI):
    @contextlib.contextmanager
    def wait_for_instance_event(self, instance, event_names, deadline=300,
                                error_callback=None):
        # NOTE(danms): Don't actually wait for any events, just
        # fall through
        yield

    def exit_wait_early(self, events):
        # We never wait, so there is nothing to exit early
        pass

    def update_compute_provider_status(self, context, rp_uuid, enabled):
        pass


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
