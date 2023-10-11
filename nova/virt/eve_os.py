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
A EVE-OS hypervisor.
"""

import collections
import datetime
import json
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
import nova.privsep.linux_net
import nova.virt.node
import nova.virt.node
from nova import context as nova_context
from nova import exception
from nova import objects as nova_objects
from nova.compute import power_state
from nova.console import type as ctype
from nova.i18n import _
from nova.network import model
from nova.network import os_vif_util
from nova.objects import diagnostics as diagnostics_obj
from nova.objects import fields as obj_fields
from nova.virt import driver
from nova.virt import hardware
from nova.virt import images

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

        return (stdout.channel.recv_exit_status())


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

        return (stdout.channel.recv_exit_status())


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
    return (state)


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
    return (uuids)


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
            if search:
                ename = search.group(0)
                state = power_state.RUNNING
            else:
                state = power_state.SHUTDOWN
        if stderr:
            out = stderr.read().decode("utf-8")
            LOG.debug('EDEN stderr: ' + out)

    LOG.debug('EDEN "%s" state: %s' % (name, power_state.STATE_MAP[state]))
    return (state)


def eden_pod_deploy(name, vcpus, mem, disk, image, mac_addresses=None, vlan_ids=None):
    LOG.debug("EDEN eden_pod_deploy")
    ename = ''
    connect = eden_connect()
    network_line = " ".join(["--networks=" + EVE_TAP_NET + ":" + \
                             mac for mac in mac_addresses])
    vlan_line = " ".join(["--vlan=" + EVE_TAP_NET + ":" + vlan for vlan in vlan_ids])
    eden_cmd = './eden pod deploy --name=' + name + \
               ' --cpus=' + str(vcpus) + ' --memory=' + str(mem) + 'MB ' + \
               network_line + \
               ' ' + vlan_line + \
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
    LOG.debug("EDEN eden_pod_delete")
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


def eden_pod_start(name):
    LOG.debug("EDEN eden_pod_start")
    ename = ''
    connect = eden_connect()
    eden_cmd = './eden pod start ' + name

    LOG.debug('EDEN cmd: ' + str(eden_cmd))

    with connect:
        stdin, stdout, stderr = connect.exec_command(
            'cd ' + CONF.eve_os.eden_dir + '; ' + eden_cmd)
        if stdout:
            out = stdout.read().decode("utf-8")
            LOG.debug('EDEN stdout: ' + out)
            search = re.search("INFO\[\d*\] app (.*) start done", out)
            if search:
                ename = search.group(1)
                return (name)
        if stderr:
            out = stderr.read().decode("utf-8")
            LOG.debug('EDEN stderr: ' + out)

    return ename


def eden_pod_stop(name):
    LOG.debug("EDEN eden_pod_stop")
    ename = ''
    connect = eden_connect()
    eden_cmd = './eden pod stop ' + name

    LOG.debug('EDEN cmd: ' + str(eden_cmd))

    with connect:
        stdin, stdout, stderr = connect.exec_command(
            'cd ' + CONF.eve_os.eden_dir + '; ' + eden_cmd)
        if stdout:
            out = stdout.read().decode("utf-8")
            LOG.debug('EDEN stdout: ' + out)
            search = re.search("INFO\[\d*\] app (.*) stop done", out)
            if search:
                ename = search.group(1)
                return (name)
        if stderr:
            out = stderr.read().decode("utf-8")
            LOG.debug('EDEN stderr: ' + out)

    return ename


def eden_dinfo():
    LOG.debug("EDEN eden_dinfo")
    connect = eden_connect()
    info = {}
    with connect:
        stdin, stdout, stderr = connect.exec_command(
            'cd ' + CONF.eve_os.eden_dir + '; ./eden info --format json')
        if stdout:
            out = stdout.read().decode("utf-8")
            # LOG.debug('EDEN stdout: ' + out)
            out = out.split('\n')
            infos = len(out)
            for i in range(0, infos):
                try:
                    info = json.loads(out[infos - 1 - i])
                    if 'dinfo' in info:
                        info = info["dinfo"]
                        break
                except json.decoder.JSONDecodeError:
                    continue
        if stderr:
            out = stderr.read().decode("utf-8")
            LOG.debug('EDEN stderr: ' + out)

    return info


def eden_metric():
    LOG.debug("EDEN eden_metric")
    metric = {}
    connect = eden_connect()
    with connect:
        stdin, stdout, stderr = connect.exec_command(
            'cd ' + CONF.eve_os.eden_dir + \
            '; ./eden metric --format=json --tail 1')
        if stdout:
            out = stdout.read().decode("utf-8")
            LOG.debug('EDEN stdout: ' + out)
            metric = json.loads(out)
        if stderr:
            out = stderr.read().decode("utf-8")
            LOG.debug('EDEN stderr: ' + out)

    return metric


def eden_pod_ps():
    LOG.debug("EDEN eden_pod_ps")
    apps = []
    connect = eden_connect()
    with connect:
        stdin, stdout, stderr = connect.exec_command(
            'cd ' + CONF.eve_os.eden_dir + '; ./eden pod ps --format=json')
        if stdout:
            out = stdout.read().decode("utf-8")
            LOG.debug('EDEN stdout: ' + out)
            apps = json.loads(out)
        if stderr:
            out = stderr.read().decode("utf-8")
            LOG.debug('EDEN stderr: ' + out)

    return apps


def eden_cpu_info():
    info = eden_dinfo()
    cpu_info = collections.OrderedDict([
        ('arch', info["machineArch"]),
        ('model', info["minfo"]["productName"]),
        ('vendor', info["minfo"]["manufacturer"]),
        ('topology', {
            'cores': info["ncpu"],
            # 'threads': 1,
            # 'sockets': 4,
        }),
    ])

    return cpu_info


def eden_diag():
    LOG.debug("EDEN eden_diag")
    diag = {}
    info = eden_dinfo()
    diag['cpu0_time'] = datetime.datetime.now() - \
                        datetime.datetime.strptime(info["bootTime"],
                                                   "%Y-%m-%dT%H:%M:%SZ")
    diag['memory'] = int(info["memory"])

    nw = eden_metric()['dm']["network"][2]
    # 'vda_errors': -1,
    # 'vda_read': 262144,
    # 'vda_read_req': 112,
    # 'vda_write': 5778432,
    # 'vda_write_req': 488,
    diag['vnet1_rx'] = int(nw["rxBytes"])
    # 'vnet1_rx_drop': 0,
    # 'vnet1_rx_errors': 0,
    diag['vnet1_rx_packets'] = int(nw["rxPkts"])
    diag['vnet1_tx'] = int(nw["txBytes"])
    # 'vnet1_tx_drop': 0,
    # 'vnet1_tx_errors': 0,
    diag['vnet1_tx_packets'] = int(nw["txPkts"])

    return diag


def eden_diag_app(name):
    LOG.debug("EDEN eden_diag_app")
    diags = diagnostics_obj.Diagnostics(
        state=power_state.STATE_MAP[eden_state(name)],
        driver='eve_os',  # hypervisor='eve_os',
        hypervisor_os='linux',
        # uptime=46664,
        config_drive=True)

    uptime = 0
    CPUUsage = 0
    mac = ''
    rxb = 0
    txb = 0
    rxp = 0
    txp = 0
    mmax = 0
    mused = 0

    apps = eden_pod_ps()
    for app in apps:
        if app['Name'] == name:
            CPUUsage = float(app['CPUUsage'])
            mac = app["Macs"][0]

    metric = eden_metric()
    if 'am' in metric:
        apps = metric['am']

        for app in apps:
            if app['AppName'] == name:
                t = app['cpu']['upTime']
                # Convert to seconds
                t = t.split('T')[-1][:-1].split(':')
                uptime = int(t[0]) * 3600 + int(t[1]) * 60 + float(t[2])
                if 'network' in app:
                    nw = app['network'][0]
                    if 'txBytes' in nw:
                        txb = int(nw['txBytes'])
                    else:
                        txb = 0
                    if 'rxBytes' in nw:
                        rxb = int(nw['rxBytes'])
                    else:
                        rxb = 0
                    if 'txPkts' in nw:
                        txp = int(nw['txPkts'])
                    else:
                        txp = 0
                    if 'txPkts' in nw:
                        rxp = int(nw['txPkts'])
                    else:
                        rxp = 0
                else:
                    txb = 0
                    rxb = 0
                    txp = 0
                    rxp = 0
                mmax = int(app['memory']['availMem'])
                mused = int(app['memory']['usedMem'])

        diags.add_cpu(id=0, time=uptime, utilisation=CPUUsage)
        diags.add_nic(mac_address=mac,
                      rx_octets=rxb,
                      # rx_errors=100,
                      # rx_drop=200,
                      rx_packets=rxp,
                      # rx_rate=300,
                      tx_octets=txb,
                      # tx_errors=400,
                      # tx_drop=500,
                      tx_packets=txp,
                      # tx_rate=600
                      )
        diags.memory_details = diagnostics_obj.MemoryDiagnostics(
            maximum=mmax, used=mused)

    LOG.debug('EDEN "%s" diags: %s' % (name, str(diags)))
    return (diags)


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


def calculate_vlan(vif_id):
    # FIXME: we may have hash collision, but no idea how to use something like app number in EVE-OS
    return str(hash(vif_id) % 4000 + 2)


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
            sub_interface = ("ev0%s" % vif.id)[:model.NIC_NAME_LEN]
            LOG.warning("Creating veth pair %(v1)s to %(v2)s",
                        {'v1': veth_1, 'v2': veth_2})
            vif_plug_ovs.linux_net.create_veth_pair(veth_1, veth_2, EVE_VETH_MTU)
            LOG.warning("Creating sub_interface %(sub_interface)s for link %(link)s vlan_id %(vlan_id)s",
                        {'sub_interface': sub_interface, 'link': veth_1, 'vlan_id': calculate_vlan(vif.id)})
            nova.privsep.linux_net.add_vlan(veth_1, sub_interface, calculate_vlan(vif.id))
            nova.privsep.linux_net.set_device_enabled(sub_interface)
            vif_plug_ovs.linux_net.add_bridge_port(vif.bridge_name, sub_interface)
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
            sub_interface = ("ev0%s" % vif.id)[:model.NIC_NAME_LEN]
            vif_plug_ovs.linux_net.delete_net_dev(sub_interface)
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
        LOG.debug("EVE_OS init_host: " + str(host))
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
        LOG.debug("EVE_OS get_info %s (%s)" % (instance.display_name, instance.uuid))
        state = eden_state(instance.uuid)
        return hardware.InstanceInfo(state=state)

    def list_instances(self):
        LOG.debug("EVE_OS list_instances: ")
        ctx = nova_context.get_admin_context()
        for uuid in eden_uuids_list():
            instance = nova_objects.Instance.get_by_uuid(ctx, uuid)
            LOG.debug("%s: %s" % (uuid, instance.name))
        instances = [nova_objects.Instance.get_by_uuid(ctx, uuid).name for uuid in eden_uuids_list()]
        LOG.debug("EVE_OS instances: " + str(instances))

        return instances

    def list_instance_uuids(self):
        LOG.debug("EVE_OS list_instance_uuids")
        return eden_uuids_list()

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        LOG.debug("EVE_OS plug_vifs")
        LOG.warning("plug_vifs Plugging network_info %(network_info)s to %(instance)s",
                    {'network_info': network_info, 'instance': instance})
        if network_info:
            for vif in network_info:
                self._vif_driver.plug(instance, vif)

    def unplug_vifs(self, instance, network_info):
        """Unplug VIFs from networks."""
        LOG.debug("EVE_OS unplug_vifs")
        LOG.warning("unplug_vifs unPlugging network_info %(network_info)s to %(instance)s",
                    {'network_info': network_info, 'instance': instance})
        if network_info:
            for vif in network_info:
                self._vif_driver.unplug(instance, vif)

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, allocations, network_info=None,
              block_device_info=None, power_on=True, accel_info=None):

        mac_addresses = []
        vlan_ids = []

        if network_info:
            for vif in network_info:
                # simulate a real driver triggering the async network
                # allocation as it might cause an error
                vif.fixed_ips()
                # store the vif as attached so we can allow detaching it later
                # with a detach_interface() call.
                self._interfaces[vif['id']] = vif
                mac_addresses.append(vif['address'])
                vlan_ids.append(calculate_vlan(vif['id']))

        uuid = instance.uuid
        ename = instance.uuid
        LOG.debug("EVE_OS spawn %s (%s)" % (ename, uuid))

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

        self.plug_vifs(instance, network_info)

        ename = eden_pod_deploy(uuid, flavor.vcpus, flavor.memory_mb,
                                flavor.root_gb, eden_image_path, mac_addresses, vlan_ids)

        # state = eden_state(uuid)

    def destroy(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, destroy_secrets=True):
        key = instance.uuid
        LOG.debug("EVE_OS destroy %s" % key)
        self.unplug_vifs(instance, network_info)
        instances = self.list_instance_uuids()
        if key in instances:
            name = eden_pod_delete(key)
            flavor = instance.flavor
            self.resources.release(
                vcpus=flavor.vcpus,
                mem=flavor.memory_mb,
                disk=flavor.root_gb)
        else:
            LOG.warning("Key '%(key)s' not in instances '%(inst)s'",
                        {'key': key,
                         'inst': instances}, instance=instance)

    def reboot(self, context, instance, network_info, reboot_type,
               block_device_info=None, bad_volumes_callback=None,
               accel_info=None):
        LOG.debug("EVE_OS reboot")
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
        LOG.debug("EVE_OS poll_rebooting_instances")

    def power_off(self, instance, timeout=0, retry_interval=0):
        LOG.debug("EVE_OS power_off")
        eden_pod_stop(instance.uuid)
        # if instance.uuid in self.instances:
        #    self.instances[instance.uuid].state = power_state.SHUTDOWN
        # else:
        #    raise exception.InstanceNotFound(instance_id=instance.uuid)

    def power_on(self, context, instance, network_info,
                 block_device_info=None, accel_info=None,
                 should_plug_vifs=True):
        LOG.debug("EVE_OS power_on")
        eden_pod_start(instance.uuid)

        # if instance.uuid in self.instances:
        #    self.instances[instance.uuid].state = power_state.RUNNING
        # else:
        #    raise exception.InstanceNotFound(instance_id=instance.uuid)

        if should_plug_vifs:
            self.plug_vifs(instance, network_info)

    def pause(self, instance):
        LOG.debug("EVE_OS pause")
        eden_pod_stop(instance.uuid)

    def unpause(self, instance):
        LOG.debug("EVE_OS unpause")
        eden_pod_start(instance.uuid)

    def suspend(self, context, instance):
        LOG.debug("EVE_OS suspend")
        eden_pod_stop(instance.uuid)

    def resume(self, context, instance, network_info, block_device_info=None):
        LOG.debug("EVE_OS resume")
        eden_pod_start(instance.uuid)

    def cleanup(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None, destroy_vifs=True,
                destroy_secrets=True):
        # cleanup() should not be called when the guest has not been destroyed.
        LOG.debug("EVE_OS cleanup")

    def attach_volume(self, context, connection_info, instance, mountpoint,
                      disk_bus=None, device_type=None, encryption=None):
        """Attach the disk to the instance at mountpoint using info."""
        LOG.debug("EVE_OS attach_volume")
        instance_name = instance.name
        if instance_name not in self._mounts:
            self._mounts[instance_name] = {}
        self._mounts[instance_name][mountpoint] = connection_info

    def detach_volume(self, context, connection_info, instance, mountpoint,
                      encryption=None):
        """Detach the disk attached to the instance."""
        LOG.debug("EVE_OS detach_volume")
        try:
            del self._mounts[instance.name][mountpoint]
        except KeyError:
            pass

    def swap_volume(self, context, old_connection_info, new_connection_info,
                    instance, mountpoint, resize_to):
        """Replace the disk attached to the instance."""
        LOG.debug("EVE_OS swap_volume")
        instance_name = instance.name
        if instance_name not in self._mounts:
            self._mounts[instance_name] = {}
        self._mounts[instance_name][mountpoint] = new_connection_info

    def extend_volume(self, context, connection_info, instance,
                      requested_size):
        """Extend the disk attached to the instance."""
        LOG.debug("EVE_OS extend_volume")

    def attach_interface(self, context, instance, image_meta, vif):
        LOG.debug("EVE_OS attach_interface")
        if vif['id'] in self._interfaces:
            raise exception.InterfaceAttachFailed(
                instance_uuid=instance.uuid)
        self._interfaces[vif['id']] = vif

    def detach_interface(self, context, instance, vif):
        LOG.debug("EVE_OS detach_interface")
        try:
            del self._interfaces[vif['id']]
        except KeyError:
            raise exception.InterfaceDetachFailed(
                instance_uuid=instance.uuid)

    def get_diagnostics(self, instance):
        LOG.debug("EVE_OS get_diagnostics")
        return eden_diag()

    def get_instance_diagnostics(self, instance):
        LOG.debug("EVE_OS get_instance_diagnostics")
        return eden_diag_app(instance.uuid)

    def get_all_volume_usage(self, context, compute_host_bdms):
        """Return usage info for volumes attached to vms on
           a given host.
        """
        LOG.debug("EVE_OS get_all_volume_usage")
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

    def block_stats(self, instance, disk_id):
        LOG.debug("EVE_OS block_stats")
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
        LOG.debug("EVE_OS get_available_resource")
        cpu_info = eden_cpu_info()

        if nodename not in self.get_available_nodes():
            return {}

        host_status = self.host_status_base.copy()
        dinfo = eden_dinfo()
        metric = eden_metric()
        dm = metric['dm']
        if 'am' in metric:
            am = metric['am']
        else:
            am = []

        resources = {
            'vcpus': dinfo['ncpu'],
            'memory_mb': dm['memory']["availMem"],
            #'local_gb': int(dinfo["storage"]),
            'vcpus_used': len(am),
            'memory_mb_used': dm['memory']["usedMem"],
            'local_gb_used': 0
        }
        if "storage" in dinfo:
            resources['local_gb'] = int(dinfo["storage"])
        else:
            resources['local_gb'] = 0
            
        host_status.update(resources)
        # host_status.update(self.resources.dump())
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
        LOG.debug("EVE_OS update_provider_tree")
        inv = provider_tree.data(nodename).inventory
        ratios = self._get_allocation_ratios(inv)

        info = eden_dinfo()
        if "ncpu" in info:
            ncpu = info["ncpu"]
        else:
            ncpu = 0
        if "memory" in info:
            mem = int(info["memory"])
        else:
            mem = 0
        if "storage" in info:
            str = int(info["storage"])
        else:
            str = 0
        inventory = {
            'VCPU': {
                'total': ncpu,
                'min_unit': 1,
                'max_unit': ncpu,
                'step_size': 1,
                'allocation_ratio': ratios[orc.VCPU],
                'reserved': CONF.reserved_host_cpus,
            },
            'MEMORY_MB': {
                'total': mem,
                'min_unit': 1,
                'max_unit': mem,
                'step_size': 1,
                'allocation_ratio': ratios[orc.MEMORY_MB],
                'reserved': CONF.reserved_host_memory_mb,
            },
            'DISK_GB': {
                'total': str,
                'min_unit': 1,
                'max_unit': str,
                'step_size': 1,
                'allocation_ratio': ratios[orc.DISK_GB],
                'reserved': self._get_reserved_host_disk_gb_from_config(),
            },
        }

        provider_tree.update_inventory(nodename, inventory)

    def get_instance_disk_info(self, instance, block_device_info=None):
        LOG.debug("EVE_OS get_instance_disk_info")
        return

    def host_power_action(self, action):
        """Reboots, shuts down or powers up the host."""
        LOG.debug("EVE_OS host_power_action: " + str(action))
        return action

    def host_maintenance_mode(self, host, mode):
        """Start/Stop host maintenance window. On start, it triggers
        guest VMs evacuation.
        """
        LOG.debug("EVE_OS host_maintenance_mode")
        if not mode:
            return 'off_maintenance'
        return 'on_maintenance'

    def set_host_enabled(self, enabled):
        """Sets the specified host's ability to accept new instances."""
        LOG.debug("EVE_OS set_host_enabled")
        if enabled:
            return 'enabled'
        return 'disabled'

    def get_volume_connector(self, instance):
        LOG.debug("EVE_OS get_volume_connector")
        return {'ip': CONF.my_block_storage_ip,
                'initiator': 'eve',
                'host': self._host}

    def get_available_nodes(self, refresh=False):
        LOG.debug("EVE_OS get_available_nodes")
        return self._nodes

    def get_nodenames_by_uuid(self, refresh=False):
        LOG.debug("EVE_OS get_nodenames_by_uuid")
        return {str(getattr(uuids, 'node_%s' % n)): n
                for n in self.get_available_nodes()}

    def instance_on_disk(self, instance):
        LOG.debug("EVE_OS instance_on_disk")
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
