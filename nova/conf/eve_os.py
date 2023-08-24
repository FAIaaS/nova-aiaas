# Copyright (c) 2023 Oleg Sadov <oleg dot sadov at gmail dot com>
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

from oslo_config import cfg


from nova.conf import paths


eve_os_opt_group = cfg.OptGroup('eve_os',
                             title='EVE-OS Options',
                             help="""
eve_os options allows cloud administrator to configure related
EVE-OS hypervisor driver to be used within an OpenStack deployment.

EVE-OS options are used when the compute_driver is set to use
EVE-OS (compute_driver=zvm.EVEDriver)
""")


eve_os_opts = [
    cfg.StrOpt('eden_host',
               default='eden',
               help="""
Host to be used to communicate with EDEN tool.
"""),
    cfg.StrOpt('eden_port',
               default='22',
               help="""
SSH port to be used to communicate with EDEN tool.
"""),
    cfg.StrOpt('eden_user',
               default='eden',
               help="""
User to be used to run EDEN tool.
"""),
    cfg.StrOpt('eden_password',
               default='',
               help="""
EDEN user's password.
"""),
    cfg.StrOpt('eden_key_file',
               default="/var/lib/nova/.ssh/eden_rsa",
               help="""
SSH certificate file to be verified in EDEN host.

A string, it must be a path to a SSH private key to use.
"""),
    cfg.StrOpt('eden_dir',
               default="~/eden/",
               help="""
The path at which EDEN executable will run.

Possible values:
    A file system path on the host running the compute service.
"""),
    cfg.StrOpt('image_tmp_path',
               default="/tmp",
               help="""
The path at which images will be stored.

Images need to be stored on the local disk of the compute host.
This configuration identifies the directory location.

Possible values:
    A file system path on the host running the compute service.
"""),
    cfg.StrOpt('eden_tmp_path',
               default="/tmp",
               help="""
The path at which images will be stored.

Images need to be stored on the local disk of the EDEN host.
This configuration identifies the directory location.

Possible values:
    A file system path on the host running the compute service.
"""),
]


def register_opts(conf):
    conf.register_group(eve_os_opt_group)
    conf.register_opts(eve_os_opts, group=eve_os_opt_group)


def list_opts():
    return {eve_os_opt_group: eve_os_opts}
