

# Copyright 2012 OpenStack Foundation
# Copyright 2013 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import collections
import subprocess


from tempest.api.network import common as net_common
from tempest.common import debug
from tempest.common.utils import data_utils
from tempest import config
from tempest.openstack.common import log as logging
from tempest.scenario import manager
from tempest import test
from collections import deque
import pdb

CONF = config.CONF
LOG = logging.getLogger(__name__)

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


class TestNetworkTwoVms(manager.NetworkScenarioTest):

    @classmethod
    def check_preconditions(cls):
        super(TestNetworkTwoVms, cls).check_preconditions()
        if not (CONF.network.tenant_networks_reachable
                or CONF.network.public_network_id):
            msg = ('Either tenant_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            cls.enabled = False
            raise cls.skipException(msg)

    @classmethod
    def setUpClass(cls):
        super(TestNetworkTwoVms, cls).setUpClass()
        for ext in ['router', 'security-group']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)
        cls.check_preconditions()

    def cleanup_wrapper(self, resource):
        self.cleanup_resource(resource, self.__class__.__name__)

    def setUp(self):
        super(TestNetworkTwoVms, self).setUp()
        self.security_group = \
            self._create_security_group_neutron(tenant_id=self.tenant_id)
        self.addCleanup(self.cleanup_wrapper, self.security_group)
        self.network, self.subnet, self.router = self._create_networks()
        for r in [self.network, self.router, self.subnet]:
            self.addCleanup(self.cleanup_wrapper, r)
        self.check_networks()

        self.servers = {}
        name = data_utils.rand_name('server-smoke')
        serv_dict = self._create_server(name, self.network)
        self.servers[serv_dict['server']] = serv_dict['keypair']
        sever_name1 = data_utils.rand_name('server-smoke')
        serv_dict_new_server = self._create_server(sever_name1, self.network)
        self.servers[serv_dict_new_server['server']] = serv_dict_new_server['keypair']
        self._check_tenant_network_connectivity()
        self.floating_ip_tuple_list = deque()
        self._create_and_associate_floating_ips()
        self._get_iperf()


    def check_networks(self):
        """
        Checks that we see the newly created network/subnet/router via
        checking the result of list_[networks,routers,subnets]
        """

        seen_nets = self._list_networks()
        seen_names = [n['name'] for n in seen_nets]
        seen_ids = [n['id'] for n in seen_nets]
        self.assertIn(self.network.name, seen_names)
        self.assertIn(self.network.id, seen_ids)

        seen_subnets = self._list_subnets()
        seen_net_ids = [n['network_id'] for n in seen_subnets]
        seen_subnet_ids = [n['id'] for n in seen_subnets]
        self.assertIn(self.network.id, seen_net_ids)
        self.assertIn(self.subnet.id, seen_subnet_ids)

        seen_routers = self._list_routers()
        seen_router_ids = [n['id'] for n in seen_routers]
        seen_router_names = [n['name'] for n in seen_routers]
        self.assertIn(self.router.name,
                      seen_router_names)
        self.assertIn(self.router.id,
                      seen_router_ids)

    def _create_server(self, name, network):
        keypair = self.create_keypair(name='keypair-%s' % name)
        self.addCleanup(self.cleanup_wrapper, keypair)
        security_groups = [self.security_group.name]
        create_kwargs = {
            'nics': [
                {'net-id': network.id},
            ],
            'key_name': keypair.name,
            'security_groups': security_groups,
        }
        server = self.create_server(name=name, create_kwargs=create_kwargs)
        self.addCleanup(self.cleanup_wrapper, server)
        return dict(server=server, keypair=keypair)

    def _check_tenant_network_connectivity(self):
        if not CONF.network.tenant_networks_reachable:
            msg = 'Tenant networks not configured to be reachable.'
            LOG.info(msg)
            return
        # The target login is assumed to have been configured for
        # key-based authentication by cloud-init.
        ssh_login = CONF.compute.image_ssh_user
        try:
            for server, key in self.servers.iteritems():
                for net_name, ip_addresses in server.networks.iteritems():
                    for ip_address in ip_addresses:
                        self._check_vm_connectivity(ip_address, ssh_login,
                                                    key.private_key)
        except Exception:
            LOG.exception('Tenant connectivity check failed')
            self._log_console_output(servers=self.servers.keys())
            debug.log_net_debug()
            raise

    def _create_and_associate_floating_ips(self):
        public_network_id = CONF.network.public_network_id
        for server in self.servers.keys():
            floating_ip = self._create_floating_ip(server, public_network_id)
            floating_ip_tuple = Floating_IP_tuple(floating_ip, server)
            self.addCleanup(self.cleanup_wrapper, floating_ip)
            self.floating_ip_tuple_list.append(floating_ip_tuple)

    def _check_public_network_connectivity(self, should_connect=True,
                                           msg=None):
        # The target login is assumed to have been configured for
        # key-based authentication by cloud-init.
        ssh_login = CONF.compute.image_ssh_user
        LOG.debug('checking network connections')
        LOG.debug('public_network:'+ssh_login)
        floating_ip, server = self.floating_ip_tuple_list[0]
        ip_address = floating_ip.floating_ip_address
        private_key = None
        if should_connect:
            private_key = self.servers[server].private_key
        try:
            self._check_vm_connectivity(ip_address,
                                        ssh_login,
                                        private_key,
                                        should_connect=should_connect)
        except Exception:
            ex_msg = 'Public network connectivity check failed'
            if msg:
                ex_msg += ": " + msg
            LOG.exception(ex_msg)
            self._log_console_output(servers=self.servers.keys())
            debug.log_net_debug()
            raise

    def _check_network_internal_connectivity(self, network):
        """
        via ssh check VM internal connectivity:
        - ping internal gateway and DHCP port, implying in-tenant connectivity
        pinging both, because L3 and DHCP agents might be on different nodes
        """
        for float_ip_tuple in list(self.floating_ip_tuple_list):
            floating_ip, server = float_ip_tuple
            # get internal ports' ips:
            # get all network ports in the new network
            internal_ips = (p['fixed_ips'][0]['ip_address'] for p in
                            self._list_ports(tenant_id=server.tenant_id,
                                             network_id=network.id)
                            if p['device_owner'].startswith('network'))
            self._check_server_connectivity(float_ip_tuple, internal_ips)

    def _ping_from_router(self, ip_address):
        cmd_string = "sudo ip netns exec "+ "qrouter-" + str(self.router.id) + " " + "ping -c1 -w1 " + ip_address
        LOG.debug(cmd_string)
        def ping():
            cmd = cmd_string.split(' ')
            proc = subprocess.Popen(cmd,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            proc.wait()
            LOG.debug(proc.returncode)
            return (proc.returncode == 0) == True
        return test.call_until_true(ping, CONF.compute.ping_timeout, 1)

    def _check_network_external_connectivity(self):
        """
        ping public network default gateway to imply external connectivity
        """
        if not CONF.network.public_network_id:
            msg = 'public network not defined.'
            LOG.info(msg)
            return

        subnet = self.network_client.list_subnets(
            network_id=CONF.network.public_network_id)['subnets']
        self.assertEqual(1, len(subnet), "Found %d subnets" % len(subnet))

        external_ips = [subnet[0]['gateway_ip']]
        self._check_server_connectivity(self.floating_ip_tuple_list[0],
                                        external_ips)

    def _check_server_connectivity(self, floating_ip_tuple, address_list):
        ip_address = floating_ip_tuple.floating_ip.floating_ip_address
        private_key = self.servers[floating_ip_tuple.server].private_key
        ssh_source = self._ssh_to_server(ip_address, private_key)
        for remote_ip in address_list:
            try:
                self.assertTrue(self._check_remote_connectivity(ssh_source,
                                                                remote_ip),
                                "Timed out waiting for %s to become "
                                "reachable" % remote_ip)
            except Exception:
                LOG.exception("Unable to access {dest} via ssh to "
                              "floating-ip {src}".format(dest=remote_ip,
                                                         src=floating_ip_tuple.floating_ip))
                debug.log_ip_ns()
                raise

    def _check_internal_router_connectivity(self, network):
        """
        Ping VMs from the router using ip netns exec
        """
        floating_ip, server = self.floating_ip_tuple_list[0]
        # get internal ports' ips:
        # get all network ports in the new network
        internal_ips = (p['fixed_ips'][0]['ip_address'] for p in
                        self._list_ports(tenant_id=server.tenant_id,
                                         network_id=network.id)
                        if p['device_owner'].startswith('network'))
        for ip_address in internal_ips:
            self.assertTrue(self._ping_from_router(ip_address))

    def _get_iperf(self):
        cmd = ["wget", CONF.compute.iperf_url]
        p1 = subprocess.Popen(cmd)
        p1.wait()

    def _check_vms_bandwidth(self):
        """
        Test bandwidth between each two VMs in the network
        """
        client_ssh_login = server_ssh_login = CONF.compute.image_ssh_user
        for floating_ip_tuple in list(self.floating_ip_tuple_list):
            server_ip_address = floating_ip_tuple.floating_ip.floating_ip_address
            server_private_key = self.servers[floating_ip_tuple.server].private_key
            for s_floating_ip_tuple in (s for s in list(self.floating_ip_tuple_list) if s != floating_ip_tuple) :
                client_ip_address = s_floating_ip_tuple.floating_ip.floating_ip_address
                client_private_key = self.servers[s_floating_ip_tuple.server].private_key
                self._check_between_vms_bandwidth(server_ip_address, server_private_key, server_ssh_login,
                                                  client_ip_address, client_private_key, client_ssh_login )

    @test.attr(type='smoke')
    @test.services('compute', 'network')
    def test_network_bandwidth_ops(self):
        self._check_public_network_connectivity(should_connect=True)

        self._check_network_internal_connectivity(network=self.network)

        self._check_internal_router_connectivity(network=self.network)

        self._check_network_external_connectivity()

        self._check_vms_bandwidth()

    def tearDown(self):
        super(TestNetworkTwoVms, self).tearDown()
        p = subprocess.Popen(["rm", CONF.compute.iperf_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.wait()