# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack, LLC
# Copyright 2013 Mirantis, Inc.
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

import logging
from nose.plugins.attrib import attr
from fuel_health.common.utils.data_utils import rand_name
from fuel_health import neutronmanager

from fuel_health.exceptions import SSHExecCommandFailed

LOG = logging.getLogger(__name__)


class TestNeutronNetwork(neutronmanager.NeutronScenarioTest):
    """
    Test suit verifies:
     - keypairs creation
     - security groups creation
     - Network creation
     - Instance creation
     - Floating ip creation
     - Instance connectivity by floating IP
    """

    @classmethod
    def check_preconditions(cls):
        super(TestNeutronNetwork, cls).check_preconditions()
        cfg = cls.config.network
        if not (cfg.tenant_networks_reachable or cfg.public_network_id):
            msg = ('Either tenant_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            cls.enabled = False
            raise cls.skipException(msg)

    @classmethod
    def setUpClass(cls):
        super(TestNeutronNetwork, cls).setUpClass()
        cls.check_preconditions()
        cls.tenant_id = cls.manager._get_identity_client(
            cls.config.identity.admin_username,
            cls.config.identity.admin_password,
            cls.config.identity.admin_tenant_name).tenant_id

        cls.keypairs = {}
        cls.security_groups = {}
        cls.networks = []
        cls.subnets = []
        cls.routers = []
        cls.servers = []
        cls.floating_ips = {}

    def setUp(self):
        super(TestNeutronNetwork, self).setUp()
        if not self.config.compute.compute_nodes:
            self.fail('There are no compute nodes')

    @classmethod
    def tearDownClass(cls):
        super(TestNeutronNetwork, cls).tearDownClass()

    @attr(type=['fuel', 'smoke'])
    def test_001_create_keypairs(self):
        """ Keypair creation
        Target components: Nova

        Scenario:
            1. Create a new keypair, check if it was created successfully.
        Duration: 25 s.
        """
        self.keypairs[self.tenant_id] = self.verify(25,
                                                    self._create_keypair,
                                                    1,
                                                    'Keypair can not be'
                                                    ' created.',
                                                    'keypair creation',
                                                    self.compute_client)

    @attr(type=['fuel', 'smoke'])
    def test_002_create_security_groups(self):
        """Security group creation
        Target components: Neutron

        Scenario:
            1. Create a security group, check if it was created correctly.
        Duration: 25 s.
        """
        self.security_groups[self.tenant_id] = self.verify(
            25, self._create_security_group, 1,
            "Security group can not be created.",
            'security group creation')


    @attr(type=['fuel', 'smoke'])
    def test_004_check_networks(self):
        """Check network parameters
        Target component: Neutron

        Scenario:
            1. Get the list of networks.
            2. Confirm that networks have expected labels.
            3. Confirm that networks have expected ids.
        Duration: 50 s.
        """
        #Checks that we see the newly created network/subnet/router via
        #checking the result of list_[networks,routers,subnets]
        seen_nets = self.verify(
            50,
            self._list_networks,
            1,
            "List of networks is not available.",
            'listing networks'
        )
        seen_labels, seen_ids = zip(*((n.label, n.id) for n in seen_nets))
        for mynet in self.networks:
            self.verify_response_body(seen_labels,
                                      mynet.label,
                                      ('Network is not created '
                                       'properly'))
            self.verify_response_body(seen_ids,
                                      mynet.id,
                                      ('Network does is created'
                                       ' properly '))

    @attr(type=['fuel', 'smoke'])
    def test_005_create_servers(self):
        """Launch instance
        Target components: Nova, Neutron

        Scenario:
            1. Create a new security group (if it doesn`t exist yet).
            2. Create an instance using the new security group.
        Duration: 200 s.
        """
        if not self.security_groups:
            self.security_groups[self.tenant_id] = self.verify(
                25,
                self._create_security_group,
                1,
                "Security group can not be created.",
                'security group creation')

        name = rand_name('ost1_test-server-smoke-')
        security_groups = [self.security_groups[self.tenant_id].name]

        server = self.verify(
            200,
            self._create_server,
            2,
            "Creating instance using the new security group has failed.",
            'image creation',
            self.compute_client, name, security_groups
        )

        self.servers.append(server)

    @attr(type=['fuel', 'smoke'])
    def test_006_assign_floating_ips(self):
        """Assign floating IP
        Target component: Neutron

        Scenario:
            1. Create a new security group (if doesn`t exist yet).
            2. Create instance using the new security group.
            3. Create a new floating IP.
            4. Assign the new floating IP to the instance.
        Duration: 200 s.
        """
        if not self.servers:
            if not self.security_groups:
                self.security_groups[self.tenant_id] = self.verify(
                    25, self._create_security_group, 1,
                    "Security group can not be created.",
                    'security group creation')
            name = rand_name('ost1_test-server-smoke-')
            security_groups = [self.security_groups[self.tenant_id].name]

            server = self.verify(
                200,
                self._create_server,
                2,
                "Server can not be created.",
                "server creation",
                self.compute_client, name, security_groups
            )
            self.servers.append(server)

        floating_ip = self.verify(
            20,
            self._create_floating_ip,
            3,
            "Floating IP can not be created.",
            'floating IP creation')

        if self.servers:
            self.verify(
                10,
                self._assign_floating_ip_to_instance,
                4,
                "Floating IP can not be assigned.",
                'floating IP assignment',
                self.compute_client, self.servers[0], floating_ip)

        self.floating_ips.append(floating_ip)

    @attr(type=['fuel', 'smoke'])
    def test_008_check_public_network_connectivity(self):
        """Check that VM is accessible via floating IP address
        Target component: Neutron

        Scenario:
            1. Create a new security group (if it doesn`t exist yet).
            2. Create an instance using the new security group
            (if it doesn`t exist yet).
            3. Create a new floating IP (if doesn`t exist yet).
            4. Assign the new floating IP to the instance.
            5. Check connectivity to the floating IP using ping command.
        Duration: 200 s.
        """
        if not self.floating_ips:
            if not self.servers:
                if not self.security_groups:
                    self.security_groups[self.tenant_id] = self.verify(
                        25, self._create_security_group, 1,
                        "Security group can not be created.",
                        'security group creation')

                name = rand_name('ost1_test-server-smoke-')
                security_groups = [self.security_groups[self.tenant_id].name]

                server = self.verify(
                    200, self._create_server, 2,
                    "Server can not be created.",
                    'server creation',
                    self.compute_client, name, security_groups)

                self.servers.append(server)

            floating_ip = self.verify(20, self._create_floating_ip, 3,
                                      "Floating IP can not be created.",
                                      'floating IP creation')
            self.floating_ips.append(floating_ip)

        if self.servers and self.floating_ips:
            self.verify(10, self._assign_floating_ip_to_instance, 4,
                        "Floating IP can not be assigned.",
                        "floating IP assignment",
                        self.compute_client,
                        self.servers[0],
                        self.floating_ips[0])

        if self.floating_ips:
            ip_address = self.floating_ips[0].ip
            self.verify(100, self._check_vm_connectivity, 5,
                        "VM connectivity doesn`t function properly.",
                        'VM connectivity checking', ip_address)

    @attr(type=['fuel', 'smoke'])
    def test_008_check_public_instance_connectivity_from_instance(self):
        """Check network connectivity from instance via floating IP
        Target component: Neutron

        Scenario:
            1. Create a new security group (if it doesn`t exist yet).
            2. Create an instance using the new security group.
            (if it doesn`t exist yet).
            3. Create a new floating IP (if it doesn`t exist yet).
            4. Assign the new floating IP to the instance.
            5. Check that public IP 8.8.8.8 can be pinged from instance.
        Duration: 200 s.
        """
        if not self.floating_ips:
            if not self.servers:
                if not self.security_groups:
                    self.security_groups[self.tenant_id] = self.verify(
                        25, self._create_security_group, 1,
                        "Security group can not be created.",
                        'security group creation')

                name = rand_name('ost1_test-server-smoke-')
                security_groups = [self.security_groups[self.tenant_id].name]

                server = self.verify(
                    200, self._create_server, 2,
                    "Server can not be created.",
                    'server creation',
                    self.compute_client, name, security_groups)

                self.servers.append(server)

            floating_ip = self.verify(
                20, self._create_floating_ip, 3,
                "Floating IP can not be created.",
                'floating IP creation')

            self.floating_ips.append(floating_ip)

        if self.servers and self.floating_ips:
            self.verify(10, self._assign_floating_ip_to_instance, 4,
                        "Floating IP can not be assigned.",
                        "floating IP assignment",
                        self.compute_client,
                        self.servers[0],
                        self.floating_ips[0])

        if self.floating_ips:
            ip_address = self.floating_ips[0].ip
            LOG.debug(ip_address)
            self.verify(100, self._check_connectivity_from_vm,
                        5, ("Connectivity to 8.8.8.8 from the VM doesn`t "
                            "function properly."),
                        'public connectivity checking from VM', ip_address)

    @attr(type=['fuel', 'smoke'])
    def test_009_check_internet_connectivity_instance_without_floatingIP(self):
        """Check network connectivity from instance without floating IP
        Target component: Neutron

        Scenario:
            1. Create a new security group (if it doesn`t exist yet).
            2. Create an instance using the new security group.
            (if it doesn`t exist yet).
            3. Check that public IP 8.8.8.8 can be pinged from instance.
        Duration: 200 s.
        """
        if not self.security_groups:
            self.security_groups[self.tenant_id] = self.verify(
                25, self._create_security_group, 1,
                "Security group can not be created.",
                'security group creation')

        name = rand_name('ost1_test-server-smoke-')
        security_groups = [self.security_groups[self.tenant_id].name]

        server = self.verify(
            200, self._create_server, 2,
            "Server can not be created.",
            'server creation',
            self.compute_client, name, security_groups)
        self.servers.append(server)

        try:
            instance_ip = server.addresses['novanetwork'][0]['addr']
            compute = getattr(server, 'OS-EXT-SRV-ATTR:host')
        except Exception as e:
            LOG.debug(e)
            self.fail("Step 3 failed: cannot get instance details. "
                      "Please refer to OpenStack logs for more details.")

        self.verify(100, self._check_connectivity_from_vm,
                    3, ("Connectivity to 8.8.8.8 from the VM doesn`t "
                        "function properly."),
                    'public connectivity checking from VM',
                    instance_ip,
                    compute)

    @attr(type=['fuel', 'smoke'])
    def test_010_check_instance_connectivity_by_tenant(self):
        """Connectivity between instances in different tenants
        Target component: Neutron

        Scenario:
            1. Create two tenants.
            2. Create users using created tenants.
            3. Create security groups for both tenants.
            4. Authenticate with the first user.
            5. Run Instance1 in the first user/tenant.
            6. Authenticate with the second user.
            7. Run Instance2, Instance 3 in the second one.
            8. Ping from Instance1 to Instance2.
            9. Ping from Instance3 to Instance2.
        Duration: 300 s.
        """

        tenant1, tenant2 = [self.verify(10, self._create_tenant, 1,
                                        "Tenant creation failed",
                                        "tenant creation")
                            for _ in range(2)]

        user1, user2 = ([self.verify(20, self._create_user, 2,
                                     'User creation failed',
                                     'user creation', self.identity_client,
                                     tenant.id)
                         for tenant in [tenant1, tenant2]])

        self.security_groups[tenant.id] = [
            self.verify(25, self._create_security_group, 3,
                        "Security group can not be created.",
                        'security group creation')
            for tenant in [tenant1, tenant2]]

        msg_s = "Can not get authentication token."
        auth = self.verify(40, self.identity_client.tokens.authenticate,
                           3, msg_s,
                           'authentication',
                           username=user1.name,
                           password='123456',
                           tenant_id=tenant1.id,
                           tenant_name=tenant1.name)

        self.verify_response_true(auth,
                                  'Step 3 failed: {msg}'.format(msg=msg_s))

        instance1 = self.verify(200, self._create_server, 4,
                                "Instance creation failed",
                                "instance creation",
                                self.compute_client,
                                rand_name('ost1_test-server-smoke-'),
                                self.security_groups[tenant1.id])

        auth = self.verify(40, self.identity_client.tokens.authenticate,
                           5, msg_s,
                           'authentication',
                           username=user2.name,
                           password='123456',
                           tenant_id=tenant2.id,
                           tenant_name=tenant2.name)

        self.verify_response_true(auth,
                                  'Step 5 failed: {msg}'.format(msg=msg_s))

        instance2, instance3 = [self.verify(400, self._create_server, 6,
                                            "Instance creation failed",
                                            "instance creation",
                                            self.compute_client,
                                            rand_name(
                                                'ost1_test-server-smoke-'),
                                            self.security_groups[tenant2.id])
                                for _ in range(2)]

        try:
            self._check_connectivity_from_vm(ip_address=instance2.ip,
                                             to_ping=instance1.ip)
            LOG.debug('Connectivity between instances in different tenants'
                      'doesn`t work properly')
            self.fail()
        except SSHExecCommandFailed:
            LOG.debug('Connectivity between instances in different tenants'
                      'works properly')

        self.verify(100, self._check_connectivity_from_vm, 8,
                    'Connectivity to {inst2} from {inst1} doesn`t function'
                    'properly'.format(
                        inst1=instance3.name, inst2=instance2.name),
                    'connectivity checking between instances',
                    ip_address=instance2.ip,
                    to_ping=instance3.ip)
