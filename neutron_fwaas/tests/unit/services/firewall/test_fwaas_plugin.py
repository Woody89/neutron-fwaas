# Copyright 2013 Big Switch Networks, Inc.
# All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import mock

from neutron.api.v2 import attributes as attr
from neutron import context
from neutron import manager
from neutron.plugins.common import constants as const
from neutron.tests import fake_notifier
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin
from oslo_config import cfg
import six
from webob import exc

import neutron_fwaas.extensions
from neutron_fwaas.extensions import firewall
from neutron_fwaas.extensions import firewallrouterinsertion
from neutron_fwaas.services.firewall import fwaas_plugin
from neutron_fwaas.tests import base
from neutron_fwaas.tests.unit.db.firewall import (
    test_firewall_db as test_db_firewall)

extensions_path = neutron_fwaas.extensions.__path__[0]

FW_PLUGIN_KLASS = (
    "neutron_fwaas.services.firewall.fwaas_plugin.FirewallPlugin"
)


class FirewallTestExtensionManager(test_l3_plugin.L3TestExtensionManager):

    def get_resources(self):
        res = super(FirewallTestExtensionManager, self).get_resources()
        firewall.RESOURCE_ATTRIBUTE_MAP['firewalls'].update(
            firewallrouterinsertion.EXTENDED_ATTRIBUTES_2_0['firewalls'])
        return res + firewall.Firewall.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestFirewallRouterInsertionBase(
        test_db_firewall.FirewallPluginDbTestCase):

    def setUp(self, core_plugin=None, fw_plugin=None, ext_mgr=None):
        self.agentapi_del_fw_p = mock.patch(test_db_firewall.DELETEFW_PATH,
            create=True, new=test_db_firewall.FakeAgentApi().delete_firewall)
        self.agentapi_del_fw_p.start()

        # the plugin without L3 support
        plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        # the L3 service plugin
        l3_plugin = ('neutron.tests.unit.extensions.test_l3.'
                     'TestL3NatServicePlugin')

        cfg.CONF.set_override('api_extensions_path', extensions_path)
        self.saved_attr_map = {}
        for resource, attrs in six.iteritems(attr.RESOURCE_ATTRIBUTE_MAP):
            self.saved_attr_map[resource] = attrs.copy()
        if not fw_plugin:
            fw_plugin = FW_PLUGIN_KLASS
        service_plugins = {'l3_plugin_name': l3_plugin,
            'fw_plugin_name': fw_plugin}

        if not ext_mgr:
            ext_mgr = FirewallTestExtensionManager()
        super(test_db_firewall.FirewallPluginDbTestCase, self).setUp(
            plugin=plugin, service_plugins=service_plugins, ext_mgr=ext_mgr)

        self.setup_notification_driver()

        self.l3_plugin = manager.NeutronManager.get_service_plugins().get(
            const.L3_ROUTER_NAT)
        self.plugin = manager.NeutronManager.get_service_plugins().get(
            const.FIREWALL)
        self.callbacks = self.plugin.endpoints[0]

    def restore_attribute_map(self):
        # Remove the csrfirewallinsertion extension
        firewall.RESOURCE_ATTRIBUTE_MAP['firewalls'].pop('router_ids')
        # Restore the original RESOURCE_ATTRIBUTE_MAP
        attr.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map

    def tearDown(self):
        self.restore_attribute_map()
        super(TestFirewallRouterInsertionBase, self).tearDown()

    def _create_firewall(self, fmt, name, description, firewall_policy_id=None,
                         admin_state_up=True, expected_res_status=None,
                         **kwargs):
        tenant_id = kwargs.get('tenant_id', self._tenant_id)
        router_ids = kwargs.get('router_ids')
        if firewall_policy_id is None:
            res = self._create_firewall_policy(fmt, 'fwp',
                                               description="firewall_policy",
                                               shared=True,
                                               firewall_rules=[],
                                               audited=True)
            firewall_policy = self.deserialize(fmt or self.fmt, res)
            firewall_policy_id = firewall_policy["firewall_policy"]["id"]
        data = {'firewall': {'name': name,
                             'description': description,
                             'firewall_policy_id': firewall_policy_id,
                             'admin_state_up': admin_state_up,
                             'tenant_id': tenant_id}}
        if router_ids is not None:
            data['firewall']['router_ids'] = router_ids
        firewall_req = self.new_create_request('firewalls', data, fmt)
        firewall_res = firewall_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(expected_res_status, firewall_res.status_int)
        return firewall_res


class TestFirewallCallbacks(TestFirewallRouterInsertionBase):

    def setUp(self):
        super(TestFirewallCallbacks,
              self).setUp(fw_plugin=FW_PLUGIN_KLASS)
        self.callbacks = self.plugin.endpoints[0]

    def test_set_firewall_status(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(
                firewall_policy_id=fwp_id,
                admin_state_up=test_db_firewall.ADMIN_STATE_UP
            ) as fw:
                fw_id = fw['firewall']['id']
                res = self.callbacks.set_firewall_status(ctx, fw_id,
                                                         const.ACTIVE,
                                                         host='dummy')
                fw_db = self.plugin.get_firewall(ctx, fw_id)
                self.assertEqual(fw_db['status'], const.ACTIVE)
                self.assertTrue(res)
                res = self.callbacks.set_firewall_status(ctx, fw_id,
                                                         const.ERROR)
                fw_db = self.plugin.get_firewall(ctx, fw_id)
                self.assertEqual(fw_db['status'], const.ERROR)
                self.assertFalse(res)

    def test_set_firewall_status_pending_delete(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(
                firewall_policy_id=fwp_id,
                admin_state_up=test_db_firewall.ADMIN_STATE_UP
            ) as fw:
                fw_id = fw['firewall']['id']
                fw_db = self.plugin._get_firewall(ctx, fw_id)
                fw_db['status'] = const.PENDING_DELETE
                ctx.session.flush()
                res = self.callbacks.set_firewall_status(ctx, fw_id,
                                                         const.ACTIVE,
                                                         host='dummy')
                fw_db = self.plugin.get_firewall(ctx, fw_id)
                self.assertEqual(fw_db['status'], const.PENDING_DELETE)
                self.assertFalse(res)

    def test_firewall_deleted(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(firewall_policy_id=fwp_id,
                               admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                               do_delete=False) as fw:
                fw_id = fw['firewall']['id']
                with ctx.session.begin(subtransactions=True):
                    fw_db = self.plugin._get_firewall(ctx, fw_id)
                    fw_db['status'] = const.PENDING_DELETE
                    ctx.session.flush()
                    res = self.callbacks.firewall_deleted(ctx, fw_id,
                                                          host='dummy')
                    self.assertTrue(res)
                    self.assertRaises(firewall.FirewallNotFound,
                                      self.plugin.get_firewall,
                                      ctx, fw_id)

    def test_firewall_deleted_error(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(
                firewall_policy_id=fwp_id,
                admin_state_up=test_db_firewall.ADMIN_STATE_UP,
            ) as fw:
                fw_id = fw['firewall']['id']
                res = self.callbacks.firewall_deleted(ctx, fw_id,
                                                      host='dummy')
                self.assertFalse(res)
                fw_db = self.plugin._get_firewall(ctx, fw_id)
                self.assertEqual(fw_db['status'], const.ERROR)

    def test_get_firewall_for_tenant(self):
        tenant_id = 'test-tenant'
        ctx = context.Context('', tenant_id)
        with self.firewall_rule(name='fwr1', tenant_id=tenant_id) as fwr1, \
                self.firewall_rule(name='fwr2', tenant_id=tenant_id) as fwr2, \
                self.firewall_rule(name='fwr3', tenant_id=tenant_id) as fwr3:
            with self.firewall_policy(tenant_id=tenant_id) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                fr = [fwr1, fwr2, fwr3]
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                res = req.get_response(self.ext_api)
                attrs = self._get_test_firewall_attrs()
                attrs['firewall_policy_id'] = fwp_id
                with self.firewall(
                        firewall_policy_id=fwp_id,
                        tenant_id=tenant_id,
                        admin_state_up=test_db_firewall.ADMIN_STATE_UP) as fw:
                    fw_id = fw['firewall']['id']
                    res = self.callbacks.get_firewalls_for_tenant(ctx,
                                                                  host='dummy')
                    fw_rules = (
                        self.plugin._make_firewall_dict_with_rules(ctx,
                                                                   fw_id)
                    )
                    fw_rules['add-router-ids'] = []
                    fw_rules['del-router-ids'] = []
                    self.assertEqual(res[0], fw_rules)
                    self._compare_firewall_rule_lists(
                        fwp_id, fr, res[0]['firewall_rule_list'])

    def test_get_firewall_for_tenant_without_rules(self):
        tenant_id = 'test-tenant'
        ctx = context.Context('', tenant_id)
        with self.firewall_policy(tenant_id=tenant_id) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs = self._get_test_firewall_attrs()
            attrs['firewall_policy_id'] = fwp_id
            with self.firewall(firewall_policy_id=fwp_id, tenant_id=tenant_id,
                               admin_state_up=test_db_firewall.ADMIN_STATE_UP
                               ) as fw:
                    # router_ids is not present in the firewall db
                    # but is added in the get_firewalls override by plugin
                    fw_list = [fw['firewall']]
                    f = self.callbacks.get_firewalls_for_tenant_without_rules
                    res = f(ctx, host='dummy')
                    for fw in res:
                        del fw['shared']
                    self.assertEqual(res, fw_list)


class TestFirewallAgentApi(base.BaseTestCase):
    def setUp(self):
        super(TestFirewallAgentApi, self).setUp()

        self.api = fwaas_plugin.FirewallAgentApi('topic', 'host')

    def test_init(self):
        self.assertEqual(self.api.client.target.topic, 'topic')
        self.assertEqual(self.api.host, 'host')

    def _call_test_helper(self, method_name):
        with mock.patch.object(self.api.client, 'cast') as rpc_mock, \
                mock.patch.object(self.api.client, 'prepare') as prepare_mock:
            prepare_mock.return_value = self.api.client
            getattr(self.api, method_name)(mock.sentinel.context, 'test')

        prepare_args = {'fanout': True}
        prepare_mock.assert_called_once_with(**prepare_args)

        rpc_mock.assert_called_once_with(mock.sentinel.context, method_name,
                                         firewall='test', host='host')

    def test_create_firewall(self):
        self._call_test_helper('create_firewall')

    def test_update_firewall(self):
        self._call_test_helper('update_firewall')

    def test_delete_firewall(self):
        self._call_test_helper('delete_firewall')


class TestFirewallPluginBase(TestFirewallRouterInsertionBase,
                             test_l3_plugin.L3NatTestCaseMixin):

    def setUp(self):
        super(TestFirewallPluginBase, self).setUp(fw_plugin=FW_PLUGIN_KLASS)
        fake_notifier.reset()

    def tearDown(self):
        super(TestFirewallPluginBase, self).tearDown()

    def test_create_firewall_routers_not_specified(self):
        """neutron firewall-create test-policy """
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id):
            with self.router(name='router2', admin_state_up=True,
                tenant_id=self._tenant_id):
                with self.firewall() as fw1:
                    self.assertEqual(const.PENDING_CREATE,
                        fw1['firewall']['status'])

    def test_create_firewall_routers_specified(self):
        """neutron firewall-create test-policy --router-ids "r1 r2" """
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as router1:
            with self.router(name='router2', admin_state_up=True,
                tenant_id=self._tenant_id) as router2:
                router_ids = [router1['router']['id'], router2['router']['id']]
                with self.firewall(router_ids=router_ids) as fw1:
                    self.assertEqual(const.PENDING_CREATE,
                        fw1['firewall']['status'])

    def test_create_firewall_routers_present_empty_list_specified(self):
        """neutron firewall-create test-policy --router-ids "" """
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id):
            with self.router(name='router2', admin_state_up=True,
                tenant_id=self._tenant_id):
                router_ids = []
                with self.firewall(router_ids=router_ids) as fw1:
                    self.assertEqual(const.INACTIVE,
                        fw1['firewall']['status'])

    def test_create_firewall_no_routers_empty_list_specified(self):
        """neutron firewall-create test-policy --router-ids "" """
        router_ids = []
        with self.firewall(router_ids=router_ids) as fw1:
            self.assertEqual(const.INACTIVE,
                fw1['firewall']['status'])

    def test_create_second_firewall_on_same_tenant(self):
        """fw1 created with default routers, fw2 no routers on same tenant."""
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id):
            with self.router(name='router2', admin_state_up=True,
                tenant_id=self._tenant_id):
                router_ids = []
                with self.firewall() as fw1:
                    with self.firewall(router_ids=router_ids) as fw2:
                        self.assertEqual(const.PENDING_CREATE,
                            fw1['firewall']['status'])
                        self.assertEqual(const.INACTIVE,
                            fw2['firewall']['status'])

    def test_create_firewall_admin_not_affected_by_other_tenant(self):
        # Create fw with admin after creating fw with other tenant
        with self.firewall(tenant_id='other-tenant') as fw1:
            with self.firewall() as fw2:
                self.assertEqual('other-tenant', fw1['firewall']['tenant_id'])
                self.assertEqual(self._tenant_id, fw2['firewall']['tenant_id'])

    def test_update_firewall(self):
        ctx = context.get_admin_context()
        name = "new_firewall1"
        attrs = self._get_test_firewall_attrs(name)

        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as router1:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['firewall_policy_id'] = fwp_id
                with self.firewall(
                    firewall_policy_id=fwp_id,
                    admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                    router_ids=[router1['router']['id']]
                ) as firewall:
                    fw_id = firewall['firewall']['id']
                    res = self.callbacks.set_firewall_status(ctx, fw_id,
                                                         const.ACTIVE)
                    data = {'firewall': {'name': name}}
                    req = self.new_update_request('firewalls', data, fw_id)
                    res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                    attrs = self._replace_firewall_status(attrs,
                                                      const.PENDING_CREATE,
                                                      const.PENDING_UPDATE)
                    for k, v in six.iteritems(attrs):
                        self.assertEqual(res['firewall'][k], v)

    def test_update_firewall_fails_when_firewall_pending(self):
        name = "new_firewall1"
        attrs = self._get_test_firewall_attrs(name)

        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as router1:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['firewall_policy_id'] = fwp_id
                with self.firewall(
                    firewall_policy_id=fwp_id,
                    admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                    router_ids=[router1['router']['id']]
                ) as firewall:
                    fw_id = firewall['firewall']['id']
                    data = {'firewall': {'name': name}}
                    req = self.new_update_request('firewalls', data, fw_id)
                    res = req.get_response(self.ext_api)
                    self.assertEqual(exc.HTTPConflict.code, res.status_int)

    def test_update_firewall_with_router_when_firewall_inactive(self):
        name = "firewall1"
        attrs = self._get_test_firewall_attrs(name)

        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as router1:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['firewall_policy_id'] = fwp_id
                with self.firewall(
                    name=name,
                    firewall_policy_id=fwp_id,
                    admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                    router_ids=[]
                ) as firewall:
                    fw_id = firewall['firewall']['id']
                    data = {
                        'firewall': {'router_ids': [router1['router']['id']]}}
                    req = self.new_update_request('firewalls', data, fw_id)
                    res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                    attrs = self._replace_firewall_status(attrs,
                                                      const.PENDING_CREATE,
                                                      const.PENDING_UPDATE)
                    for k, v in six.iteritems(attrs):
                        self.assertEqual(res['firewall'][k], v)

    def test_update_firewall_shared_fails_for_non_admin(self):
        ctx = context.get_admin_context()
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as router1:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall(
                    firewall_policy_id=fwp_id,
                    admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                    tenant_id='noadmin',
                    router_ids=[router1['router']['id']]
                ) as firewall:
                    fw_id = firewall['firewall']['id']
                    self.callbacks.set_firewall_status(ctx, fw_id,
                                                   const.ACTIVE)
                    data = {'firewall': {'shared': True}}
                    req = self.new_update_request(
                        'firewalls', data, fw_id,
                        context=context.Context('', 'noadmin'))
                    res = req.get_response(self.ext_api)
                    self.assertEqual(exc.HTTPForbidden.code, res.status_int)

    def test_update_firewall_policy_fails_when_firewall_pending(self):
        name = "new_firewall1"
        attrs = self._get_test_firewall_attrs(name)

        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id):
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['firewall_policy_id'] = fwp_id
                with self.firewall(
                    firewall_policy_id=fwp_id,
                    admin_state_up=test_db_firewall.ADMIN_STATE_UP
                ):
                    data = {'firewall_policy': {'name': name}}
                    req = self.new_update_request('firewall_policies',
                                              data, fwp_id)
                    res = req.get_response(self.ext_api)
                    self.assertEqual(exc.HTTPConflict.code, res.status_int)

    def test_update_firewall_rule_fails_when_firewall_pending(self):
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id):
            with self.firewall_rule(name='fwr1') as fr:
                with self.firewall_policy() as fwp:
                    fwp_id = fwp['firewall_policy']['id']
                    fr_id = fr['firewall_rule']['id']
                    fw_rule_ids = [fr_id]
                    data = {'firewall_policy':
                           {'firewall_rules': fw_rule_ids}}
                    req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                    req.get_response(self.ext_api)
                    with self.firewall(
                        firewall_policy_id=fwp_id,
                        admin_state_up=test_db_firewall.ADMIN_STATE_UP
                    ):
                        data = {'firewall_rule': {'protocol': 'udp'}}
                        req = self.new_update_request('firewall_rules',
                                                  data, fr_id)
                        res = req.get_response(self.ext_api)
                        self.assertEqual(exc.HTTPConflict.code, res.status_int)

    def test_delete_firewall_with_no_routers(self):
        ctx = context.get_admin_context()
        # stop the AgentRPC patch for this one to test pending states
        self.agentapi_del_fw_p.stop()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(
                firewall_policy_id=fwp_id,
                admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                do_delete=False
            ) as fw:
                fw_id = fw['firewall']['id']
                req = self.new_delete_request('firewalls', fw_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, exc.HTTPNoContent.code)
                self.assertRaises(firewall.FirewallNotFound,
                                  self.plugin.get_firewall,
                                  ctx, fw_id)

    def test_delete_firewall_after_agent_delete(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(firewall_policy_id=fwp_id,
                               do_delete=False) as fw:
                fw_id = fw['firewall']['id']
                req = self.new_delete_request('firewalls', fw_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, exc.HTTPNoContent.code)
                self.assertRaises(firewall.FirewallNotFound,
                                  self.plugin.get_firewall,
                                  ctx, fw_id)

    def test_make_firewall_dict_with_in_place_rules(self):
        ctx = context.get_admin_context()
        with self.firewall_rule(name='fwr1') as fwr1, \
                self.firewall_rule(name='fwr2') as fwr2, \
                self.firewall_rule(name='fwr3') as fwr3:
            with self.firewall_policy() as fwp:
                fr = [fwr1, fwr2, fwr3]
                fwp_id = fwp['firewall_policy']['id']
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                req.get_response(self.ext_api)
                attrs = self._get_test_firewall_attrs()
                attrs['firewall_policy_id'] = fwp_id
                with self.firewall(
                    firewall_policy_id=fwp_id,
                    admin_state_up=test_db_firewall.ADMIN_STATE_UP,
                    router_ids=[]
                ) as fw:
                    fw_id = fw['firewall']['id']
                    fw_rules = (
                        self.plugin._make_firewall_dict_with_rules(ctx,
                                                                   fw_id)
                    )
                    self.assertEqual(fw_rules['id'], fw_id)
                    self._compare_firewall_rule_lists(
                        fwp_id, fr, fw_rules['firewall_rule_list'])

    def test_make_firewall_dict_with_in_place_rules_no_policy(self):
        ctx = context.get_admin_context()
        with self.firewall() as fw:
            fw_id = fw['firewall']['id']
            fw_rules = self.plugin._make_firewall_dict_with_rules(ctx, fw_id)
            self.assertEqual([], fw_rules['firewall_rule_list'])

    def test_list_firewalls(self):
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(name='fw1', firewall_policy_id=fwp_id,
                               description='fw') as fwalls:
                self._test_list_resources('firewall', [fwalls],
                                          query_params='description=fw')

    def test_insert_rule(self):
        ctx = context.get_admin_context()
        with self.firewall_rule() as fwr:
            fr_id = fwr['firewall_rule']['id']
            rule_info = {'firewall_rule_id': fr_id}
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall(firewall_policy_id=fwp_id) as fw:
                    fw_id = fw['firewall']['id']
                    self.plugin.insert_rule(ctx, fwp_id, rule_info)
                    fw_rules = self.plugin._make_firewall_dict_with_rules(
                        ctx, fw_id)
                    self.assertEqual(1, len(fw_rules['firewall_rule_list']))
                    self.assertEqual(fr_id,
                                     fw_rules['firewall_rule_list'][0]['id'])

    def test_insert_rule_notif(self):
        ctx = context.get_admin_context()
        with self.firewall_rule() as fwr:
            fr_id = fwr['firewall_rule']['id']
            rule_info = {'firewall_rule_id': fr_id}
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall(firewall_policy_id=fwp_id):
                    self.plugin.insert_rule(ctx, fwp_id, rule_info)
            notifications = fake_notifier.NOTIFICATIONS
            expected_event_type = 'firewall_policy.update.insert_rule'
            event_types = [event['event_type'] for event in notifications]
            self.assertIn(expected_event_type, event_types)

    def test_remove_rule(self):
        ctx = context.get_admin_context()
        with self.firewall_rule() as fwr:
            fr_id = fwr['firewall_rule']['id']
            rule_info = {'firewall_rule_id': fr_id}
            with self.firewall_policy(firewall_rules=[fr_id]) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall(firewall_policy_id=fwp_id) as fw:
                    fw_id = fw['firewall']['id']
                    self.plugin.remove_rule(ctx, fwp_id, rule_info)
                    fw_rules = self.plugin._make_firewall_dict_with_rules(
                        ctx, fw_id)
                    self.assertEqual([], fw_rules['firewall_rule_list'])

    def test_firewall_quota_lower(self):
        """Test quota using overridden value."""
        cfg.CONF.set_override('quota_firewall', 3, group='QUOTAS')
        with self.firewall(name='quota1'), \
                self.firewall(name='quota2'), \
                self.firewall(name='quota3'):
            data = {'firewall': {'name': 'quota4',
                                 'firewall_policy_id': None,
                                 'tenant_id': self._tenant_id,
                                 'shared': False}}
            req = self.new_create_request('firewalls', data, 'json')
            res = req.get_response(self.ext_api)
            self.assertIn('Quota exceeded', res.body.decode('utf-8'))
            self.assertEqual(exc.HTTPConflict.code, res.status_int)

    def test_remove_rule_notif(self):
        ctx = context.get_admin_context()
        with self.firewall_rule() as fwr:
            fr_id = fwr['firewall_rule']['id']
            rule_info = {'firewall_rule_id': fr_id}
            with self.firewall_policy(firewall_rules=[fr_id]) as fwp:
                fwp_id = fwp['firewall_policy']['id']
                with self.firewall(firewall_policy_id=fwp_id):
                    self.plugin.remove_rule(ctx, fwp_id, rule_info)
            notifications = fake_notifier.NOTIFICATIONS
            expected_event_type = 'firewall_policy.update.remove_rule'
            event_types = [event['event_type'] for event in notifications]
            self.assertIn(expected_event_type, event_types)
