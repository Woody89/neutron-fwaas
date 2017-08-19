# Copyright 2013 Big Switch Networks, Inc.
# All Rights Reserved.
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

from neutron.api.v2 import attributes as attr
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context as neutron_context
from neutron.i18n import _LW
from neutron import manager
from neutron.plugins.common import constants as const
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils
import oslo_messaging
from netaddr import IPNetwork
from neutron.i18n import _LE
from neutron.db import agents_db
from neutron_fwaas.db.hf import hf_fwaas_db
from neutron_fwaas.db.firewall import firewall_router_insertion_db
from neutron_fwaas.extensions import firewall as fw_ext
from neutron_fwaas.services.firewall.plugins.hf_dp import \
    constants as fw_constants
from neutron.common import exceptions as nexception
from random import randint

import re
import json
import requests
LOG = logging.getLogger(__name__)


class FirewallCallbacks(agents_db.AgentExtRpcCallback):
    target = oslo_messaging.Target(version='1.0')

    def __init__(self, plugin):
        super(FirewallCallbacks, self).__init__()
        self.plugin = plugin

    def set_firewall_status(self, context, firewall_id, status, **kwargs):
        """Agent uses this to set a firewall's status."""
        LOG.debug("Setting firewall %s to status: %s" % (firewall_id, status))
        # Sanitize status first
        if status in (const.ACTIVE, const.DOWN, const.INACTIVE):
            to_update = status
        else:
            to_update = const.ERROR
        # ignore changing status if firewall expects to be deleted
        # That case means that while some pending operation has been
        # performed on the backend, neutron server received delete request
        # and changed firewall status to PENDING_DELETE
        updated = self.plugin.update_firewall_status(
            context, firewall_id, to_update, not_in=(const.PENDING_DELETE,))
        if updated:
            LOG.debug("firewall %s status set: %s" % (firewall_id, to_update))
        return updated and to_update is not const.ERROR

    def firewall_deleted(self, context, firewall_id, **kwargs):
        """Agent uses this to indicate firewall is deleted."""
        LOG.debug("firewall_deleted() called")
        with context.session.begin(subtransactions=True):
            fw_db = self.plugin._get_firewall(context, firewall_id)
            # allow to delete firewalls in ERROR state
            if fw_db.status in (const.PENDING_DELETE, const.ERROR):
                self.plugin.delete_db_firewall_object(context, firewall_id)
                return True
            else:
                LOG.warn(_LW('Firewall %(fw)s unexpectedly deleted by agent, '
                             'status was %(status)s'),
                         {'fw': firewall_id, 'status': fw_db.status})
                fw_db.update({"status": const.ERROR})
                return False

    def get_firewalls_for_tenant(self, context, **kwargs):
        """Agent uses this to get all firewalls and rules for a tenant."""
        LOG.debug("get_firewalls_for_tenant() called")
        fw_list = []
        for fw in self.plugin.get_firewalls(context):
            fw_with_rules = self.plugin._make_firewall_dict_with_rules(
                context, fw['id'])
            if fw['status'] == const.PENDING_DELETE:
                fw_with_rules['add-router-ids'] = []
                fw_with_rules['del-router-ids'] = (
                    self.plugin.get_firewall_routers(context, fw['id']))
            else:
                fw_with_rules['add-router-ids'] = (
                    self.plugin.get_firewall_routers(context, fw['id']))
                fw_with_rules['del-router-ids'] = []
            fw_list.append(fw_with_rules)
        return fw_list

    def get_firewalls_for_tenant_without_rules(self, context, **kwargs):
        """Agent uses this to get all firewalls for a tenant."""
        LOG.debug("get_firewalls_for_tenant_without_rules() called")
        fw_list = [fw for fw in self.plugin.get_firewalls(context)]
        return fw_list

    def get_tenants_with_firewalls(self, context, **kwargs):
        """Agent uses this to get all tenants that have firewalls."""
        LOG.debug("get_tenants_with_firewalls() called")
        ctx = neutron_context.get_admin_context()
        fw_list = self.plugin.get_firewalls(ctx)
        fw_tenant_list = list(set(fw['tenant_id'] for fw in fw_list))
        return fw_tenant_list

    def set_insert_rule(self, context, firewall_id, status, rule):
        if status == const.ERROR:
            self.plugin.remove_rule(
                context, rule['policy_id'], rule, need_rpc=False)
            status = const.ACTIVE
            self.set_firewall_status(context, firewall_id, status)
            return
        else:
            status = const.ACTIVE
            self.set_firewall_status(context, firewall_id, status)
            return

    def set_remove_rule(self, context, firewall_id, status, rule):
        if status == const.ERROR:
            status = const.ACTIVE
            self.set_firewall_status(context, firewall_id, status)
            return
        else:
            self.plugin.remove_packetfilter_and_asso_on_db(context, rule)
            status = const.ACTIVE
            self.set_firewall_status(context, firewall_id, status)
            return


class FirewallAgentApi(object):
    """Plugin side of plugin to agent RPC API."""

    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def create_firewall(self, context, firewall):
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'create_firewall', firewall=firewall,
                   host=self.host)

    def update_firewall(self, context, firewall):
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'update_firewall', firewall=firewall,
                   host=self.host)

    def delete_firewall(self, context, firewall):
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'delete_firewall', firewall=firewall,
                   host=self.host)

    def create_vfw(self, context, vsys):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'create_vfw', vsys=vsys,
                          host=self.host)

    def delete_vfw(self, context, vsys):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'delete_vfw', vsys=vsys,
                          host=self.host)

    def insert_rule(self, context, rule, host=None):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'insert_rule', rule=rule,
                          host=self.host)

    def update_rule(self, context, rule, host=None):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_rule', rule=rule,
                          host=self.host)

    def remove_rule(self, context, packetfilter, host=None):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'remove_rule', packetfilter=packetfilter,
                          host=self.host)

    def create_vlan(self, context, vlan):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'create_vlan', vlan=vlan,
                          host=self.host)

    def delete_vlan(self, context, vlan):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'delete_vlan', vlan=vlan,
                          host=self.host)

    def create_vrf(self, context, vrf):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'create_vrf', vrf=vrf,
                          host=self.host)

    def delete_vrf(self, context, vrf):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'delete_vrf', vrf=vrf,
                          host=self.host)

    def create_zone(self, context, zone):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'create_zone', zone=zone,
                          host=self.host)

    def create_netservice(self, context, service):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'create_service', service=service,
                          host=self.host)

    def create_addr(self, context, addr):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'create_addr', addr=addr,
                          host=self.host)

    def create_timer(self, context, timer):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'create_timer', timer=timer,
                          host=self.host)

    def delete_zone(self, context, security_area):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'delete_zone', security_area=security_area,
                          host=self.host)

    def update_vrf(self, context, vrf):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_vrf', vrf=vrf,
                          host=self.host)


class FirewallPlugin(
        hf_fwaas_db.Firewall_db_mixin,
        firewall_router_insertion_db.FirewallRouterInsertionDbMixin):

    """Implementation of the Neutron Firewall Service Plugin.

    This class manages the workflow of FWaaS request/response.
    Most DB related works are implemented in class
    firewall_db.Firewall_db_mixin.
    """
    supported_extension_aliases = ["fwaas", "fwaasrouterinsertion"]
    path_prefix = fw_ext.FIREWALL_PREFIX

    def __init__(self):
        """Do the initialization for the firewall service plugin here."""
        self.start_rpc_listeners()

        self.agent_rpc = FirewallAgentApi(
            fw_constants.FIREWALL_AGENT,
            cfg.CONF.host
        )
        hf_fwaas_db.subscribe()

    def start_rpc_listeners(self):
        self.endpoints = [FirewallCallbacks(self)]

        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(
            topics.FIREWALL_PLUGIN, self.endpoints, fanout=False)
        return self.conn.consume_in_threads()

    def _rpc_update_firewall(self, context, firewall_id):
        status_update = {"firewall": {"status": const.PENDING_UPDATE}}
        super(FirewallPlugin, self).update_firewall(context, firewall_id,
                                                    status_update)
        fw_with_rules = self._make_firewall_dict_with_rules(context,
                                                            firewall_id)
        # this is triggered on an update to fw rule or policy, no
        # change in associated routers.
        fw_with_rules['add-router-ids'] = self.get_firewall_routers(
            context, firewall_id)
        fw_with_rules['del-router-ids'] = []
        self.agent_rpc.update_firewall(context, fw_with_rules)

    def _rpc_update_firewall_policy(self, context, firewall_policy_id):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy:
            for firewall_id in firewall_policy['firewall_list']:
                self._rpc_update_firewall(context, firewall_id)

    def _ensure_update_firewall(self, context, firewall_id):
        fwall = self.get_firewall(context, firewall_id)
        if fwall['status'] in [const.PENDING_CREATE,
                               const.PENDING_UPDATE,
                               const.PENDING_DELETE]:
            raise fw_ext.FirewallInPendingState(firewall_id=firewall_id,
                                                pending_state=fwall['status'])

    def _ensure_update_firewall_policy(self, context, firewall_policy_id):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy and 'firewall_list' in firewall_policy:
            for firewall_id in firewall_policy['firewall_list']:
                self._ensure_update_firewall(context, firewall_id)

    def _ensure_update_firewall_rule(self, context, firewall_rule_id):
        fw_rule = self.get_firewall_rule(context, firewall_rule_id)
        if 'firewall_policy_id' in fw_rule and fw_rule['firewall_policy_id']:
            self._ensure_update_firewall_policy(context,
                                                fw_rule['firewall_policy_id'])

    def _get_routers_for_create_firewall(self, tenant_id, context, firewall):

        # pop router_id as this goes in the router association db
        # and not firewall db
        router_ids = firewall['firewall'].pop('router_ids', None)
        if router_ids == attr.ATTR_NOT_SPECIFIED:
            # old semantics router-ids keyword not specified pick up
            # all routers on tenant.
            l3_plugin = manager.NeutronManager.get_service_plugins().get(
                const.L3_ROUTER_NAT)
            ctx = neutron_context.get_admin_context()
            routers = l3_plugin.get_routers(ctx)
            router_ids = [
                router['id']
                for router in routers
                if router['tenant_id'] == tenant_id]
            # validation can still fail this if there is another fw
            # which is associated with one of these routers.
            self.validate_firewall_routers_not_in_use(context, router_ids)
            return router_ids
        else:
            if not router_ids:
                # This indicates that user specifies no routers.
                return []
            else:
                # some router(s) provided.
                self.validate_firewall_routers_not_in_use(context, router_ids)
                return router_ids

    def _get_vlan_security_area(self, context, firewall_id, router_id):
        ip_data = {}
        ip_url = fw_constants.SERVICE_PORTAL + '/svpc/order/security_areas'
        headerdata = {'Content-type': 'application/json'}
        ip_data['firewall_id'] = firewall_id
        ip_data['sz_router_id'] = router_id
        ret = requests.post(ip_url, data=json.dumps(ip_data),
                            headers=headerdata
                            )
        if ret.json()['status'] == 'fail':
            raise fw_ext.ResourceAllocateException(
                content=ret.json()['message'])
        else:
            vlan_info = ret.json()['content']
            return vlan_info

    def _send_svpc_info(self, context, security_area):
        ip_data = {}
        ip_url = fw_constants.SERVICE_PORTAL + '/svpc/order/svpc_cidr'
        headerdata = {'Content-type': 'application/json'}
        ip_data['firewall_id'] = security_area['firewall_id']
        ip_data['cidr'] = security_area['cidr']
        ret = requests.post(ip_url, data=json.dumps(ip_data),
                            headers=headerdata
                            )
        if ret.json()['status'] == 'fail':
            raise fw_ext.ResourceAllocateException(
                content=ret.json()['message'])
        else:
            vlan_info = ret.json()['content']
            return vlan_info

    def _vlan_security_area_recover(self, context, router_id):
        url = fw_constants.SERVICE_PORTAL + '/svpc/order/security_areas/' + router_id
        headerdata = {'Content-type': 'application/json'}
        ret = requests.delete(url, headers=headerdata)
        if ret.json()['status'] == 'fail':
            raise fw_ext.ResourceAllocateException(
                content=ret.json()['message'])

    def create_firewall(self, context, firewall):
        LOG.debug("create_firewall() called")
        firewall_obj = firewall['firewall']
        tenant_id = self._get_tenant_id_for_create(context,
                                                   firewall_obj)
        fw_name = super(FirewallPlugin, self).get_firewalls(
            context,
            {'name': [firewall_obj['name']]
             }
        )
        fw_policy_id = super(FirewallPlugin, self).get_firewalls(
            context,
            {'firewall_policy_id':
             [firewall_obj['firewall_policy_id']],
             'tenant_id': [tenant_id]
             }
        )
        if fw_name:
            raise fw_ext.FirewallNameExist(name=firewall_obj['name'])
        elif fw_policy_id:
            raise fw_ext.FirewallPolicyInUse(
                firewall_policy_id=firewall_obj['firewall_policy_id'])
        else:
            status = const.ERROR
            fw = super(FirewallPlugin, self).create_firewall(
                context, firewall, status)
            data = {'id': fw['id'],
                    'fabric': 'YT-HW-BIZ',
                    'project_id': tenant_id
                    }
            resources = self._get_resource_fw(context, data)
            input_vlan_dict = {
                'vlan_id': resources['vlan'],
                'ipaddr': resources['ip'],
                'vlan_name': 'vlan-if' + resources['vlan'],
                'ifnames': '',
                'sz_id': None,
                'tenant_id': tenant_id,
                'vrf_id': None,
            }
            vlan = self._create_vlan(context, fw, input_vlan_dict)
            input_vrf_dict = {'name': firewall_obj['name'],
                              'vsys_id': None,
                              'ifnames': input_vlan_dict['vlan_name'],
                              'vlan_id': vlan['id'],
                              }
            vrf = self._create_vrf(context, fw, input_vrf_dict)
            vrf_update = {}
            input_vsys_dict = {'name': firewall_obj['name'],
                               'type': 8,
                               'vlan_id': vlan['id'],
                               'vrf_id': vrf['id']
                               }
            vsys = self._create_vsys(context, fw, input_vsys_dict)
            input_fw_vsys_dict = {
                'firewall_id': fw['id'],
                'vsys_id': vsys['id']
            }
            super(FirewallPlugin, self).create_fw_vsys(context,
                                                       input_fw_vsys_dict
                                                       )
            vrf_update['vsys_id'] = vsys['id']
            super(FirewallPlugin, self).update_vrf(context,
                                                   vrf['id'],
                                                   vrf_update
                                                   )
            status_update = {"firewall": {"status": const.ACTIVE}}
            super(FirewallPlugin, self).update_firewall(
                context,
                fw['id'],
                status_update)
            return super(FirewallPlugin, self).get_firewall(context,
                                                            fw['id']
                                                            )

    def _create_vlan(self, context, fw, vlan_dict):
        vlan_param = {'vlanId': vlan_dict['vlan_id'],
                      'ipAddr': vlan_dict['ipaddr'],
                      'ifNames': vlan_dict['ifnames']
                      }
        vlan_ret = self.agent_rpc.create_vlan(context, vlan_param)
        if vlan_ret['status'] == const.ERROR:
            status_update = {"firewall": {"status": const.ERROR}}
            super(FirewallPlugin, self).update_firewall(
                context,
                fw['id'],
                status_update)
            raise fw_ext.HardwareFirewallVlanCreateFaild(
                vlan_id=vlan_dict['vlan_id'])
        vlan = super(FirewallPlugin, self).create_vlan(context,
                                                       vlan_dict
                                                       )
        return vlan

    def _create_vrf(self, context, fw, input_vrf_dict):
        vlan_update = {}
        vrf_param = {'name': input_vrf_dict['name'],
                     'ifName': input_vrf_dict['ifnames']
                     }
        vrf_ret = self.agent_rpc.create_vrf(context, vrf_param)
        if vrf_ret['status'] == const.ERROR:
            status_update = {"firewall": {"status": const.ERROR}}
            super(FirewallPlugin, self).update_firewall(
                context,
                fw['id'],
                status_update)
            raise fw_ext.HardwareFirewallVrfCreateFaild(
                vrf_id=input_vrf_dict['name'])
        vrf = super(FirewallPlugin, self).create_vrf(context,
                                                     input_vrf_dict
                                                     )
        vlan_update['vrf_id'] = vrf['id']
        super(FirewallPlugin, self).update_vlan(context,
                                                input_vrf_dict['vlan_id'],
                                                vlan_update
                                                )
        return vrf

    def _create_vsys(self, context, firewall, input_vsys_dict):
        input_vsys_dict['resource'] = firewall['name']
        vsys_ret = self.agent_rpc.create_vfw(context, input_vsys_dict)
        if vsys_ret['status'] == const.ERROR:
            status_update = {"firewall": {"status": const.ERROR}}
            super(FirewallPlugin, self).update_firewall(
                context,
                firewall['id'],
                status_update)
            raise fw_ext.HardwareFirewallVsysCreateFaild(
                vsys_id=input_vsys_dict['name'])
        vsys = super(FirewallPlugin, self).create_vsys(context,
                                                       input_vsys_dict
                                                       )
        return vsys

    def update_firewall(self, context, id, firewall):
        LOG.debug("update_firewall() called on firewall %s", id)

        self._ensure_update_firewall(context, id)
        # pop router_id as this goes in the router association db
        # and not firewall db
        router_ids = firewall['firewall'].pop('router_ids', None)
        fw_current_rtrs = self.get_firewall_routers(context, id)
        if router_ids is not None:
            if router_ids == []:
                # This indicates that user is indicating no routers.
                fw_new_rtrs = []
            else:
                self.validate_firewall_routers_not_in_use(
                    context, router_ids, id)
                fw_new_rtrs = router_ids
            self.update_firewall_routers(context, {'fw_id': id,
                                                   'router_ids': fw_new_rtrs})
        else:
            # router-ids keyword not specified for update pick up
            # existing routers.
            fw_new_rtrs = self.get_firewall_routers(context, id)

        if not fw_new_rtrs and not fw_current_rtrs:
            # no messaging to agent needed, and we need to continue
            # in INACTIVE state
            firewall['firewall']['status'] = const.INACTIVE
            fw = super(FirewallPlugin, self).update_firewall(
                context, id, firewall)
            fw['router_ids'] = []
            return fw
        else:
            firewall['firewall']['status'] = const.PENDING_UPDATE
            fw = super(FirewallPlugin, self).update_firewall(
                context, id, firewall)
            fw['router_ids'] = fw_new_rtrs

        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, fw['id']))

        # determine rtrs to add fw to and del from
        fw_with_rules['add-router-ids'] = fw_new_rtrs
        fw_with_rules['del-router-ids'] = list(
            set(fw_current_rtrs).difference(set(fw_new_rtrs)))

        # last-router drives agent to ack with status to set state to INACTIVE
        fw_with_rules['last-router'] = not fw_new_rtrs

        LOG.debug("update_firewall %s: Add Routers: %s, Del Routers: %s",
                  fw['id'],
                  fw_with_rules['add-router-ids'],
                  fw_with_rules['del-router-ids'])

        self.agent_rpc.update_firewall(context, fw_with_rules)

        return fw

    def delete_db_firewall_object(self, context, id):
        super(FirewallPlugin, self).delete_firewall(context, id)

    def delete_firewall(self, context, id):
        fw = super(FirewallPlugin, self).get_firewall(context, id)
        if fw:
            fw_vsys_obj = super(FirewallPlugin, self).\
                get_firewalls_vsys_associations(context, {'firewall_id': [id]})
            packetfilter = super(FirewallPlugin, self).\
                get_firewall_packetfilters(
                context, {'vsys_id': [fw_vsys_obj[0]['vsys_id']]})
            if packetfilter:
                raise fw_ext.FirewallAssociatePacketfilter(fw_id=id)
            else:
                vsys_obj = super(FirewallPlugin, self).\
                    get_hardware_firewall_vsys(context,
                                               fw_vsys_obj[0]['vsys_id'])
                ret = self.agent_rpc.delete_vfw(context, vsys_obj)
                if ret['status'] == const.ERROR:
                    raise fw_ext.DeviceDeleteFailed(obj_id=id)
                else:
                    vrf_objs = super(FirewallPlugin, self).get_vrfs(
                        context, {'vsys_id': [fw_vsys_obj[0]['vsys_id']]}
                    )
                    vlan_objs = super(FirewallPlugin, self).get_vlans(
                        context, {'vrf_id': [vrf_objs[0]['id']]})
                    vlan_ret = self.agent_rpc.delete_vlan(context,
                                                          vlan_objs[0])
                    if vlan_ret['status'] == const.ERROR:
                        raise fw_ext.DeviceDeleteFailed(obj_id=vlan_objs[0][
                            'vlan_name'])
                    vrf_ret = self.agent_rpc.delete_vrf(context, vrf_objs[0])
                    if vrf_ret['status'] == const.ERROR:
                        raise fw_ext.DeviceDeleteFailed(obj_id=vrf_objs[0][
                            'name'])
                    super(FirewallPlugin, self).delete_obj_by_vsysid(
                        context, fw_vsys_obj[0]['vsys_id'])
                    super(FirewallPlugin, self).delete_vlan(
                        context, vrf_objs[0]['id'])
                    super(FirewallPlugin, self).delete_hardware_firewall_vrf(
                        context, vrf_objs[0]['id'])
                    security_areas = super(FirewallPlugin, self).\
                        get_firewall_security_areas(context, {'firewall_id':
                                                              [id]})
                    for item in security_areas:
                        area_zone_associa = super(FirewallPlugin, self).\
                            get_firewall_area_zone_associations(
                            context, {'security_area_id':
                                      [item['id']]})
                        super(FirewallPlugin, self).\
                            delete_firewall_area_zone_associations(
                                context, area_zone_associa[0]['id'])
                        super(FirewallPlugin, self).\
                            delete_hardware_firewall_security_zone(
                                context, area_zone_associa[0][
                                    'security_zone_id'])
                        super(FirewallPlugin, self).\
                            delete_security_area(context, area_zone_associa[0][
                                'security_area_id'])
                    super(FirewallPlugin, self).delete_firewall_vsys_associa(
                        context, id)
                    super(FirewallPlugin, self).delete_firewall(context, id)
                    super(FirewallPlugin, self).delete_hardware_firewall_vsys(
                        context, fw_vsys_obj[0]['vsys_id'])
                    self._recover_resource_fw(context, id)
        else:
            raise fw_ext.FirewallNotFound(firewall_id=id)

    def update_firewall_policy(self, context, id, firewall_policy):
        LOG.debug("update_firewall_policy() called")
        self._ensure_update_firewall_policy(context, id)
        fwp = super(FirewallPlugin,
                    self).update_firewall_policy(context, id, firewall_policy)
        # self._rpc_update_firewall_policy(context, id)
        return fwp

    def _notify_firewall_updates(self, context, resource, update_info):
        notifier = n_rpc.get_notifier('network')
        notifier.info(context, resource, update_info)

    def insert_rule(self, context, id, rule_info):
        """modified method for HF requirement pz"""
        LOG.debug("insert_rule() called")
        ret = super(FirewallPlugin, self).insert_rule(context, id, rule_info)
        fwr = super(FirewallPlugin, self).get_firewall_rule(
            context, rule_info["firewall_rule_id"])
        self._ensure_update_firewall_policy(context, id)
        rpc_insert_rule_dict = {
            "name": fwr['name'],
            "srcIpObjNames": "",
            "dstIpObjNames": "",
            "dstZoneName": "",
            "srcZoneName": "",
            "serviceNames": "",
            "action": "",
            "longSession": fwr['session_type'],
            "timeObjName": "",
            "vfwName": "",
            "targetName": "",
            "log": "0",
            "moveFlag": "0",
        }
        try:
            filters = {}
            # To determine whether the need for regulation
            if rule_info['insert_before']:
                filters['id'] = [rule_info['insert_before']]
                target_rule_dict = super(
                    FirewallPlugin, self).get_firewall_rules(
                    context, filters)
                rpc_insert_rule_dict['targetName'] = \
                    target_rule_dict[0]['name']
                rpc_insert_rule_dict['moveFlag'] = "0"
            elif rule_info['insert_after']:
                filters['id'] = [rule_info['insert_after']]
                target_rule_dict = super(
                    FirewallPlugin, self).get_firewall_rules(
                    context, filters)
                rpc_insert_rule_dict['targetName'] = \
                    target_rule_dict[0]['name']
                rpc_insert_rule_dict['moveFlag'] = "1"
            firewall_obj = super(
                FirewallPlugin, self).get_firewalls(
                context, {
                    "firewall_policy_id": [
                        fwr['firewall_policy_id']
                    ]
                })
            if len(firewall_obj) == 0:
                raise fw_ext.HardwareFirewallNotFound()
            firewall_id = firewall_obj[0]['id']
            # self.update_firewall_status(
            #     context, firewall_id, const.PENDING_UPDATE)
            # rule_dict :save to database
            # rpc_insert_rule_dict : save to rpc& device
            fwr['firewall_id'] = firewall_id
            fwr['vsys_id'] = self.get_vsys_id(context, firewall_id=firewall_id)
            fwr['vfwName'] =\
                rpc_insert_rule_dict['vfwName'] = firewall_obj[0]['name']
            if fwr['action'] == "allow":
                rpc_insert_rule_dict['action'] = "1"
            else:
                rpc_insert_rule_dict['action'] = "0"
            s_area = self._check_hardware_firewall_area_byrouter(
                context,
                router_id = fwr['src_router_id'],
                firewall_id = firewall_id,
                area_type='src'
            )
            d_area = self._check_hardware_firewall_area_byrouter(context,
                router_id=fwr['dst_router_id'], firewall_id=firewall_id,
                area_type='dst'
            )
            rpc_insert_rule_dict['srcZoneName'], rpc_insert_rule_dict[
                'dstZoneName'] = s_area['name'], d_area['name']
            timer_obj = self._create_timer(
                context, fwr)
            rpc_insert_rule_dict['timeObjName'] = timer_obj['name']
            s_addr_objs, d_addr_objs = self._create_addr(context, fwr)
            s_addr_names = ",".join([addr_name['name']
                                     for addr_name in s_addr_objs])
            d_addr_names = ",".join([addr_name['name']
                                     for addr_name in d_addr_objs])
            rpc_insert_rule_dict['srcIpObjNames'], rpc_insert_rule_dict[
                'dstIpObjNames'] = s_addr_names, d_addr_names
            service_obj = self._create_netservice(context, fwr)
            rpc_insert_rule_dict['serviceNames'] = service_obj['name']
            insert_ret = self.agent_rpc.insert_rule(
                context, rpc_insert_rule_dict)
            if insert_ret['status'] == const.ERROR:
                raise fw_ext.FirewallRuleCreateFaild(name=fwr['name'])
        except Exception as e:
            super(FirewallPlugin, self).remove_rule(context, id, rule_info)
            super(
                FirewallPlugin,
                self).delete_firewall_rule(
                context,
                rule_info['firewall_rule_id'])
            raise
        packetfilter_obj = self._create_hardware_firewall_packetfilter(
            context, fwr, rpc_insert_rule_dict, timer_obj)
        self.create_hardware_firewall_packetfilter_associate(
            context,
            fwr=fwr,
            packetfilter_obj=packetfilter_obj,
            s_addr_objs=s_addr_objs,
            d_addr_objs=d_addr_objs,
            service_obj=service_obj,
            szone_obj=s_area,
            dzone_obj=d_area
        )
        resource = 'firewall_policy.update.insert_rule'
        self._notify_firewall_updates(context, resource, rule_info)
        return ret

    def _rpc_insert_rule(self, context, firewall_policy_id, rule_info):
        """Added method for HF requirement"""
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy:
            for firewall_id in firewall_policy['firewall_list']:
                status_update = {"firewall": {"status": const.PENDING_UPDATE}}
                super(FirewallPlugin, self).update_firewall(
                    context,
                    firewall_id,
                    status_update)
                self.agent_rpc.insert_rule(context, rule_info)

    def remove_rule(self, context, id, rule_info, need_rpc=True):
        # need_rpc : Whether you need to delete data from the device
        LOG.debug("remove_rule() called")
        self._ensure_update_firewall_policy(context, id)
        fwp = super(FirewallPlugin, self).get_firewall_policy(
            context, id)
        if rule_info['firewall_rule_id'] not in fwp['firewall_rules']:
            raise fw_ext.FirewallRuleNotAssociatedWithPolicy(
                firewall_rule_id=rule_info['firewall_rule_id'],
                firewall_policy_id=id
            )
#         self._rpc_update_firewall_policy(context, id)
        fwr_id = rule_info['firewall_rule_id']
        rule_packetfilter = super(FirewallPlugin,
                                  self).get_packetfilter_ids(context, {
                                      'rule_id': [fwr_id]
                                  }
        )
        if len(rule_packetfilter) == 0:
            raise fw_ext.FirewallRulesPacketfilterAssociationsNotFound(
                rule_packetfilter_id=fwr_id)
        packetfilter_id = rule_packetfilter[0]['packetfilter_id']
        packetfilter = super(FirewallPlugin,
                             self).get_firewall_packetfilters(context, {
                                 'id': [packetfilter_id]
                             }
        )
        if len(packetfilter) == 0:
            raise fw_ext.FirewallPacketfilterNotFound(
                fw_packetfilter_id=packetfilter_id)
        firewall = self.get_hardware_firewall_vsys(
            context, packetfilter[0]['vsys_id'])
        packetfilter[0]["vfwName"] = firewall['name']
        packetfilter[0]['firewall_rule_id'] = rule_info['firewall_rule_id']
        packetfilter[0]['policy_id'] = id
        try:
            if need_rpc:
                remove_ret = self.agent_rpc.remove_rule(
                    context, packetfilter[0])
                if remove_ret['status'] == const.ERROR:
                    raise fw_ext.FirewallRuleDeleteFaild(name=firewall['name'])
            self.remove_packetfilter_and_asso_on_db(context, packetfilter[0])
            fwp = super(FirewallPlugin, self).remove_rule(
                context,
                id,
                rule_info)
        except nexception.NotFound:
            raise
        resource = 'firewall_policy.update.remove_rule'
        self._notify_firewall_updates(context, resource, rule_info)
        return fwp

    def remove_packetfilter_and_asso_on_db(self, context, packetfilter):
        # This is insert_rule have error on create_packetfilter
        # The associations was create , so there is need to delete the
        # Associations
        super(FirewallPlugin, self).del_rule_packetfilter(
            context, packetfilter['id'])
        super(FirewallPlugin, self).delete_firewall_packetfilter(
            context,
            packetfilter['id'])

    def remove_rule_on_db(self, context, id, rule_info):
        # This is insert_rule have error on create 3 elemenet
        # (service, addr, time)
        # The Associations is not create ,so there is no need to delete the
        # Associations
        self._ensure_update_firewall_policy(context, id)
        fwp = super(FirewallPlugin, self).\
            remove_rule(context, id, rule_info)
        self.update_firewall_status(context,
                                    id=id,
                                    status=const.ACTIVE)

    def create_hardware_firewall_packetfilter_associate(self, context,
                                                        fwr,
                                                        packetfilter_obj,
                                                        s_addr_objs,
                                                        d_addr_objs,
                                                        service_obj,
                                                        szone_obj,
                                                        dzone_obj,
                                                        ):
        # create packetfilter associations to (addr , service , timer)
        self.create_hardware_firewall_rule_packetfilter_associate(
            context, packetfilter_obj['id'], fwr['id']
        )
        for s_addr_obj in s_addr_objs:
            self.create_hardware_firewall_packetfilter_saddr_associate(
                context, s_addr_obj['id'], packetfilter_obj['id'])
        for d_addr_obj in d_addr_objs:
            self.create_hardware_firewall_packetfilter_daddr_associate(
                context, d_addr_obj['id'], packetfilter_obj['id'])
        self.create_hardware_firewall_packetfilter_service_associate(
            context, service_obj['id'], packetfilter_obj['id'])
        self.create_hardware_firewall_packetfilter_zone_associate(
            context, szone_obj['id'], packetfilter_obj['id'])
        self.create_hardware_firewall_packetfilter_zone_associate(
            context, dzone_obj['id'], packetfilter_obj['id'])

    def _create_hardware_firewall_packetfilter(
            self, context, packetfilter, rpc_insert_rule_dict, timer_obj):
        packetfilter['timeobj_id'] = timer_obj['id']
        packetfilter['log'] = rpc_insert_rule_dict['log']
        packetfilter['action'] = rpc_insert_rule_dict['action']
        return self.create_hardware_firewall_packetfilter(
            context,
            packetfilter)

    def get_firewalls(self, context, filters=None, fields=None):
        LOG.debug("fwaas get_firewalls() called")
        fw_list = super(FirewallPlugin, self).get_firewalls(
            context, filters, fields)
        for fw in fw_list:
            fw_current_rtrs = self.get_firewall_routers(context, fw['id'])
            fw['router_ids'] = fw_current_rtrs
        return fw_list

    def get_firewall(self, context, id, fields=None):
        LOG.debug("fwaas get_firewall() called")
        res = super(FirewallPlugin, self).get_firewall(
            context, id, fields)
        fw_current_rtrs = self.get_firewall_routers(context, id)
        res['router_ids'] = fw_current_rtrs
        return res

    def _check_hardware_firewall_area_byrouter(
            self, context, router_id, firewall_id, area_type):
        # Determine the destination security zone ( same as one, not others)
        # Part of the function with _check_hardware_firewall_source_area_byip()
        # repeat
        filters = {"firewall_id": [firewall_id], 'router_id': [router_id]}
        dst_areas = []
        securityareas = super(FirewallPlugin, self). \
                    get_firewall_security_areas(
                    context,
                filters=filters)
        if len(securityareas) != 1:
            raise fw_ext.HardwareFirewallSecurityAreaNotFoundByRouterID(
                router_id=router_id)
        elif area_type == "dst" and\
                securityareas[0]['security_area_type'] == "out":
                raise fw_ext.HardwareFirewallSecurityareaDstNotOUT()
        zone_id = self.get_zone_id(context, securityareas[0]['id'])
        securityareas = self.get_hardware_firewall_security_zone(
            context, id=zone_id)
        return securityareas

    def _create_addr(self, context, rule_info_obj):
        # create addr on device , and source_ip can be multiple
        LOG.debug("insert_ip_addr_obj called")
        d_addr_objs, s_addr_objs = [], []
        for source_ip in rule_info_obj['source_ip_address'].split(";"):
            s_ip_addr_name = source_ip
            ip_filters = dict()
            ip_filters['name'] = [s_ip_addr_name]
            ip_filters['vsys_id'] = [rule_info_obj['vsys_id']]
            ip_addr_input_dict = {}
            ip_addr_input_dict['name'] = s_ip_addr_name
            ip_addr_input_dict['ip'] = source_ip
            ip_addr_input_dict['vsys_id'] = rule_info_obj['vsys_id']
            ip_addr_obj_list = super(
                FirewallPlugin, self).get_hardware_ip_addr_objs(
                context, ip_filters)
            if len(ip_addr_obj_list) == 0:
                ip_addr_input_dict['vfwName'] = rule_info_obj['vfwName']
                ret = self.agent_rpc.create_addr(context, ip_addr_input_dict)
                if ret['status'] == const.ERROR:
                    raise fw_ext.HardwareFirewallAddrCreateFaild(
                        name=s_ip_addr_name)
                else:
                    s_addr_obj = super(
                        FirewallPlugin, self).create_hardware_ip_addr_obj(
                        context, rule_info_obj, ip_addr_input_dict)
            else:
                s_addr_obj = ip_addr_obj_list[0]
            s_addr_objs.append(s_addr_obj)

        for dst_ip in rule_info_obj['destination_ip_address'].split(";"):
            d_ip_addr_name = dst_ip
            ip_filters = dict()
            ip_filters['name'] = [d_ip_addr_name]
            ip_filters['vsys_id'] = [rule_info_obj['vsys_id']]
            ip_addr_input_dict = {}
            ip_addr_input_dict['name'] = d_ip_addr_name
            ip_addr_input_dict['ip'] = dst_ip
            ip_addr_input_dict['vsys_id'] = rule_info_obj['vsys_id']
            ip_addr_obj_list = super(
                FirewallPlugin, self).get_hardware_ip_addr_objs(
                context, ip_filters)
            if len(ip_addr_obj_list) == 0:
                ip_addr_input_dict['vfwName'] = rule_info_obj['vfwName']
                ret = self.agent_rpc.create_addr(context, ip_addr_input_dict)
                if ret['status'] == const.ERROR:
                    raise fw_ext.HardwareFirewallAddrCreateFaild(
                        name=d_ip_addr_name)
                else:
                    d_addr_obj = super(
                        FirewallPlugin, self).create_hardware_ip_addr_obj(
                        context, rule_info_obj, ip_addr_input_dict)
            else:
                d_addr_obj = ip_addr_obj_list[0]
            d_addr_objs.append(d_addr_obj)
        return s_addr_objs, d_addr_objs

    def _create_netservice(self, context, rule_info_obj):
        # create netservice on device
        # if port :
        #   name = protocol + port
        # else:
        #   name = protocol + any
        LOG.debug("insert_server_obj called")
        if rule_info_obj['protocol'] == "icmp":
            server_name="icmp"
        elif rule_info_obj['destination_port'] is not None:
            server_name = rule_info_obj['protocol'] + \
                "_" + rule_info_obj['destination_port']
        else:
            server_name = rule_info_obj['protocol'] + "_" + "Any"
        server_input_dict = {}
        server_input_dict['name'] = server_name
        server_input_dict['proto'] = rule_info_obj['protocol']
        if rule_info_obj['protocol'] == "icmp":
            server_input_dict['destination_port'] = ""
        elif rule_info_obj['destination_port'] is not None:
            server_input_dict['destination_port'] = rule_info_obj[
                'destination_port']
        server_input_dict['vsys_id'] = rule_info_obj['vsys_id']
        server_filters = {}
        server_filters['vsys_id'] = [rule_info_obj['vsys_id']]
        server_filters['name'] = [server_name]
        server_obj_list = super(FirewallPlugin, self).get_hardware_server_objs(
            context, server_filters)
        if len(server_obj_list) == 0:
            input_dict = server_input_dict
            input_dict['port'] = input_dict['destination_port']
            input_dict['vfwName'] = rule_info_obj['vfwName']
            if rule_info_obj['protocol'] == "icmp":
                input_dict['port'] = "8-0"
            elif ":" in input_dict['port']:
                input_dict['port'] = "-".join(input_dict['port'].split(":"))
            else:
                input_dict['port'] =\
                    "-".join([input_dict['port'],input_dict['port']])
            input_dict['proto'] = {'tcp': '6', 'udp': '17', 'icmp': '1'}[
                input_dict['proto']]
            ret = self.agent_rpc.create_netservice(context, input_dict)
            if ret['status'] == const.ERROR:
                raise fw_ext.HardwareFirewallServiceCreateFaild(
                    name=server_name)
            else:
                server_obj = super(
                    FirewallPlugin,
                    self).create_hardware_server_obj(
                    context,
                    rule_info_obj,
                    server_input_dict)
        else:
            server_obj = server_obj_list[0]
        return server_obj

    def _create_timer(self, context, rule_info_obj):
        # create timer on device
        LOG.debug("insert_time_obj called")
        date_time_name = "".join(
            re.findall(
                r'(\w*[0-9]+)\w*',
                rule_info_obj['start_time'] + rule_info_obj['end_time']))
        time_filters = {}
        time_filters['vsys_id'] = [rule_info_obj["vsys_id"]]
        time_filters['name'] = [date_time_name]
        time_obj_list = super(FirewallPlugin, self).get_hardware_time_objs(
            context, time_filters)
        date_time_input_dict = {}
        date_time_input_dict['name'] = date_time_name
        date_time_input_dict['mode'] = '1'
        date_time_input_dict['week'] = ''
        date_time_input_dict['startDay'], date_time_input_dict['startTime']\
            = rule_info_obj['start_time'].split(' ')
        date_time_input_dict['endDay'], date_time_input_dict[
            'endTime'] = rule_info_obj['end_time'].split(' ')
        date_time_input_dict['vsysName'] = rule_info_obj['vfwName']
        if len(time_obj_list) == 0:
            ret = self.agent_rpc.create_timer(context, date_time_input_dict)
            # ret = {"status":"success"}
            if ret['status'] == const.ERROR:
                raise fw_ext.HardwareFirewallTimerCreateFaild(
                    name=date_time_input_dict['name'])
            else:
                timer_obj = super(
                    FirewallPlugin, self).create_hardware_time_obj(
                    context, rule_info_obj, date_time_input_dict)
        else:
            timer_obj = time_obj_list[0]
        return timer_obj

    def get_vsys_id(self, context, firewall_id):
        # get vsys_id from firewall_vsys_associations
        ret = super(FirewallPlugin, self).get_firewalls_vsys_associations(
            context, filters={"firewall_id": [firewall_id]})
        return ret[0]["vsys_id"]

    def get_zone_id(self, context, security_area_id):
        # get zone_id  from area_zone_associations
        ret = super(FirewallPlugin, self).\
            get_hardware_firewalls_security_area_zone_associations(
            context, filters={"security_area_id": [security_area_id]})
        return ret[0]["security_zone_id"]

    def _get_resource_fw(self, context, data):
        ip_url = fw_constants.SERVICE_PORTAL + '/svpc/order/firewall'
        headerdata = {'Content-type': 'application/json'}
        ret = requests.post(ip_url, data=json.dumps(data),
                            headers=headerdata
                            )
        if ret.json()['status'] == 'fail':
            raise fw_ext.ResourceAllocateException(
                content=ret.json()['message'])
        else:
            resources = ret.json()['content']
            return resources
    
    def _recover_resource_fw(self, context, id):
        ip_url = fw_constants.SERVICE_PORTAL + '/svpc/order/firewall/' + id
        headerdata = {'Content-type': 'application/json'}
        ret = requests.delete(ip_url,
                            headers=headerdata
                            )
        if ret.json()['status'] == 'fail':
            raise fw_ext.ResourceAllocateException(
                content=ret.json()['message'])

    def create_security_area(self, context, security_area):
        LOG.debug("create_security_area called")
        fws = security_area['security_area']
        firewall = super(FirewallPlugin, self).get_firewall(context,
                                                            fws['firewall_id'])
        if firewall['status'] != const.ACTIVE:
            raise fw_ext.FirewallNotActive(firewall_name=firewall['name'])
        self._check_security_area_params(context, fws)
        tenant_id = self._get_tenant_id_for_create(context, fws)
        fws['tenant_id'] = tenant_id
        if fws['security_area_type'] == 'out':
            fws_list = super(FirewallPlugin, self). \
                get_firewall_security_areas(context, {
                    'security_area_type': ['out'],
                    'firewall_id': [fws['firewall_id']]
            })
            if len(fws_list):
                raise fw_ext.HardwareFirewallSecurityAreaOutExist()
            if len(fws['cidr']) > 1:
                raise fw_ext.HardwareFirewallSecurityAreaCidr()
            fws['priority'] = '5'
            fws['cidr'] = fws['cidr'][0]
            fws['router_id'] = fws['router_id']
            self._send_svpc_info(context, fws)
            vrf_out = self._get_vrf_by_area(context, fws)
            vlan_out_list = super(FirewallPlugin, self). \
                _get_hardware_firewall_vlans(context,
                                             {'vrf_id':
                                                  [vrf_out['id']]})
            vlan_out = ''
            for vlan in vlan_out_list:
                if vlan['sz_id'] is None:
                    vlan_out = vlan
            fws['ifnames'] = vlan_out['vlan_name']
            security_area = super(FirewallPlugin, self). \
                create_security_area(context, fws)
            security_area_obj = self._create_security_zones(context,
                                                            security_area,
                                                            vlan_out)
            security_area_obj['cidr'] = security_area_obj['cidr'],
        elif fws['security_area_type'] == 'in':
            fws['priority'] = '85'
            fws['cidr'] = ';'.join(fws['cidr'])
            fws['ifnames'] = ''
            security_area = super(FirewallPlugin, self). \
                create_security_area(context, fws)
            firewall_id = security_area['firewall_id']
            try:
                vlan_info = self._get_vlan_security_area(context,
                                                         firewall_id,
                                                         fws['router_id'])
            except:
                super(FirewallPlugin, self). \
                    delete_firewall_security_area(
                    context,
                    security_area['router_id'])
                raise
            vlan_id=vlan_info['vlan']
            dptech_firewall_vlan = hf_fwaas_db.HardwareFirewallVlan(
                vlan_id=vlan_id,
                vlan_name='vlan-if' + vlan_id,
                ipaddr=vlan_info['ip'],
                ifnames='',
                sz_id=None,
                vrf_id=None,
                tenant_id=tenant_id)
            try:
                vlan_obj = self._create_vlan_obj(context, dptech_firewall_vlan)
            except:
                super(FirewallPlugin, self). \
                    delete_firewall_security_area(
                    context, security_area['router_id'])
                raise
            security_area['ifnames'] = vlan_obj['vlan_name']
            super(
                FirewallPlugin,
                self).update_security_area(
                context,
                security_area['id'],
                security_area)
            dptech_firewall_vrf = self._get_vrf_by_area(context, security_area)
            dptech_firewall_vrf['ifnames'] = dptech_firewall_vrf['ifnames'] + \
                                             ',' + vlan_obj['vlan_name']
            try:
                self._update_vrf(context, dptech_firewall_vrf)
            except:
                super(FirewallPlugin, self). \
                    delete_hardware_firewall_vlan(context, vlan_obj['id'])
                super(FirewallPlugin, self). \
                    delete_firewall_security_area(
                    context, security_area['router_id'])
                raise
            vlan_obj['vrf_id'] = dptech_firewall_vrf['id']
            super(FirewallPlugin, self).update_hardware_firewall_vlan(
                context, vlan_obj['id'], vlan_obj)
            security_area_obj = self._create_security_zones(
                context, security_area, vlan_obj)
            security_area_obj['cidr'] = security_area_obj['cidr'].split(';')
        else:
            raise fw_ext.HardwareFirewallSecurityAreaTypeError()
        return security_area_obj

    def _create_vlan_obj(self, context, vlan):
        vlan_dict = {
            "vlanId": vlan['vlan_id'],
            "ipAddr": vlan['ipaddr'],
            "ifNames": vlan['ifnames']}
        rv = self.agent_rpc.create_vlan(context, vlan_dict)
        if rv['status'] == const.ERROR:
            raise fw_ext.HardwareFirewallVlanCreateFaild(vlan_id=vlan['id'])
        vlan = super(
            FirewallPlugin,
            self).create_hardware_firewall_vlan(
            context,
            vlan)
        return vlan

    def _check_security_area_params(self, context, security_area_obj):
        if len(security_area_obj['cidr']) == 0:
            raise fw_ext.HardwareFirewallSecurityArearCidrIsNone
        firewall_id = security_area_obj['firewall_id']
        security_area_name_filter = {}
        security_area_name_filter['firewall_id'] = [firewall_id]
        security_area_name_filter['name'] = [security_area_obj['name']]
        security_area_name_list = super(FirewallPlugin, self).\
            get_firewall_security_areas(context,
                                        security_area_name_filter)
        if len(security_area_name_list):
            raise fw_ext.HardwareFirewallSecurityAreaNameExist()
        security_area_router_filter = {}
        security_area_router_filter['firewall_id'] = [firewall_id]
        security_area_router_filter['router_id'] = [
            security_area_obj['router_id']]
        security_area_router_list = super(FirewallPlugin, self).\
            get_firewall_security_areas(context,
                                        security_area_router_filter)
        if len(security_area_router_list):
            raise fw_ext.HardwareFirewallSecurityArearouterExist()

    def _create_security_zones(self, context, security_area, vlan):
        firewall = super(FirewallPlugin, self).get_firewall(
            context, security_area['firewall_id'])
        create_zone_dict = {
            'name': security_area['name'],
            'ifNames': security_area['ifnames'],
            'priority': security_area['priority'],
            'vfwName': firewall['name']}
        rz = self.agent_rpc.create_zone(context, create_zone_dict)
        if rz['status'] == const.ERROR:
            if security_area['security_area_type'] == 'in':
                vrf = self._get_vrf_by_area(context, security_area)
                vrf = self._get_vrf_ifnames(context, vrf, vlan)
                super(FirewallPlugin, self).update_vrf(context, vrf['id'], vrf)
                super(FirewallPlugin, self).\
                    delete_hardware_firewall_vlan(context,
                                                  vlan['id'])
            super(FirewallPlugin, self).\
                delete_firewall_security_area(context,
                                              security_area['router_id'])
            raise fw_ext.HardwareFirewallSecurityAreaCreateFailed(
                security_area_name=security_area['name'])
        security_zone = super(FirewallPlugin, self).\
            create_hardware_firewall_security_zone(context,
                                                   security_area)
        vlan['sz_id'] = security_zone['id']
        super(
            FirewallPlugin,
            self).update_hardware_firewall_vlan(
            context,
            vlan['id'],
            vlan)
        fwaz = hf_fwaas_db.FirewallAreaZoneAssociations(
            security_area_id=security_area['id'],
            security_zone_id=security_zone['id']
        )
        super(FirewallPlugin, self).create_firewall_area_zone_associations(
            context, fwaz)
        return security_area

    def _get_vrf_by_area(self, context, securityarea):
        firewalls_vsys_filter = {}
        firewalls_vsys_filter['firewall_id'] = [securityarea['firewall_id']]
        firewalls_vsys_list = super(FirewallPlugin, self).\
            get_firewalls_vsys_associations(context,
                                            firewalls_vsys_filter)
        firewalls_vsys = firewalls_vsys_list[0]
        vsys_id = firewalls_vsys['vsys_id']
        vsys = super(FirewallPlugin, self).get_hardware_firewall_vsys(context,
                                                                      vsys_id)
        dptech_firewall_vrf_filter = {}
        dptech_firewall_vrf_filter['vsys_id'] = [vsys['id']]
        dptech_firewall_vrf_list = super(FirewallPlugin, self).\
            get_vrfs_obj(context, dptech_firewall_vrf_filter)
        dptech_firewall_vrf = dptech_firewall_vrf_list[0]
        return dptech_firewall_vrf

    def _update_vrf(self, context, vrf):
        update_vrf_dicr = {
            'vrfName': vrf['name'],
            'vrfInterface': vrf['ifnames']
        }
        rf = self.agent_rpc.update_vrf(context, update_vrf_dicr)
        if rf['status'] == const.ERROR:
            raise fw_ext.HardwareFirewallVrfUpdateFailed()
        super(FirewallPlugin, self).update_vrf(context, vrf['id'], vrf)

    def _get_vrf_ifnames(self, context, vrf, vlan):
        ifnames_vrf = vrf['ifnames']
        ifnames_list = ifnames_vrf.split(',')
        if vlan['vlan_name'] in ifnames_list:
            del ifnames_list[ifnames_list.index(vlan['vlan_name'])]

        new_ifnames = ",".join(ifnames_list)
        vrf['ifnames'] = new_ifnames
        return vrf

    def delete_security_area(self, context, id):
        security_area = super(
            FirewallPlugin,
            self).get_firewall_security_area(
            context,
            id)
        firewall_id = security_area['firewall_id']
        firewall = super(FirewallPlugin, self).get_firewall(context,
                                                            firewall_id)
        security_area_zone = super(
            FirewallPlugin, self). get_firewall_area_zone_associations(
            context, {
                'security_area_id': [
                    security_area['id']]})[0]
        firewall_security_zone_list = super(FirewallPlugin, self).\
            get_hardware_firewalls_security_zone_associations(
            context, {'sz_id': [security_area_zone['security_zone_id']]})
        if len(firewall_security_zone_list) > 0:
            raise fw_ext.HardwareFirewallSecurityAreaInUSe(
                security_area_name=security_area['name'])
        vlan = super(
            FirewallPlugin, self)._get_hardware_firewall_vlans(
            context, {
                'sz_id': [security_area_zone['security_zone_id']]})[0]
        delete_zone_dict = {
            'name': security_area['name'],
            'vfwName': firewall['name']}
        rz = self.agent_rpc.delete_zone(context, delete_zone_dict)
        if rz['status'] == const.ERROR:
            raise fw_ext.HardwareFirewallSecurityAreaDeleteFailed
        vrf = self._get_vrf_by_area(context, security_area)
        vrf = self._get_vrf_ifnames(context, vrf, vlan)
        try:
            if security_area['security_area_type'] == 'in':
                self._update_vrf(context, vrf)
        except:
            raise
        finally:
            super(FirewallPlugin, self).\
                delete_firewall_area_zone_associations(
                context, security_area_zone['id'])
            if security_area['security_area_type'] == 'in':
                super(FirewallPlugin, self).delete_hardware_firewall_vlan(
                    context, vlan['id'])
                self._vlan_security_area_recover(context,
                                                 security_area['router_id'])
            else:
                vlan['sz_id'] = None
                super(FirewallPlugin, self).\
                        create_hardware_firewall_vlan(context, vlan)
            super(FirewallPlugin, self).delete_hardware_firewall_security_zone(
                context, security_area_zone['security_zone_id'])
            super(
                FirewallPlugin,
                self).delete_firewall_security_area(
                context,
                id)

    def create_firewall_rule(self, context, firewall_rule):
        self._ensure_update_firewall_rule_uniq(context, firewall_rule)
        self.check_create_rule_ip_legal(firewall_rule)
        return super(FirewallPlugin, self).create_firewall_rule(
            context,
            firewall_rule)

    def _ensure_update_firewall_rule_uniq(self, context, firewall_rule):
        rule = self.get_firewall_rules(context, {
            "tenant_id": [context.tenant_id],
            "name": [firewall_rule['firewall_rule']['name']]
        })
        if len(rule) != 0:
            raise fw_ext.FirewallRuleNameExist(
                name=firewall_rule['firewall_rule']['name'])

    def create_firewall_policy(self, context, firewall_policy):
        filters = {"name": [firewall_policy["firewall_policy"]["name"]]}
        fwp = self.get_firewall_policies(context, filters=filters)
        if len(fwp) != 0:
            raise fw_ext.FirewallPolicyNameExist(
                name=firewall_policy["firewall_policy"]["name"])
        return super(
            FirewallPlugin,
            self).create_firewall_policy(
            context,
            firewall_policy)

    def get_host_for_ha(self, context=None):
        filters = {
            "agent_type": [fw_constants.AGENT_TYPE]
        }
        agents = super(FirewallPlugin, self).get_agents(
            context, filters=filters)
        if len(agents) > 0:
            step = randint(0, len(agents) - 1)
            return agents[step]['host']
        else:
            return cfg.CONF.host

    def update_firewall_rule(self, context, id, firewall_rule):
        self.check_update_rule_ip_legal(firewall_rule)
        origin_fwr = super(FirewallPlugin, self).get_firewall_rule(context, id)
        if origin_fwr['firewall_policy_id'] in [None, '']:
            raise fw_ext.FirewallRuleNotAssociatedWithPolicy(
                firewall_rule_id=id,
                firewall_policy_id=None
            )
        if firewall_rule['firewall_rule'].get('name') and origin_fwr['name'] != firewall_rule['firewall_rule']['name']:
            self._ensure_update_firewall_rule_uniq(context, firewall_rule)
        after_fwr = super(FirewallPlugin, self).update_firewall_rule(
            context, id, firewall_rule)

        try:
            rpc_update_rule_dict = {
                "oldname": origin_fwr['name'],
                "name": after_fwr['name'],
                "srcIpObjNames": "",
                "dstIpObjNames": "",
                "dstZoneName": "",
                "srcZoneName": "",
                "serviceNames": "",
                "action": "",
                "longSession": after_fwr['session_type'],
                "timeObjName": "",
                "vfwName": "",
                # "targetName": "",
                "log": "0",
                # "moveFlag": "0",
            }
            # To determine whether the need for regulation
            firewall_obj = super(
                FirewallPlugin, self).get_firewalls(
                context, {
                    "firewall_policy_id": [
                        after_fwr['firewall_policy_id']
                    ]
                })
            if len(firewall_obj) == 0:
                raise fw_ext.HardwareFirewallNotFound()

            firewall_id = firewall_obj[0]['id']
            # self.update_firewall_status(
            #     context, firewall_id, const.PENDING_UPDATE)
            # rule_dict :save to database
            # rpc_insert_rule_dict : save to rpc& device
            after_fwr['firewall_id'] \
                = rpc_update_rule_dict['firewall_id'] = firewall_id
            after_fwr['vsys_id'] = self.get_vsys_id(
                context, firewall_id=firewall_id)
            after_fwr['vfwName'] = \
                rpc_update_rule_dict['vfwName'] = firewall_obj[0]['name']
            if after_fwr['action'] == "allow":
                rpc_update_rule_dict['action'] = "1"
            else:
                rpc_update_rule_dict['action'] = "0"
            s_area = self._check_hardware_firewall_area_byrouter(context,
                router_id=after_fwr['src_router_id'], firewall_id=firewall_id,
                area_type='src'
            )
            d_area = self._check_hardware_firewall_area_byrouter(context,
                router_id=after_fwr['dst_router_id'], firewall_id=firewall_id,
                area_type='dst'
            )
            rpc_update_rule_dict['srcZoneName'],\
                rpc_update_rule_dict['dstZoneName'] \
                = s_area['name'], d_area['name']
            timer_obj = self._create_timer(
                context, after_fwr)
            rpc_update_rule_dict['timeObjName'] = timer_obj['name']
            s_addr_objs, d_addr_objs = self._create_addr(context, after_fwr)
            s_addr_names =\
                ",".join([addr_name['name'] for addr_name in s_addr_objs])
            d_addr_names =\
                ",".join([addr_name['name'] for addr_name in d_addr_objs])
            rpc_update_rule_dict['srcIpObjNames'], \
                rpc_update_rule_dict['dstIpObjNames'] = \
                s_addr_names, d_addr_names
            service_obj = self._create_netservice(context, after_fwr)
            rpc_update_rule_dict['serviceNames'] = service_obj['name']
            insert_ret = self.agent_rpc.update_rule(
                context, rpc_update_rule_dict)
            if insert_ret['status'] == const.ERROR:
                raise fw_ext.FirewallRuleUpdateFaild(name=after_fwr['name'])
        except Exception as e:
            super(FirewallPlugin, self).update_firewall_rule(context, id, {
                "firewall_rule": origin_fwr})
            raise
        # release rule and packetfilter associations
        old_fwhp = self._get_hardware_firewall_packetfilter_by_ruleid(
            context, rule_id=id)
        self.remove_packetfilter_and_asso_on_db(
            context, packetfilter={'id': old_fwhp['id']})

        new_fwhp = self._create_hardware_firewall_packetfilter(
            context, after_fwr, rpc_update_rule_dict, timer_obj)
        self.create_hardware_firewall_packetfilter_associate(
            context,
            fwr=after_fwr,
            packetfilter_obj=new_fwhp,
            s_addr_objs=s_addr_objs,
            d_addr_objs=d_addr_objs,
            service_obj=service_obj,
            szone_obj=s_area,
            dzone_obj=d_area
        )
        return after_fwr
        # pass

    def _get_hardware_firewall_packetfilter_by_ruleid(
            self, context, rule_id=None):
        filters = {}
        filters['rule_id'] = [rule_id]
        asso_obj = super(FirewallPlugin, self).\
            get_hardware_firewall_rule_packetfilter_asso(
            context,
            filters=filters)
        packetfilter_id = asso_obj[0]["packetfilter_id"]
        return super(FirewallPlugin, self).\
            get_hardware_firewall_packetfilter(
            context, id=packetfilter_id
        )

    def _check_iplist_duplicate(self, iplist):
        if len(iplist) != len(set(iplist)):
            raise fw_ext.FirewallIpAddressDuplicate()

    def check_rule_iplist_duplicate(self, rule_info):
        self._check_iplist_duplicate(
            rule_info['firewall_rule']['source_ip_address'].split(";")
        )
        self._check_iplist_duplicate(
            rule_info['firewall_rule']['destination_ip_address'].split(";")
        )

    def check_create_rule_ip_legal(self, firewall_rule):
        if not firewall_rule['firewall_rule']['destination_port']:
            raise fw_ext.FirewallDstPortNotEmpty()
        if firewall_rule['firewall_rule']['source_ip_address'] is None:
            raise fw_ext.HardwareFirewallAddrNotNone()
        if firewall_rule['firewall_rule']['destination_ip_address']\
                is None:
            raise fw_ext.HardwareFirewallAddrNotNone()
        self.check_rule_iplist_duplicate(firewall_rule)
        if len(firewall_rule['firewall_rule']
               ['source_ip_address'].split(";")) > 10:
            raise fw_ext.HardwareFirewallAddrExceed()
        else:
            source_ips \
                = firewall_rule['firewall_rule']['source_ip_address']
            for ipaddr in source_ips.split(";"):
                try:
                    IPNetwork(ipaddr)
                except:
                    raise fw_ext.HardwareFirewallAddrIllegal(ipaddr=ipaddr)
        if len(firewall_rule['firewall_rule']
               ['destination_ip_address'].split(";")) > 10:
            raise fw_ext.HardwareFirewallAddrExceed()
        else:
            dst_ips\
                = firewall_rule['firewall_rule']['destination_ip_address']
            for ipaddr in dst_ips.split(";"):
                try:
                    IPNetwork(ipaddr)
                except:
                    raise fw_ext.HardwareFirewallAddrIllegal(ipaddr=ipaddr)

    def check_update_rule_ip_legal(self, firewall_rule):
        if firewall_rule['firewall_rule'].get('source_ip_address'):
            if len(firewall_rule['firewall_rule']['source_ip_address'].split(";")) > 10:
                raise fw_ext.HardwareFirewallAddrExceed()
            else:
                source_ips \
                    = firewall_rule['firewall_rule']['source_ip_address']
                for ipaddr in source_ips.split(";"):
                    try:
                        IPNetwork(ipaddr)
                    except:
                        raise fw_ext.HardwareFirewallAddrIllegal(ipaddr=ipaddr)
            self._check_iplist_duplicate(firewall_rule['firewall_rule']['source_ip_address'].split(";"))

        if firewall_rule['firewall_rule'].get('destination_ip_address') :
            if len(firewall_rule['firewall_rule']['destination_ip_address'].split(";")) > 10:
                raise fw_ext.HardwareFirewallAddrExceed()
            else:
                dst_ips\
                    = firewall_rule['firewall_rule']['destination_ip_address']
                for ipaddr in dst_ips.split(";"):
                    try:
                        IPNetwork(ipaddr)
                    except:
                        raise fw_ext.HardwareFirewallAddrIllegal(ipaddr=ipaddr)
            self._check_iplist_duplicate(
                firewall_rule['firewall_rule']['destination_ip_address'].split(";"))