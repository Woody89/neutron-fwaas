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

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import constants
from neutron.db import common_db_mixin as base_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import l3
from neutron import manager
from neutron.plugins.common import constants as p_const
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy.ext.orderinglist import ordering_list
from sqlalchemy import orm
from sqlalchemy.orm import exc
from datetime import datetime, timedelta
from neutron.db import agents_db
import netaddr
import time

from neutron_fwaas.extensions import firewall as fw_ext


LOG = logging.getLogger(__name__)


class FirewallRule(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Firewall rule."""
    __tablename__ = 'firewall_rules'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    firewall_policy_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('firewall_policies.id'),
                                   nullable=True)
    shared = sa.Column(sa.Boolean)
    protocol = sa.Column(sa.String(40))
    ip_version = sa.Column(sa.Integer, nullable=False)
    source_ip_address = sa.Column(sa.String(46))
    destination_ip_address = sa.Column(sa.String(46))
    source_port_range_min = sa.Column(sa.Integer)
    source_port_range_max = sa.Column(sa.Integer)
    destination_port_range_min = sa.Column(sa.Integer)
    destination_port_range_max = sa.Column(sa.Integer)
    src_router_id = sa.Column(sa.String(36))
    dst_router_id = sa.Column(sa.String(36))
    session_type = sa.Column(sa.Integer)
    start_time = sa.Column(sa.String)
    end_time = sa.Column(sa.String)
    action = sa.Column(sa.Enum('allow', 'deny', 'reject',
                               name='firewallrules_action'))
    enabled = sa.Column(sa.Boolean)
    position = sa.Column(sa.Integer)


class Firewall(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Firewall resource."""
    __tablename__ = 'firewalls'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    shared = sa.Column(sa.Boolean)
    admin_state_up = sa.Column(sa.Boolean)
    status = sa.Column(sa.String(16))
    firewall_policy_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('firewall_policies.id'),
                                   nullable=True)


class SecurityArea(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Security Area resource."""
    __tablename__ = 'firewall_security_area'
    name = sa.Column(sa.String(255))
    priority = sa.Column(sa.String(10))
    firewall_id = sa.Column(sa.String(36),
                            sa.ForeignKey('firewalls.id'),
                            nullable=True)
    tenant_id = sa.Column(sa.String(35))
    security_area_type = sa.Column(sa.String(10))
    router_id = sa.Column(sa.String(32))
    cidr = sa.Column(sa.String(255))
    ifnames = sa.Column(sa.String(1024))


class HardwareFirewallSecurityZone(
        model_base.BASEV2,
        models_v2.HasId,
        models_v2.HasTenant):
    """Represents a Hardware Firewall SecurityZone resource."""
    __tablename__ = 'dptech_firewall_security_zone_t'
    name = sa.Column(sa.String(255))
    ifnames = sa.Column(sa.String(1024))
    priority = sa.Column(sa.String(10))
    tenant_id = sa.Column(sa.String(35))
    security_area_type = sa.Column(sa.String(10))
    router_id = sa.Column(sa.String(32))
    cidr = sa.Column(sa.String(255))


class FirewallAreaZoneAssociations(model_base.BASEV2, models_v2.HasId):
    """Represents a Firewall Area Zone Associatios resource"""
    __tablename__ = 'firewall_area_zone_associations'
    security_area_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('firewall_security_area.id'),
                                 nullable=False)
    security_zone_id = sa.Column(sa.String(36), sa.ForeignKey(
        'dptech_firewall_security_zone_t.id'), nullable=False)


class HardwareFirewallPacketfilterZoneAssociations(
        model_base.BASEV2, models_v2.HasId):
    """Represents a Hardware Firewall Security Zone Associations resource"""
    __tablename__ = 'dptech_firewall_security_zone_associations_t'
    sz_id = sa.Column(sa.String(36),
                      sa.ForeignKey('dptech_firewall_security_zone_t.id'),
                      nullable=True)
    packetfilter_id = sa.Column(sa.String(36), sa.ForeignKey(
        'dptech_firewall_packetfilter_info_t.id'), nullable=True)


class HardwareFirewallVsys(model_base.BASEV2, models_v2.HasId):
    """Represents a Hardware Firewall Vsys resource."""
    __tablename__ = 'dptech_firewall_vsys_t'
    name = sa.Column(sa.String(255))
    type = sa.Column(sa.Integer)


class FirewallVsysAssociations(model_base.BASEV2, models_v2.HasId):
    """Represents a Firewall Vsys Associations resource"""
    __tablename__ = 'firewalls_vsys_associations'
    firewall_id = sa.Column(sa.String(36),
                            sa.ForeignKey('firewalls.id'))
    vsys_id = sa.Column(sa.String(36),
                        sa.ForeignKey('dptech_firewall_vsys_t.id'))


class HardwareFirewallVrf(model_base.BASEV2, models_v2.HasId):
    """Represents a Hardware Firewall Vrf resource"""
    __tablename__ = 'dptech_firewall_vrf_t'
    name = sa.Column(sa.String(36))
    vsys_id = sa.Column(sa.String(36))
    ifnames = sa.Column(sa.String(255))


class FirewallPolicy(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Firewall Policy resource."""
    __tablename__ = 'firewall_policies'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    shared = sa.Column(sa.Boolean)
    firewall_rules = orm.relationship(
        FirewallRule,
        backref=orm.backref('firewall_policies', cascade='all, delete'),
        order_by='FirewallRule.position',
        collection_class=ordering_list('position', count_from=1))
    audited = sa.Column(sa.Boolean)
    firewalls = orm.relationship(Firewall, backref='firewall_policies')


class HardwareFirewallAddrobj(model_base.BASEV2, models_v2.HasId):
    """Represents a Firewall ip addrobj resource."""
    __tablename__ = 'dptech_firewall_addrobj_t'
    name = sa.Column(sa.String(255))
    ip = sa.Column(sa.String(36))
    expip = sa.Column(sa.String(36))
    vsys_id = sa.Column(sa.String(36))


class HardwareFirewallServiceobj(model_base.BASEV2, models_v2.HasId):
    """Represents a dptech_firewall_service_info_t resource."""
    __tablename__ = 'dptech_firewall_service_info_t'
    name = sa.Column(sa.String(255))
    proto = sa.Column(sa.String(255))
    port = sa.Column(sa.String(255))
    vsys_id = sa.Column(sa.String(36))


class HardwareFirewallTimeobj(model_base.BASEV2, models_v2.HasId):
    """Represents a dptech_firewall_timeobject_t resource."""
    __tablename__ = 'dptech_firewall_timeobject_t'
    name = sa.Column(sa.String(255))
    mode = sa.Column(sa.String(3))
    week = sa.Column(sa.String(15))
    startDay = sa.Column(sa.String(100))
    endDay = sa.Column(sa.String(100))
    startTime = sa.Column(sa.String(100))
    endTime = sa.Column(sa.String(100))
    vsys_id = sa.Column(sa.String(36))


class HardwareFirewallVlan(
        model_base.BASEV2,
        models_v2.HasId,
        models_v2.HasTenant):
    """Represents a dptech_firewall_vlan_t resource."""
    __tablename__ = 'dptech_firewall_vlan_t'
    vlan_id = sa.Column(sa.String(36))
    vlan_name = sa.Column(sa.String(36))
    ipaddr = sa.Column(sa.String(36))
    tenant_id = sa.Column(sa.String(255))
    ifnames = sa.Column(sa.String(64))
    sz_id = sa.Column(sa.String(36),
                      sa.ForeignKey('firewall_security_area.id'),
                      nullable=True
                      )
    vrf_id = sa.Column(sa.String(36),
                       sa.ForeignKey('dptech_firewall_vrf_t.id'),
                       nullable=True
                       )


class HardwareFirewallPacketfilter(model_base.BASEV2, models_v2.HasId):
    """Represents a Firewall rule."""
    __tablename__ = 'dptech_firewall_packetfilter_info_t'
    name = sa.Column(sa.String(255))
    action = sa.Column(sa.Integer)
    log = sa.Column(sa.Integer)
    session_type = sa.Column(sa.Integer)
    vsys_id = sa.Column(sa.String(36))
    timeobj_id = sa.Column(sa.String(36))


class HardwareFirewallPacketfilterSaddrAssociate(
        model_base.BASEV2, models_v2.HasId):
    """Represents a Firewall rule."""
    __tablename__ = 'dptech_firewall_packtfilter_saddrobj_associations_t'
    addrobj_id = sa.Column(sa.String(36))
    packetfilter_id = sa.Column(sa.String(36))


class HardwareFirewallPacketfilterDaddrAssociate(
        model_base.BASEV2, models_v2.HasId):
    """Represents a Firewall rule."""
    __tablename__ = 'dptech_firewall_packtfilter_daddrobj_associations_t'
    addrobj_id = sa.Column(sa.String(36))
    packetfilter_id = sa.Column(sa.String(36))


class HardwareFirewallPacketfilterServiceAssociate(
        model_base.BASEV2, models_v2.HasId):
    """Represents a Firewall rule."""
    __tablename__ = 'dptech_firewall_packtfilter_service_associations_t'
    service_id = sa.Column(sa.String(36))
    packetfilter_id = sa.Column(sa.String(36))


class FirewallRulesPacketfilterAssociations(
        model_base.BASEV2, models_v2.HasId):
    """Represents a firewall_rules_packtfilter_associations resource."""
    __tablename__ = 'firewall_rules_packetfilter_associations'
    rule_id = sa.Column(sa.String(36))
    packetfilter_id = sa.Column(sa.String(36))


class Firewall_db_mixin(fw_ext.FirewallPluginBase, base_db.CommonDbMixin,
                        agents_db.AgentDbMixin):
    """Mixin class for Firewall DB implementation."""

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _get_firewall(self, context, id):
        try:
            return self._get_by_id(context, Firewall, id)
        except exc.NoResultFound:
            raise fw_ext.FirewallNotFound(firewall_id=id)

    def _get_vlan(self, context, id):
        try:
            return self._get_by_id(context, HardwareFirewallVlan, id)
        except exc.NoResultFound:
            raise fw_ext.HardwareFirewallVlanNotFound(vlan_id=id)

    def _get_vrf(self, context, id):
        try:
            return self._get_by_id(context, HardwareFirewallVrf, id)
        except exc.NoResultFound:
            raise fw_ext.HardwareFirewallVrfNotFound(vrf_id=id)

    def _get_firewall_policy(self, context, id):
        try:
            return self._get_by_id(context, FirewallPolicy, id)
        except exc.NoResultFound:
            raise fw_ext.FirewallPolicyNotFound(firewall_policy_id=id)

    def _get_firewall_rule(self, context, id):
        try:
            return self._get_by_id(context, FirewallRule, id)
        except exc.NoResultFound:
            raise fw_ext.FirewallRuleNotFound(firewall_rule_id=id)

    def _get_hardware_firewall_addrobj(self, context, id):
        try:
            return self._get_by_id(context, HardwareFirewallAddrobj, id)
        except exc.NoResultFound:
            raise fw_ext.HardwareFirewallAddrobjNotFound(addr_obj=id)

    def _get_hardware_firewall_serverobj(self, context, id):
        try:
            return self._get_by_id(context, HardwareFirewallServiceobj, id)
        except exc.NoResultFound:
            raise fw_ext.HardwareFirewallServerobjNotFound(server_obj=id)

    def _get_hardware_firewall_timeobj(self, context, id):
        try:
            return self._get_by_id(context, HardwareFirewallTimeobj, id)
        except exc.NoResultFound:
            raise fw_ext.HardwareFirewallTimeobjNotFound(time_id=id)

    def _get_security_area(self, context, id):
        try:
            return self._get_by_id(context, SecurityArea, id)
        except exc.NoResultFound:
            raise fw_ext.HardwareFirewallSecurityareaNotFound(
                security_area_id=id)

    def _get_security_area_by_router_id(self, context, id):
        try:
            return self._get_by_router_id(context, SecurityArea, id)
        except exc.NoResultFound:
            raise fw_ext.HardwareFirewallSecurityareaNotFoundByRouter(
                security_area_router_id=id)

    def _get_by_router_id(self, context, model, id):
        query = self._model_query(context, model)
        return query.filter(model.router_id == id).one()

    def _get_hardware_firewall_vsys(self, context, id):
        try:
            return self._get_by_id(context, HardwareFirewallVsys, id)
        except:
            raise

    def _get_hardware_firewall_vrf(self, context, id):
        try:
            return self._get_by_id(context, HardwareFirewallVrf, id)
        except exc.NoResultFound:
            raise

    def _get_hardware_firewall_security_zone(self, context, id):
        try:
            return self._get_by_id(context, HardwareFirewallSecurityZone, id)
        except exc.NoResultFound:
            raise

    def _get_hardware_firewall_vlan(self, context, id):
        try:
            return self._get_by_id(context, HardwareFirewallVlan, id)
        except exc.NoResultFound:
            raise

    def _get_firewall_area_zone_association(self, context, id):
        try:
            return self._get_by_id(context, FirewallAreaZoneAssociations,
                                   id)
        except exc.NoResultFound:
            raise

    def _get_firewall_rule_packetfilter_association(self, context, id):
        try:
            return self._get_by_id(context, FirewallAreaZoneAssociations,
                                   id)
        except exc.NoResultFound:
            raise

    def _get_hardware_firewall_packetfilter(self, context, id):
        try:
            return self._get_by_id(context, HardwareFirewallPacketfilter,
                                   id)
        except exc.NoResultFound:
            raise fw_ext.FirewallPacketfilterNotFound(
                fw_packetfilter_id=id)

    def _make_firewall_dict(self, fw, fields=None):
        res = {'id': fw['id'],
               'tenant_id': fw['tenant_id'],
               'name': fw['name'],
               'description': fw['description'],
               'shared': fw['shared'],
               'admin_state_up': fw['admin_state_up'],
               'status': fw['status'],
               'firewall_policy_id': fw['firewall_policy_id']}
        return self._fields(res, fields)

    def _make_area_zone_dict(self, fw, fields=None):
        res = {'id': fw['id'],
               "security_area_id": fw["security_area_id"],
               "security_zone_id": fw["security_zone_id"]
               }
        return self._fields(res, fields)

    def _make_firewall_vsys_dict(self, fw, fields=None):
        res = {'id': fw['id'],
               'firewall_id': fw['firewall_id'],
               'vsys_id': fw['vsys_id']
               }
        return self._fields(res, fields)

    def _make_firewall_policy_dict(self, firewall_policy, fields=None):
        fw_rules = [rule['id'] for rule in firewall_policy['firewall_rules']]
        firewalls = [fw['id'] for fw in firewall_policy['firewalls']]
        res = {'id': firewall_policy['id'],
               'tenant_id': firewall_policy['tenant_id'],
               'name': firewall_policy['name'],
               'description': firewall_policy['description'],
               'shared': firewall_policy['shared'],
               'audited': firewall_policy['audited'],
               'firewall_rules': fw_rules,
               'firewall_list': firewalls}
        return self._fields(res, fields)

    def _make_firewall_rule_dict(self, firewall_rule, fields=None):
        position = None
        # We return the position only if the firewall_rule is bound to a
        # firewall_policy.
        if firewall_rule['firewall_policy_id']:
            position = firewall_rule['position']
        src_port_range = self._get_port_range_from_min_max_ports(
            firewall_rule['source_port_range_min'],
            firewall_rule['source_port_range_max'])
        dst_port_range = self._get_port_range_from_min_max_ports(
            firewall_rule['destination_port_range_min'],
            firewall_rule['destination_port_range_max'])
        res = {'id': firewall_rule['id'],
               'tenant_id': firewall_rule['tenant_id'],
               'name': firewall_rule['name'],
               'description': firewall_rule['description'],
               'firewall_policy_id': firewall_rule['firewall_policy_id'],
               'shared': firewall_rule['shared'],
               'protocol': firewall_rule['protocol'],
               'ip_version': firewall_rule['ip_version'],
               'source_ip_address': firewall_rule['source_ip_address'],
               'destination_ip_address':
               firewall_rule['destination_ip_address'],
               'source_port': src_port_range,
               'destination_port': dst_port_range,
               'src_router_id': firewall_rule['src_router_id'],
               'dst_router_id': firewall_rule['dst_router_id'],
               'action': firewall_rule['action'],
               'start_time': firewall_rule['start_time'],
               'end_time': firewall_rule['end_time'],
               'session_type': firewall_rule['session_type'],
               'position': position,
               'enabled': firewall_rule['enabled']}
        return self._fields(res, fields)

    def _make_hardware_packetfilter_dict(self, packetfilter, fields=None):
        res = {'id': packetfilter['id'],
               'name': packetfilter['name'],
               'action': packetfilter['action'],
               'log': packetfilter['log'],
               'session_type': packetfilter['session_type'],
               'vsys_id': packetfilter['vsys_id'],
               'timeobj_id': packetfilter['timeobj_id'],
               }
        return self._fields(res, fields)

    def _make_rule_packetfilter_dict(self, rule_packetfilter, fields=None):
        res = {'id': rule_packetfilter['id'],
               'rule_id': rule_packetfilter['rule_id'],
               'packetfilter_id': rule_packetfilter['packetfilter_id']
               }
        return self._fields(res, fields)

    def _make_security_area_dict(self, security_area, fields=None):
        res = {'id': security_area['id'],
               'tenant_id': security_area['tenant_id'],
               'name': security_area['name'],
               'priority': security_area['priority'],
               'firewall_id': security_area['firewall_id'],
               'security_area_type': security_area['security_area_type'],
               'router_id': security_area['router_id'],
               'cidr': security_area['cidr'],
               'ifnames': security_area['ifnames']}
        return self._fields(res, fields)

    def _make_hardware_firewall_security_zone(
            self, hardware_firewall_security_zone, fields=None):
        res = {
            'id': hardware_firewall_security_zone['id'],
            'tenant_id': hardware_firewall_security_zone['tenant_id'],
            'name': hardware_firewall_security_zone['name'],
            'priority': hardware_firewall_security_zone['priority'],
            'security_area_type':
                hardware_firewall_security_zone['security_area_type'],
            'router_id': hardware_firewall_security_zone['router_id'],
            'cidr': hardware_firewall_security_zone['cidr'],
            'ifnames': hardware_firewall_security_zone['ifnames']}
        return self._fields(res, fields)

    def _make_firewall_area_zone_associations(
            self, firewall_area_zone_associations, fields=None):
        res = {
            'id': firewall_area_zone_associations['id'],
            'security_area_id':
                firewall_area_zone_associations['security_area_id'],
            'security_zone_id':
                firewall_area_zone_associations['security_zone_id']}
        return self._fields(res, fields)

    def _make_hardware_firewall_security_zone_associations(
            self, hardware_firewall_security_zone_associations, fields=None):
        res = {
            'id': hardware_firewall_security_zone_associations['id'],
            'sz_id': hardware_firewall_security_zone_associations['sz_id'],
            'packetfilter_id':
            hardware_firewall_security_zone_associations['packetfilter_id'],
        }
        return self._fields(res, fields)

    def _make_vlan_dict(self, vlan, fields=None):
        res = {'id': vlan['id'],
               'vlanId': vlan['vlan_id'],
               'vlan_name': vlan['vlan_name'],
               'ipAddr': vlan['ipaddr'],
               'ifNames': vlan['ifnames'],
               'sz_id': vlan['sz_id'],
               'tenant_id': vlan['tenant_id'],
               'vrf_id': vlan['vrf_id'],
               }
        return self._fields(res, fields)

    def _make_hardware_firewall_addrobj(self, ip_obj, fields=None):
        res = {'id': ip_obj['id'],
               'name': ip_obj['name'],
               'ip': ip_obj['ip'],
               'expip': ip_obj['expip'],
               'vsys_id': ip_obj['vsys_id'],
               }
        return self._fields(res, fields)

    def _make_hardware_firewall_serviceobj(self, serviceobj, fields=None):
        res = {'id': serviceobj['id'],
               'name': serviceobj['name'],
               'proto': serviceobj['proto'],
               'port': serviceobj['port'],
               'vsys_id': serviceobj['vsys_id'],
               }
        return self._fields(res, fields)

    def _make_hardware_firewall_timeobj(self, timeobj, fields=None):
        res = {'id': timeobj['id'],
               'name': timeobj['name'],
               'mode': timeobj['mode'],
               'week': timeobj['week'],
               'startDay': timeobj['startDay'],
               'endDay': timeobj['endDay'],
               'startTime': timeobj['startTime'],
               'endTime': timeobj['endTime'],
               'vsys_id': timeobj['vsys_id'],
               }
        return self._fields(res, fields)

    def _make_hardware_firewall_vlan(self, vlan, fields=None):
        res = {'id': vlan['id'],
               'vlan_id': vlan['vlan_id'],
               'vlan_name': vlan['vlan_name'],
               'ipaddr': vlan['ipaddr'],
               'ifnames': vlan['ifnames'],
               'sz_id': vlan['sz_id'],
               'tenant_id': vlan['tenant_id'],
               }
        return self._fields(res, fields)

    def _make_hardware_firewall_packetfilter(self, packetfilter, fields=None):
        res = {'id': packetfilter['id'],
               'name': packetfilter['name'],
               'action': packetfilter['action'],
               'log': packetfilter['log'],
               'session_type': packetfilter['session_type'],
               'vsys_id': packetfilter['vsys_id'],
               'timeobj_id': packetfilter['timeobj_id']}
        return self._fields(res, fields)

    def _make_hardware_firewall_rule_packetfilter_associations(
            self, rule, fields=None):
        res = {'id': rule['id'],
               'rule_id': rule['rule_id'],
               'packetfilter_id': rule['packetfilter_id']
               }
        return self._fields(res, fields)

    def _make_hardware_packetfilter_addr_dict(self, rule, fields=None):
        res = {"id": rule['id'],
               "addrobj_id": rule['addrobj_id'],
               "packetfilter_id": rule['packetfilter_id']
               }
        return self._fields(res, fields)

    def _make_hardware_packetfilter_rule_dict(self, rule, fields=None):
        res = {"id": rule['id'],
               "rule_id": rule['rule_id'],
               "packetfilter_id": rule['packetfilter_id']
               }
        return self._fields(res, fields)

    def _make_hardware_packetfilter_service_dict(self, rule, fields=None):
        res = {"id": rule['id'],
               "service_id": rule['service_id'],
               "packetfilter_id": rule['packetfilter_id']
               }
        return self._fields(res, fields)

    def _make_hardware_packetfilter_zone_dict(self, rule, fields=None):
        res = {"id": rule['id'],
               "sz_id": rule['sz_id'],
               "packetfilter_id": rule['packetfilter_id']
               }
        return self._fields(res, fields)

    def _make_hardware_packetfilter_timer_dict(self, rule, fields=None):
        res = {"id": rule['id'],
               "service_id": rule['service_id'],
               "packetfilter_id": rule['packetfilter_id']
               }
        return self._fields(res, fields)

    def _make_hardware_firewall_vrf(self, vrf, fields=None):
        res = {'id': vrf['id'],
               'ifName': vrf['ifnames'],
               'name': vrf['name'],
               'vsys_id': vrf['vsys_id']
               }
        return self._fields(res, fields)

    def _make_hardware_firewall_vrf_obj(self, vrf, fields=None):
        res = {'id': vrf['id'],
               'ifnames': vrf['ifnames'],
               'name': vrf['name'],
               'vsys_id': vrf['vsys_id']
               }
        return self._fields(res, fields)

    def _make_hardware_firewall_vsys(self, vsys, fields=None):
        res = {'id': vsys['id'],
               'name': vsys['name'],
               'type': vsys['type']
               }
        return self._fields(res, fields)

    def _make_fw_vsys_dict(self, fw_vsys, fields=None):
        res = {'id': fw_vsys['id'],
               'firewall_id': fw_vsys['firewall_id'],
               'vsys_id': fw_vsys['vsys_id']
               }
        return self._fields(res, fields)

    def _make_firewalls_vsys_associations(self, firewalls_vsys, fields=None):
        res = {'id': firewalls_vsys['id'],
               'firewall_id': firewalls_vsys['firewall_id'],
               'vsys_id': firewalls_vsys['vsys_id']
               }
        return self._fields(res, fields)

    def _make_hardware_firewall_sz(self, zone, fields=None):
        res = {'id': zone['id'],
               'name': zone['name'],
               'ifNames': zone['ifNames'],
               'vfwName': None
               }
        return self._fields(res, fields)

    def _make_firewall_dict_with_rules(self, context, firewall_id):
        firewall = self.get_firewall(context, firewall_id)
        fw_policy_id = firewall['firewall_policy_id']
        if fw_policy_id:
            fw_policy = self.get_firewall_policy(context, fw_policy_id)
            fw_rules_list = [self.get_firewall_rule(
                context, rule_id) for rule_id in fw_policy['firewall_rules']]
            firewall['firewall_rule_list'] = fw_rules_list
        else:
            firewall['firewall_rule_list'] = []
        # FIXME(Sumit): If the size of the firewall object we are creating
        # here exceeds the largest message size supported by rabbit/qpid
        # then we will have a problem.
        return firewall

    def _check_firewall_rule_conflict(self, fwr_db, fwp_db):
        if not fwr_db['shared']:
            if fwr_db['tenant_id'] != fwp_db['tenant_id']:
                raise fw_ext.FirewallRuleConflict(
                    firewall_rule_id=fwr_db['id'],
                    tenant_id=fwr_db['tenant_id'])

    def _set_rules_for_policy(self, context, firewall_policy_db, fwp):
        rule_id_list = fwp['firewall_rules']
        fwp_db = firewall_policy_db
        with context.session.begin(subtransactions=True):
            if not rule_id_list:
                fwp_db.firewall_rules = []
                fwp_db.audited = False
                return
            # We will first check if the new list of rules is valid
            filters = {'id': [r_id for r_id in rule_id_list]}
            rules_in_db = self._get_collection_query(context, FirewallRule,
                                                     filters=filters)
            rules_dict = dict((fwr_db['id'], fwr_db) for fwr_db in rules_in_db)
            for fwrule_id in rule_id_list:
                if fwrule_id not in rules_dict:
                    # If we find an invalid rule in the list we
                    # do not perform the update since this breaks
                    # the integrity of this list.
                    raise fw_ext.FirewallRuleNotFound(
                        firewall_rule_id=fwrule_id)
                elif rules_dict[fwrule_id]['firewall_policy_id']:
                    if (rules_dict[fwrule_id]['firewall_policy_id'] !=
                            fwp_db['id']):
                        raise fw_ext.FirewallRuleInUse(
                            firewall_rule_id=fwrule_id)
                if 'shared' in fwp:
                    if fwp['shared'] and not rules_dict[fwrule_id]['shared']:
                        raise fw_ext.FirewallRuleSharingConflict(
                            firewall_rule_id=fwrule_id,
                            firewall_policy_id=fwp_db['id'])
                elif fwp_db['shared'] and not rules_dict[fwrule_id]['shared']:
                    raise fw_ext.FirewallRuleSharingConflict(
                        firewall_rule_id=fwrule_id,
                        firewall_policy_id=fwp_db['id'])
            for fwr_db in rules_in_db:
                self._check_firewall_rule_conflict(fwr_db, fwp_db)
            # New list of rules is valid so we will first reset the existing
            # list and then add each rule in order.
            # Note that the list could be empty in which case we interpret
            # it as clearing existing rules.
            fwp_db.firewall_rules = []
            for fwrule_id in rule_id_list:
                fwp_db.firewall_rules.append(rules_dict[fwrule_id])
            fwp_db.firewall_rules.reorder()
            fwp_db.audited = False

    def _check_unshared_rules_for_policy(self, fwp_db, fwp):
        if fwp['shared']:
            rules_in_db = fwp_db['firewall_rules']
            for fwr_db in rules_in_db:
                if not fwr_db['shared']:
                    raise fw_ext.FirewallPolicySharingConflict(
                        firewall_rule_id=fwr_db['id'],
                        firewall_policy_id=fwp_db['id'])

    def _process_rule_for_policy(self, context, firewall_policy_id,
                                 firewall_rule_db, position):
        with context.session.begin(subtransactions=True):
            fwp_query = context.session.query(
                FirewallPolicy).with_lockmode('update')
            fwp_db = fwp_query.filter_by(id=firewall_policy_id).one()
            if position:
                # Note that although position numbering starts at 1,
                # internal ordering of the list starts at 0, so we compensate.
                fwp_db.firewall_rules.insert(position - 1, firewall_rule_db)
            else:
                fwp_db.firewall_rules.remove(firewall_rule_db)
            fwp_db.firewall_rules.reorder()
            fwp_db.audited = False
        return self._make_firewall_policy_dict(fwp_db)

    def _get_min_max_ports_from_range(self, port_range):
        if not port_range:
            return [None, None]
        min_port, sep, max_port = port_range.partition(":")
        if not max_port:
            max_port = min_port
        self._validate_fwr_port_range(min_port, max_port)
        return [int(min_port), int(max_port)]

    def _get_port_range_from_min_max_ports(self, min_port, max_port):
        if not min_port:
            return None
        if min_port == max_port:
            return str(min_port)
        self._validate_fwr_port_range(min_port, max_port)
        return '%s:%s' % (min_port, max_port)

    def _validate_fw_parameters(self, context, fw, fw_tenant_id):
        if 'firewall_policy_id' not in fw:
            return
        fwp_id = fw['firewall_policy_id']
        fwp = self._get_firewall_policy(context, fwp_id)
        if fw_tenant_id != fwp['tenant_id'] and not fwp['shared']:
            raise fw_ext.FirewallPolicyConflict(firewall_policy_id=fwp_id)

    def _validate_fwr_src_dst_ip_version(self, fwr):
        src_version = dst_version = None
        if fwr['source_ip_address']:
            src_version = netaddr.IPNetwork(fwr['source_ip_address']).version
        if fwr['destination_ip_address']:
            dst_version = netaddr.IPNetwork(
                fwr['destination_ip_address']).version
        rule_ip_version = fwr['ip_version']
        if ((src_version and src_version != rule_ip_version) or
                (dst_version and dst_version != rule_ip_version)):
            raise fw_ext.FirewallIpAddressConflict()

    def _validate_fwr_port_range(self, min_port, max_port):
        if int(min_port) > int(max_port):
            port_range = '%s:%s' % (min_port, max_port)
            raise fw_ext.FirewallRuleInvalidPortValue(port=port_range)

    def _validate_fwr_protocol_parameters(self, fwr):
        protocol = fwr['protocol']
        if protocol not in (constants.PROTO_NAME_TCP,
                            constants.PROTO_NAME_UDP):
            if fwr['source_port'] or fwr['destination_port']:
                raise fw_ext.FirewallRuleInvalidICMPParameter(
                    param="Source, destination port")

    def _validate_fwr_datetime(self, date_time):
        try:
            time.strptime(date_time, '%Y-%m-%d %H:%M')
        except:
            raise fw_ext.HardwareFirewallDataTimeFormatError(param="dateTime")

    def create_firewall(self, context, firewall, status=None):
        LOG.debug("create_firewall() called")
        fw = firewall['firewall']
        tenant_id = self._get_tenant_id_for_create(context, fw)
        # distributed routers may required a more complex state machine;
        # the introduction of a new 'CREATED' state allows this, whilst
        # keeping a backward compatible behavior of the logical resource.
        if not status:
            status = (p_const.CREATED if cfg.CONF.router_distributed
                      else p_const.PENDING_CREATE)
        with context.session.begin(subtransactions=True):
            self._validate_fw_parameters(context, fw, tenant_id)
            firewall_db = Firewall(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=fw['name'],
                description=fw['description'],
                firewall_policy_id=fw['firewall_policy_id'],
                admin_state_up=fw['admin_state_up'],
                status=status)
            context.session.add(firewall_db)
        return self._make_firewall_dict(firewall_db)

    def update_firewall(self, context, id, firewall):
        LOG.debug("update_firewall() called")
        fw = firewall['firewall']
        with context.session.begin(subtransactions=True):
            fw_db = self.get_firewall(context, id)
            self._validate_fw_parameters(context, fw, fw_db['tenant_id'])
            count = context.session.query(Firewall).filter_by(id=id).update(fw)
            if not count:
                raise fw_ext.FirewallNotFound(firewall_id=id)
        return self.get_firewall(context, id)

    def update_firewall_obj(self, context, id, firewall):
        LOG.debug("update_firewall() called")
        fw = firewall
        with context.session.begin(subtransactions=True):
            fw_db = self.get_firewall(context, id)
            self._validate_fw_parameters(context, fw, fw_db['tenant_id'])
            count = context.session.query(Firewall).filter_by(id=id).update(fw)
            if not count:
                raise fw_ext.FirewallNotFound(firewall_id=id)
        return self.get_firewall(context, id)

    def update_vlan(self, context, id, vlan):
        LOG.debug("update_vlan() called")
        with context.session.begin(subtransactions=True):
            count = context.session.query(HardwareFirewallVlan).\
                filter_by(id=id).update(vlan)
            if not count:
                raise fw_ext.HardwareFirewallVlanNotFound(vlan_id=id)
        return self.get_vlan(context, id)

    def update_vrf(self, context, id, vrf):
        LOG.debug("update_vrf() called")
        with context.session.begin(subtransactions=True):
            count = context.session.query(HardwareFirewallVrf).\
                filter_by(id=id).update(vrf)
            if not count:
                raise fw_ext.HardwareFirewallVrfNotFound(vrf_id=id)
        return self.get_vrf(context, id)

    def update_firewall_status(self, context, id, status, not_in=None):
        """Conditionally update firewall status.

        Status transition is performed only if firewall is not in the specified
        states as defined by 'not_in' list.
        """
        # filter in_ wants iterable objects, None isn't.
        not_in = not_in or []
        with context.session.begin(subtransactions=True):
            return (context.session.query(Firewall).
                    filter(Firewall.id == id).
                    filter(~Firewall.status.in_(not_in)).
                    update({'status': status}, synchronize_session=False))

    def delete_firewall(self, context, id):
        LOG.debug("delete_firewall() called")
        with context.session.begin(subtransactions=True):
            # Note: Plugin should ensure that it's okay to delete if the
            # firewall is active
            count = context.session.query(Firewall).filter_by(id=id).delete()
            if not count:
                raise fw_ext.FirewallNotFound(firewall_id=id)

    def get_firewall(self, context, id, fields=None):
        LOG.debug("get_firewall() called")
        fw = self._get_firewall(context, id)
        return self._make_firewall_dict(fw, fields)

    def get_vlan(self, context, id, fields=None):
        LOG.debug("get_vlan() called")
        vlan = self._get_vlan(context, id)
        return self._make_vlan_dict(vlan, fields)

    def get_vrf(self, context, id, fields=None):
        LOG.debug("get_vrf() called")
        vrf = self._get_vrf(context, id)
        return self._make_hardware_firewall_vrf(vrf, fields)

    def get_vrfs(self, context, filters=None, fields=None):
        LOG.debug("get_vrfs() called")
        return self._get_collection(context, HardwareFirewallVrf,
                                    self._make_hardware_firewall_vrf,
                                    filters=filters, fields=fields)

    def get_vrfs_obj(self, context, filters=None, fields=None):
        LOG.debug("get_vrfs() called")
        return self._get_collection(context, HardwareFirewallVrf,
                                    self._make_hardware_firewall_vrf_obj,
                                    filters=filters, fields=fields)

    def get_firewalls(self, context, filters=None, fields=None):
        LOG.debug("get_firewalls() called")
        return self._get_collection(context, Firewall,
                                    self._make_firewall_dict,
                                    filters=filters, fields=fields)

    def get_firewalls_count(self, context, filters=None):
        LOG.debug("get_firewalls_count() called")
        return self._get_collection_count(context, Firewall,
                                          filters=filters)

    def create_firewall_policy(self, context, firewall_policy):
        LOG.debug("create_firewall_policy() called")
        fwp = firewall_policy['firewall_policy']
        tenant_id = self._get_tenant_id_for_create(context, fwp)
        with context.session.begin(subtransactions=True):
            fwp_db = FirewallPolicy(id=uuidutils.generate_uuid(),
                                    tenant_id=tenant_id,
                                    name=fwp['name'],
                                    description=fwp['description'],
                                    shared=fwp['shared'])
            context.session.add(fwp_db)
            self._set_rules_for_policy(context, fwp_db, fwp)
            fwp_db.audited = fwp['audited']
        return self._make_firewall_policy_dict(fwp_db)

    def update_firewall_policy(self, context, id, firewall_policy):
        LOG.debug("update_firewall_policy() called")
        fwp = firewall_policy['firewall_policy']
        with context.session.begin(subtransactions=True):
            fwp_db = self._get_firewall_policy(context, id)
            # check tenant ids are same for fw and fwp or not
            if not fwp.get('shared', True) and fwp_db.firewalls:
                for fw in fwp_db['firewalls']:
                    if fwp_db['tenant_id'] != fw['tenant_id']:
                        raise fw_ext.FirewallPolicyInUse(
                            firewall_policy_id=id)
            # check any existing rules are not shared
            if 'shared' in fwp and 'firewall_rules' not in fwp:
                self._check_unshared_rules_for_policy(fwp_db, fwp)
            elif 'firewall_rules' in fwp:
                self._set_rules_for_policy(context, fwp_db, fwp)
                del fwp['firewall_rules']
            if 'audited' not in fwp:
                fwp['audited'] = False
            fwp_db.update(fwp)
        return self._make_firewall_policy_dict(fwp_db)

    def delete_firewall_policy(self, context, id):
        LOG.debug("delete_firewall_policy() called")
        with context.session.begin(subtransactions=True):
            fwp = self._get_firewall_policy(context, id)
            # Ensure that the firewall_policy  is not
            # being used
            qry = context.session.query(Firewall)
            if qry.filter_by(firewall_policy_id=id).first():
                raise fw_ext.FirewallPolicyInUse(firewall_policy_id=id)
            else:
                context.session.delete(fwp)

    def get_firewall_policy(self, context, id, fields=None):
        LOG.debug("get_firewall_policy() called")
        fwp = self._get_firewall_policy(context, id)
        return self._make_firewall_policy_dict(fwp, fields)

    def get_firewall_policies(self, context, filters=None, fields=None):
        LOG.debug("get_firewall_policies() called")
        return self._get_collection(context, FirewallPolicy,
                                    self._make_firewall_policy_dict,
                                    filters=filters, fields=fields)

    def get_firewalls_policies_count(self, context, filters=None):
        LOG.debug("get_firewall_policies_count() called")
        return self._get_collection_count(context, FirewallPolicy,
                                          filters=filters)

    def create_firewall_rule(self, context, firewall_rule):
        LOG.debug("create_firewall_rule() called")
        fwr = firewall_rule['firewall_rule']
        if 'start_time' not in fwr.keys() or len(fwr['start_time']) == 0:
            start_time = datetime.now().strftime("%Y-%m-%d %H:%M")
            fwr['start_time'] = start_time
        else:
            self._validate_fwr_datetime(fwr['start_time'])
        if fwr['src_router_id'] == fwr['dst_router_id']:
            raise fw_ext.HardwareFirewallRouterIdDuplicate()
        if 'end_time' not in fwr.keys() or len(fwr['end_time']) == 0:
            end_time = (
                datetime.now() +
                timedelta(
                    days=+
                    3650)).strftime("%Y-%m-%d %H:%M")
            fwr['end_time'] = end_time
        else:
            self._validate_fwr_datetime(fwr['end_time'])
            if fwr['start_time'] >= fwr['end_time']:
                raise fw_ext.HardwareFirewallDataTimeError()
        self._validate_fwr_protocol_parameters(fwr)
        # self._validate_fwr_src_dst_ip_version(fwr)
        tenant_id = self._get_tenant_id_for_create(context, fwr)
        if not fwr['protocol'] and (fwr['source_port'] or
                                    fwr['destination_port']):
            raise fw_ext.FirewallRuleWithPortWithoutProtocolInvalid()
        if fwr['protocol'] != "icmp":
            src_port_min, src_port_max = self._get_min_max_ports_from_range(
                fwr['source_port'])
            dst_port_min, dst_port_max = self._get_min_max_ports_from_range(
                fwr['destination_port'])
        else:
            src_port_min, src_port_max = None,None
            dst_port_min, dst_port_max = None,None
        with context.session.begin(subtransactions=True):
            fwr_db = FirewallRule(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=fwr['name'],
                description=fwr['description'],
                shared=fwr['shared'],
                protocol=fwr['protocol'],
                ip_version=fwr['ip_version'],
                source_ip_address=fwr['source_ip_address'],
                destination_ip_address=fwr['destination_ip_address'],
                source_port_range_min=src_port_min,
                source_port_range_max=src_port_max,
                destination_port_range_min=dst_port_min,
                destination_port_range_max=dst_port_max,
                src_router_id = fwr['src_router_id'],
                dst_router_id = fwr['dst_router_id'],
                action=fwr['action'],
                start_time=fwr['start_time'],
                end_time=fwr['end_time'],
                session_type='1',
                enabled=fwr['enabled'])
            context.session.add(fwr_db)
        return self._make_firewall_rule_dict(fwr_db)

    def update_security_area(self, context, id, security_area):
        LOG.debug("update_security_area() called")
        fws = security_area
        fws_db = self._get_security_area(context, id)
        with context.session.begin(subtransactions=True):
            fws_db.update(fws)
        return self._make_security_area_dict(fws_db)

    def create_security_area(self, context, security_area):
        LOG.debug("create_security_area() called")
        fws = security_area
        tenant_id = self._get_tenant_id_for_create(context, fws)
        fws_db = SecurityArea(
            id=uuidutils.generate_uuid(),
            tenant_id=tenant_id,
            name=fws['name'],
            priority=fws['priority'],
            ifnames=fws['ifnames'],
            firewall_id=fws['firewall_id'],
            router_id=fws['router_id'],
            security_area_type=fws['security_area_type'],
            cidr=fws['cidr'])
        context.session.add(fws_db)
        return self._make_security_area_dict(fws_db)

    def create_hardware_firewall_security_zone(
            self, context, dp_security_area):
        LOG.debug("create_hardware_firewall_security_zone() called")
        dpfws = dp_security_area
        tenant_id = self._get_tenant_id_for_create(context, dpfws)
        with context.session.begin(subtransactions=True):
            dpfws_db = HardwareFirewallSecurityZone(
                id=uuidutils.generate_uuid(),
                name=dpfws['name'],
                ifnames=dpfws['ifnames'],
                priority=dpfws['priority'],
                tenant_id=tenant_id,
                security_area_type=dpfws['security_area_type'],
                router_id=dpfws['router_id'],
                cidr=dpfws['cidr'])
            context.session.add(dpfws_db)
        return self._make_hardware_firewall_security_zone(dpfws_db)

    def create_firewall_area_zone_associations(
            self, context, firewall_area_zone_associations):
        LOG.debug("create_firewall_area_zone_associations() called")
        az = firewall_area_zone_associations
        with context.session.begin(subtransactions=True):
            az_db = FirewallAreaZoneAssociations(
                id=uuidutils.generate_uuid(),
                security_area_id=az['security_area_id'],
                security_zone_id=az['security_zone_id'])
            context.session.add(az_db)
        return self._make_firewall_area_zone_associations(az_db)

    def delete_firewall_area_zone_associations(self, context, id):
        with context.session.begin(subtransactions=True):
            area_zone = self._get_firewall_area_zone_association(context, id)
            context.session.delete(area_zone)

    def get_firewall_area_zone_associations(
            self, context, filters=None, fields=None):
        LOG.debug("get_firewall_area_zone_associations() called")
        return self._get_collection(context, FirewallAreaZoneAssociations,
                                    self._make_firewall_area_zone_associations,
                                    filters=filters, fields=fields)

    def delete_hardware_firewall_security_zone(self, context, id):
        LOG.debug("delete_hardware_firewall_security_zone() called")
        with context.session.begin(subtransactions=True):
            security_zone = self._get_hardware_firewall_security_zone(
                context, id)
            context.session.delete(security_zone)

    def get_hardware_firewall_security_zone(self, context, id, fields=None):
        LOG.debug("get_hardware_firewall_security_zone() called")
        fwsz = self._get_hardware_firewall_security_zone(context, id)
        return self._make_hardware_firewall_security_zone(fwsz, fields)

    def get_hardware_firewall_security_zones(
            self, context, filters=None, fields=None):
        LOG.debug("get_hardware_firewall_security_zones() called")
        return self._get_collection(context, HardwareFirewallSecurityZone,
                                    self._make_hardware_firewall_security_zone,
                                    filters=filters, fields=fields)

    def create_vlan(self, context, vlan):
        LOG.debug('create_vlan() called')
        with context.session.begin(subtransactions=True):
            vlan_db = HardwareFirewallVlan(
                id=uuidutils.generate_uuid(),
                vlan_id=vlan['vlan_id'],
                vlan_name=vlan['vlan_name'],
                ipaddr=vlan['ipaddr'],
                ifnames=vlan['ifnames'],
                sz_id=vlan['sz_id'],
                tenant_id=vlan['tenant_id'],
                vrf_id=vlan['vrf_id'],
            )
            context.session.add(vlan_db)
        return self._make_vlan_dict(vlan_db)

    def get_vlans(self, context, filters=None, fields=None):
        LOG.debug('get_vlans() called')
        return self._get_collection(context, HardwareFirewallVlan,
                                    self._make_vlan_dict,
                                    filters=filters, fields=fields)

    def create_vrf(self, context, vrf):
        LOG.debug('create_vrf() called')
        with context.session.begin(subtransactions=True):
            vrf_db = HardwareFirewallVrf(
                id=uuidutils.generate_uuid(),
                name=vrf['name'],
                ifnames=vrf['ifnames'],
                vsys_id=vrf['vsys_id']
            )
            context.session.add(vrf_db)
        return self._make_hardware_firewall_vrf(vrf_db)

    def create_fw_vsys(self, context, fw_vsys):
        LOG.debug('create_fw_vsys() called')
        with context.session.begin(subtransactions=True):
            fw_vsys_db = FirewallVsysAssociations(
                id=uuidutils.generate_uuid(),
                firewall_id=fw_vsys['firewall_id'],
                vsys_id=fw_vsys['vsys_id']
            )
            context.session.add(fw_vsys_db)
        return self._make_fw_vsys_dict(fw_vsys_db)

    def create_vsys(self, context, vsys):
        LOG.debug('create_vsys() called')
        with context.session.begin(subtransactions=True):
            vsys_db = HardwareFirewallVsys(id=uuidutils.generate_uuid(),
                                           name=vsys['name'],
                                           type=vsys['type']
                                           )
            context.session.add(vsys_db)
        return self._make_hardware_firewall_vsys(vsys_db)

#     def create_sz(self, context, zone):
#         LOG.debug('create_sz() called')
#         with context.session.begin(subtransactions=True):
#             vsys_db = FirewallSecurityArea(id=uuidutils.generate_uuid(),
#                                            name=zone['name'],
#                                            ifnames=zone['ifNames'],
#                                            priority=zone['priority']
#                                            )
#             context.session.add(vsys_db)
#         return self._make_hardware_firewall_vsys(vsys_db)

    def update_firewall_rule(self, context, id, firewall_rule):
        LOG.debug("update_firewall_rule() called")
        fwr = firewall_rule['firewall_rule']
        fwr_db = self._get_firewall_rule(context, id)
        if 'start_time' not in fwr.keys() or len(fwr['start_time']) == 0:
            start_time = datetime.now().strftime("%Y-%m-%d %H:%M")
            fwr['start_time'] = start_time
        else:
            self._validate_fwr_datetime(fwr['start_time'])
        if 'end_time' not in fwr.keys() or len(fwr['end_time']) == 0:
            end_time = (
                datetime.now() +
                timedelta(
                    days=+
                    3650)).strftime("%Y-%m-%d %H:%M")
            fwr['end_time'] = end_time
        else:
            self._validate_fwr_datetime(fwr['end_time'])
            if fwr['start_time'] >= fwr['end_time']:
                raise fw_ext.HardwareFirewallDataTimeError()
        if fwr_db.firewall_policy_id:
            fwp_db = self._get_firewall_policy(context,
                                               fwr_db.firewall_policy_id)
            if 'shared' in fwr and not fwr['shared']:
                if fwr_db['tenant_id'] != fwp_db['tenant_id']:
                    raise fw_ext.FirewallRuleInUse(firewall_rule_id=id)
        if 'source_port' in fwr and fwr['protocol'] != "icmp":
            src_port_min, src_port_max = self._get_min_max_ports_from_range(
                fwr['source_port'])
            fwr['source_port_range_min'] = src_port_min
            fwr['source_port_range_max'] = src_port_max
            del fwr['source_port']

        if 'destination_port' in fwr and fwr['protocol'] != "icmp":
            dst_port_min, dst_port_max = self._get_min_max_ports_from_range(
                fwr['destination_port'])
            fwr['destination_port_range_min'] = dst_port_min
            fwr['destination_port_range_max'] = dst_port_max
            del fwr['destination_port']

        with context.session.begin(subtransactions=True):
            protocol = fwr.get('protocol', fwr_db['protocol'])
            if not protocol:
                sport = fwr.get('source_port_range_min',
                                fwr_db['source_port_range_min'])
                dport = fwr.get('destination_port_range_min',
                                fwr_db['destination_port_range_min'])
                if sport or dport:
                    raise fw_ext.FirewallRuleWithPortWithoutProtocolInvalid()
            fwr_db.update(fwr)
            if fwr_db.firewall_policy_id:
                fwp_db.audited = False
        return self._make_firewall_rule_dict(fwr_db)

    def delete_firewall_rule(self, context, id):
        LOG.debug("delete_firewall_rule() called")
        with context.session.begin(subtransactions=True):
            fwr = self._get_firewall_rule(context, id)
            if fwr.firewall_policy_id:
                raise fw_ext.FirewallRuleInUse(firewall_rule_id=id)
            context.session.delete(fwr)

    def del_rule_packetfilter(self, context, packetfilter_id):
        LOG.debug('delete_rule_packetfilter() called')
        with context.session.begin(subtransactions=True):
            context.session.query(FirewallRulesPacketfilterAssociations).\
                filter_by(packetfilter_id=packetfilter_id).delete()
            # if not count:
            #     raise fw_ext.FirewallRulesPacketfilterAssociationsNotFound(
            #         rule_packetfilter_id=packetfilter_id)

    def delete_firewall_packetfilter(self, context, id):
        LOG.debug('delete_firewall_packetfilter() called')
        with context.session.begin(subtransactions=True):
            context.session.query(
                HardwareFirewallPacketfilterServiceAssociate).\
                filter_by(packetfilter_id=id).delete()
            # if not service_count:
            #     raise fw_ext.FirewallPacketfilterServiceNotFound(
            #         firewall_packetfilter_id=id)
            context.session.query(HardwareFirewallPacketfilterDaddrAssociate).\
                filter_by(packetfilter_id=id).delete()
            # if not daddr_count:
            #     raise fw_ext.FirewallPacketfilterDaddrobjNotFound(
            #         firewall_packetfilter_id=id)
            context.session.query(HardwareFirewallPacketfilterSaddrAssociate).\
                filter_by(packetfilter_id=id).delete()
            # if not saddr_count:
            #     raise fw_ext.FirewallPacketfilterSaddrobjNotFound(
            #         firewall_packetfilter_id=id)
            context.session.query(
                HardwareFirewallPacketfilterZoneAssociations).\
                filter_by(packetfilter_id=id).delete()
            # if not zone_count:
            #     raise fw_ext.FirewallPacketfilterSZNotFound(
            #         firewall_packetfilter_id=id)
            context.session.query(
                HardwareFirewallPacketfilter). filter_by(id=id).delete()
            # if not packetfilter_count:
            #     raise fw_ext.FirewallPacketfilterNotFound(
            #         firewall_packetfilter_id=id)

    def get_firewall_rule(self, context, id, fields=None):
        LOG.debug("get_firewall_rule() called")
        fwr = self._get_firewall_rule(context, id)
        return self._make_firewall_rule_dict(fwr, fields)

    def get_firewall_rules(self, context, filters=None, fields=None):
        LOG.debug("get_firewall_rules() called")
        return self._get_collection(context, FirewallRule,
                                    self._make_firewall_rule_dict,
                                    filters=filters, fields=fields)

    def get_firewall_packetfilters(self, context, filters=None, fields=None):
        LOG.debug("get_firewall_packetfilters() called")
        return self._get_collection(context, HardwareFirewallPacketfilter,
                                    self._make_hardware_packetfilter_dict,
                                    filters=filters, fields=fields)

    def get_packetfilter_ids(self, context, filters=None, fields=None):
        LOG.debug('get_packetfilter_id() called.')
        return self._get_collection(
            context,
            FirewallRulesPacketfilterAssociations,
            self._make_rule_packetfilter_dict,
            filters=filters,
            fields=fields)

    def get_firewalls_rules_count(self, context, filters=None):
        LOG.debug("get_firewall_rules_count() called")
        return self._get_collection_count(context, FirewallRule,
                                          filters=filters)

    def _validate_insert_remove_rule_request(self, id, rule_info):
        if not rule_info or 'firewall_rule_id' not in rule_info:
            raise fw_ext.FirewallRuleInfoMissing()

    def insert_rule(self, context, id, rule_info):
        LOG.debug("insert_rule() called")
        self._validate_insert_remove_rule_request(id, rule_info)
        firewall_rule_id = rule_info['firewall_rule_id']
        insert_before = True
        ref_firewall_rule_id = None
        if not firewall_rule_id:
            raise fw_ext.FirewallRuleNotFound(firewall_rule_id=None)
        if 'insert_before' in rule_info:
            ref_firewall_rule_id = rule_info['insert_before']
        if not ref_firewall_rule_id and 'insert_after' in rule_info:
            # If insert_before is set, we will ignore insert_after.
            ref_firewall_rule_id = rule_info['insert_after']
            insert_before = False
        with context.session.begin(subtransactions=True):
            fwr_db = self._get_firewall_rule(context, firewall_rule_id)
            fwp_db = self._get_firewall_policy(context, id)
            if fwr_db["firewall_policy_id"]:
                raise fw_ext.FirewallRuleInUse(firewall_rule_id=fwr_db['id'])
            self._check_firewall_rule_conflict(fwr_db, fwp_db)
            if ref_firewall_rule_id:
                # If reference_firewall_rule_id is set, the new rule
                # is inserted depending on the value of insert_before.
                # If insert_before is set, the new rule is inserted before
                # reference_firewall_rule_id, and if it is not set the new
                # rule is inserted after reference_firewall_rule_id.
                ref_fwr_db = self._get_firewall_rule(
                    context, ref_firewall_rule_id)
                if ref_fwr_db.firewall_policy_id != id:
                    raise fw_ext.FirewallRuleNotAssociatedWithPolicy(
                        firewall_rule_id=ref_fwr_db['id'],
                        firewall_policy_id=id)
                if insert_before:
                    position = ref_fwr_db.position
                else:
                    position = ref_fwr_db.position + 1
            else:
                # If reference_firewall_rule_id is not set, it is assumed
                # that the new rule needs to be inserted at the top.
                # insert_before field is ignored.
                # So default insertion is always at the top.
                # Also note that position numbering starts at 1.
                position = 1
            return self._process_rule_for_policy(context, id, fwr_db,
                                                 position)

    def remove_rule(self, context, id, rule_info):
        LOG.debug("remove_rule() called")
        self._validate_insert_remove_rule_request(id, rule_info)
        firewall_rule_id = rule_info['firewall_rule_id']
        if not firewall_rule_id:
            raise fw_ext.FirewallRuleNotFound(firewall_rule_id=None)
        with context.session.begin(subtransactions=True):
            fwr_db = self._get_firewall_rule(context, firewall_rule_id)
            if fwr_db.firewall_policy_id != id:
                raise fw_ext.FirewallRuleNotAssociatedWithPolicy(
                    firewall_rule_id=fwr_db['id'],
                    firewall_policy_id=id)
            return self._process_rule_for_policy(context, id, fwr_db, None)

    def create_hardware_ip_addr_obj(self, context, firewall_rule,
                                    ip_addr_input_dict, status=None):
        LOG.debug("create_ip_addr_obj() called")
        # distributed routers may required a more complex state machine;
        # the introduction of a new 'CREATED' state allows this, whilst
        # keeping a backward compatible behavior of the logical resource.
        # filters = {}
        # filters['firewall_rule_id'] = [firewall_rule['id']]
        # filters['firewall_id'] = [firewall_rule['firewall_id']]
        # filters['ip'] = [ip]
        # ip_addr_obj_list = self.get_ip_addr_objs(context, filters)
        # if len(ip_addr_obj_list) >0:
        #     return ip_addr_obj_list[0]
        with context.session.begin(subtransactions=True):
            id = uuidutils.generate_uuid()
            Hardware_Firewall_Dddrobj_db = HardwareFirewallAddrobj(
                id=id,
                name=ip_addr_input_dict['name'],
                ip=ip_addr_input_dict['ip'],
                vsys_id=firewall_rule['vsys_id']
            )
            context.session.add(Hardware_Firewall_Dddrobj_db)
            return self._make_hardware_firewall_addrobj(
                Hardware_Firewall_Dddrobj_db)

    def get_hardware_ip_addr_obj(self, context, id, fields=None):
        LOG.debug("get_ip_addr_obj() called")
        ip_addr_bbj = self._get_hardware_firewall_addrobj(context, id)
        return self._make_hardware_firewall_addrobj(ip_addr_bbj, fields)

    def get_hardware_ip_addr_objs(self, context, filters=None, fields=None):
        LOG.debug("get_ip_addr_objs() called")
        return self._get_collection(context, HardwareFirewallAddrobj,
                                    self._make_hardware_firewall_addrobj,
                                    filters=filters, fields=fields)

    def create_hardware_server_obj(self, context,
                                   firewall_rule,
                                   server_input_dict,
                                   status=None):
        LOG.debug("create_hardware_Server_obj() called")
        # distributed routers may required a more complex state machine;
        # the introduction of a new 'CREATED' state allows this, whilst
        # keeping a backward compatible behavior of the logical resource.
        # filters = {}
        # filters['firewall_rule_id'] = [firewall_rule['id']]
        # filters['firewall_id'] = [firewall_rule['firewall_id']]
        # filters['ip'] = [ip]
        # ip_addr_obj_list = self.get_ip_addr_objs(context, filters)
        # if len(ip_addr_obj_list) >0:
        #     return ip_addr_obj_list[0]
        with context.session.begin(subtransactions=True):
            id = uuidutils.generate_uuid()
            Hardware_Firewall_Serverobj_db = HardwareFirewallServiceobj(
                id=id,
                name=server_input_dict['name'],
                proto=server_input_dict['proto'],
                port=server_input_dict['destination_port'],
                vsys_id=firewall_rule['vsys_id']
            )
            context.session.add(Hardware_Firewall_Serverobj_db)
            return self._make_hardware_firewall_serviceobj(
                Hardware_Firewall_Serverobj_db)

    def get_hardware_server_obj(self, context, id, fields=None):
        LOG.debug("get_hardware_Server_obj() called")
        server_bbj = self._get_hardware_firewall_serverobj(context, id)
        return self._make_hardware_firewall_serviceobj(server_bbj, fields)

    def get_hardware_server_objs(self, context, filters=None, fields=None):
        LOG.debug("get_hardware_Server_objs() called")
        return self._get_collection(context, HardwareFirewallServiceobj,
                                    self._make_hardware_firewall_serviceobj,
                                    filters=filters, fields=fields)

    def create_hardware_time_obj(self, context, firewall_rule,
                                 firewall_time, status=None):
        LOG.debug("create_hardware_time_obj() called")
        with context.session.begin(subtransactions=True):
            id = uuidutils.generate_uuid()
            Hardware_Firewall_Time_db = HardwareFirewallTimeobj(
                id=id,
                name=firewall_time['name'],
                mode=firewall_time['mode'],
                week=firewall_time['week'],
                startDay=firewall_time['startDay'],
                endDay=firewall_time['endDay'],
                startTime=firewall_time['startTime'],
                endTime=firewall_time['endTime'],
                vsys_id=firewall_rule['vsys_id'],
            )
            context.session.add(Hardware_Firewall_Time_db)
            return self._make_hardware_firewall_timeobj(
                Hardware_Firewall_Time_db)

    def get_hardware_time_obj(self, context, id, fields=None):
        LOG.debug("get_hardware_time_obj() called")
        timeo_bj = self._get_hardware_firewall_timeobj(context, id)
        return self._make_hardware_firewall_timeobj(timeo_bj, fields)

    def get_hardware_time_objs(self, context, filters=None, fields=None):
        LOG.debug("get_hardware_time_objs() called")
        return self._get_collection(context, HardwareFirewallTimeobj,
                                    self._make_hardware_firewall_timeobj,
                                    filters=filters, fields=fields)

    def delete_obj_by_vsysid(self, context, vsys_id):
        LOG.debug('delete_obj_by_vsysid() called')
        with context.session.begin(subtransactions=True):
            context.session.query(HardwareFirewallServiceobj).\
                filter_by(vsys_id=vsys_id).delete()
            context.session.query(HardwareFirewallTimeobj).\
                filter_by(vsys_id=vsys_id).delete()
            context.session.query(HardwareFirewallAddrobj).\
                filter_by(vsys_id=vsys_id).delete()

    def delete_firewall_security_area(self, context, id):
        LOG.debug('delete_firewall_security_area() called')
        with context.session.begin(subtransactions=True):
            fws = context.session.query(SecurityArea).filter_by(router_id=id)
            count = fws.delete()
            if not count:
                raise fw_ext.HardwareFirewallSecurityareaNotFound(
                    security_area_id=fws.id)

    def delete_security_area(self, context, id):
        LOG.debug('delete_security_area() called')
        with context.session.begin(subtransactions=True):
            context.session.query(SecurityArea).\
                filter_by(id=id).delete()

    def get_security_area(self, context, id, fields=None):
        LOG.debug('get_security() called')
        fws = self._get_security_area_by_router_id(context, id)
        return self._make_security_area_dict(fws, fields)

    def get_firewall_security_area(self, context, id, fields=None):
        LOG.debug('get_security() called')
        fws = self._get_security_area_by_router_id(context, id)
        return self._make_security_area_dict(fws, fields)

    def get_hardware_firewall_vsys(self, context, id, fields=None):
        LOG.debug('get_hardware_firewall_vsys() called')
        vsys = self._get_hardware_firewall_vsys(context, id)
        return self._make_hardware_firewall_vsys(vsys, fields)

    def get_firewalls_vsys_associations(self, context, filters, fields=None):
        LOG.debug('get_firewalls_vsys_associations() called')
        return self._get_collection(context,
                                    FirewallVsysAssociations,
                                    self._make_firewalls_vsys_associations,
                                    filters=filters, fields=fields)

    def get_hardware_firewalls_security_area_zone_associations(
            self, context, filters=None, fields=None):
        LOG.debug('get_hardware_firewalls_se'
                  'curity_area_zone_associations() called')
        return self._get_collection(context,
                                    FirewallAreaZoneAssociations,
                                    self._make_firewall_area_zone_associations,
                                    filters=filters, fields=fields)

    def get_firewall_security_areas(self, context, filters=None, fields=None):
        LOG.debug("get_firewall_security_areas() called")
        return self._get_collection(context, SecurityArea,
                                    self._make_security_area_dict,
                                    filters=filters, fields=fields)

    def update_firewall_rule_status(self, context, id, status, not_in=None):
        """Conditionally update rule status.

        Status transition is performed only if firewall is not in the specified
        states as defined by 'not_in' list.
        """
        # filter in_ wants iterable objects, None isn't.
        not_in = not_in or []
        with context.session.begin(subtransactions=True):
            return (context.session.query(FirewallRule).
                    filter(FirewallRule.id == id).
                    filter(~FirewallRule.status.in_(not_in)).
                    update({'status': status}, synchronize_session=False))

    def _get_hardware_firewall_vlans(self, context, filters=None, fields=None):
        return self._get_collection(context, HardwareFirewallVlan,
                                    self._make_hardware_firewall_vlan,
                                    filters=filters, fields=fields)

    def create_hardware_firewall_vlan(self, context, hardware_firewall_vlan):
        LOG.debug("create_hardware_firewall_vlan() called")
        tenant_id = self._get_tenant_id_for_create(context,
                                                   hardware_firewall_vlan)
        vlan = hardware_firewall_vlan
        with context.session.begin(subtransactions=True):
            id = uuidutils.generate_uuid()
            fwv_db = HardwareFirewallVlan(
                id=id,
                vlan_id=vlan['vlan_id'],
                vlan_name=vlan['vlan_name'],
                ipaddr=vlan['ipaddr'],
                ifnames=vlan['ifnames'],
                sz_id=vlan['sz_id'],
                tenant_id=tenant_id,
                vrf_id=vlan['vrf_id'])
            context.session.add(fwv_db)
            return self._make_hardware_firewall_vlan(fwv_db)

    def update_hardware_firewall_vlan(
            self, context, id, hardware_firewall_vlan):
        LOG.debug("update_hardware_firewall_vlan() called")
        vlan = hardware_firewall_vlan
        vlan_db = self._get_hardware_firewall_vlan(context, id)
        with context.session.begin(subtransactions=True):
            vlan_db.update(vlan)
            return self._make_hardware_firewall_vlan(vlan_db)

    def get_hardware_firewall_vrf(self, context, id, fields=None):
        LOG.debug("get_hardware_firewall_vrf() called")
        vrf = self._get_hardware_firewall_vrf(context, id)
        return self._make_hardware_firewall_vrf(vrf, fields)

    def get_hardware_firewall_vrfs(self, context, filters=None, fields=None):
        return self._get_collection(context, HardwareFirewallVrf,
                                    self._make_hardware_firewall_vrf,
                                    filters=filters, fields=fields)

    def update_dptehch_firewall_vrf(self, context, id, hardware_firewall_vrf):
        LOG.debug("update_hardware_firewall_vrf() called")
        vrf = hardware_firewall_vrf
#         ifnames = vrf['ifnames']
        vrf_db = self._get_hardware_firewall_vrf(context, id)
#         ifnames_db = vrf_db('ifnames')
        with context.session.begin(subtransactions=True):
            vrf_db.update(vrf)
        return self._make_hardware_firewall_vrf(vrf_db)

    def delete_hardware_friewall_addr(self, context, id):
        LOG.debug("delete_hardware_friewall_addr() called")
        with context.session.begin(subtransactions=True):
            count = context.session.query(HardwareFirewallAddrobj).\
                filter_by(id=id).delete()
            if not count:
                raise fw_ext.HardwareFirewallAddrobjNotFound(addr_obj=id)

    def delete_hardware_frewall_netservice(self, context, id):
        LOG.debug("delete_hardware_frewall_netservice() called")
        with context.session.begin(subtransactions=True):
            # Note: Plugin should ensure that it's okay to delete if the
            # firewall is active
            count = context.session.query(HardwareFirewallServiceobj).\
                filter_by(id=id).delete()
            if not count:
                raise fw_ext.HardwareFirewallServerobjNotFound(
                    server_obj=id)

    def delete_hardware_firewall_vlan(self, context, id):
        LOG.debug("delete_hardware_frewall_vlan() called")
        with context.session.begin(subtransactions=True):
            # Note: Plugin should ensure that it's okay to delete if the
            # firewall is active
            count = context.session.query(HardwareFirewallVlan).\
                filter_by(id=id).delete()
            if not count:
                raise fw_ext.HardwareFirewallVlanNotFound(
                    vlan_id=id)

    def delete_vlan(self, context, vrf_id):
        LOG.debug("delete_vlan() called")
        with context.session.begin(subtransactions=True):
            context.session.query(HardwareFirewallVlan).\
                filter_by(vrf_id=vrf_id).delete()

    def delete_hardware_firewall_vrf(self, context, id):
        LOG.debug("delete_hardware_firewall_vrf() called")
        with context.session.begin(subtransactions=True):
            # Note: Plugin should ensure that it's okay to delete if the
            # firewall is active
            count = context.session.query(HardwareFirewallVrf).\
                filter_by(id=id).delete()
            if not count:
                raise fw_ext.HardwareFirewallVrfNotFound(
                    vrf_id=id)

    def delete_hardware_firewall_vsys(self, context, id):
        LOG.debug("delete_hardware_firewall_vsys() called")
        with context.session.begin(subtransactions=True):
            # Note: Plugin should ensure that it's okay to delete if the
            # firewall is active
            count = context.session.query(HardwareFirewallVsys).\
                filter_by(id=id).delete()
            if not count:
                raise fw_ext.HardwareFirewallVsysNotFound(
                    vsys_id=id)

    def delete_firewall_vsys_associa(self, context, id):
        LOG.debug("delete_firewall_vsys_associa() called")
        with context.session.begin(subtransactions=True):
            # Note: Plugin should ensure that it's okay to delete if the
            # firewall is active
            count = context.session.query(FirewallVsysAssociations).\
                filter_by(firewall_id=id).delete()
            if not count:
                raise fw_ext.HardwareFirewallVsysAssociaNotFound(
                    id=id)

    def delete_hardware_frewall_timer(self, context, id):
        LOG.debug("delete_hardware_frewall_timer() called")
        with context.session.begin(subtransactions=True):
            # Note: Plugin should ensure that it's okay to delete if the
            # firewall is active
            count = context.session.query(HardwareFirewallTimeobj).\
                filter_by(id=id).delete()
            if not count:
                raise fw_ext.HardwareFirewallTimeobjNotFound(time_id=id)

    def create_hardware_firewall_packetfilter(self, context, packetfilter):
        LOG.debug("create_hardware_firewall_packetfilter() called")
        with context.session.begin(subtransactions=True):
            pck_db = HardwareFirewallPacketfilter(
                name=packetfilter['name'],
                action=packetfilter['action'],
                log=packetfilter['log'],
                session_type=packetfilter['session_type'],
                vsys_id=packetfilter['vsys_id'],
                timeobj_id=packetfilter['timeobj_id']
            )
            context.session.add(pck_db)
        return self._make_hardware_firewall_packetfilter(pck_db)

    def create_hardware_firewall_packetfilter_saddr_associate(
            self, context, addrobj_id, packetfilter_id):
        LOG.debug("create_hardware_firewall_packetfilter_saddr_associate()"
                  " called")
        with context.session.begin(subtransactions=True):
            pck_db = HardwareFirewallPacketfilterSaddrAssociate(
                addrobj_id=addrobj_id,
                packetfilter_id=packetfilter_id
            )
            context.session.add(pck_db)
        return self._make_hardware_packetfilter_addr_dict(pck_db)

    def create_hardware_firewall_packetfilter_daddr_associate(
            self, context, addrobj_id, packetfilter_id):
        LOG.debug("create_hardware_firewall_packetfilter_daddr_associate()"
                  " called")
        with context.session.begin(subtransactions=True):
            pck_db = HardwareFirewallPacketfilterDaddrAssociate(
                addrobj_id=addrobj_id,
                packetfilter_id=packetfilter_id
            )
            context.session.add(pck_db)
        return self._make_hardware_packetfilter_addr_dict(pck_db)

    def create_hardware_firewall_rule_packetfilter_associate(
            self, context, packetfilter_id, rule_id):
        LOG.debug("create_hardware_firewall_rule_packetfilter_associate()"
                  " called")
        with context.session.begin(subtransactions=True):
            pck_db = FirewallRulesPacketfilterAssociations(
                rule_id=rule_id,
                packetfilter_id=packetfilter_id
            )
            context.session.add(pck_db)
        return self._make_hardware_packetfilter_rule_dict(pck_db)

    def create_hardware_firewall_packetfilter_service_associate(
            self, context, service_id, packetfilter_id):
        LOG.debug("create_hardware_firewall_packetfilter_service_associate()"
                  " called")
        with context.session.begin(subtransactions=True):
            pck_db = HardwareFirewallPacketfilterServiceAssociate(
                service_id=service_id,
                packetfilter_id=packetfilter_id
            )
            context.session.add(pck_db)
        return self._make_hardware_packetfilter_service_dict(pck_db)

    def create_hardware_firewall_packetfilter_zone_associate(
            self, context, sz_id, packetfilter_id):
        LOG.debug("create_hardware_firewall_packetfilter_zone_associate()"
                  " called")
        with context.session.begin(subtransactions=True):
            pck_db = HardwareFirewallPacketfilterZoneAssociations(
                sz_id=sz_id,
                packetfilter_id=packetfilter_id
            )
            context.session.add(pck_db)
        return self._make_hardware_packetfilter_zone_dict(pck_db)

    def get_hardware_firewalls_security_zone_associations(self, context,
                                                          filters=None,
                                                          fields=None):
        return self._get_collection(
            context, HardwareFirewallPacketfilterZoneAssociations,
            self._make_hardware_firewall_security_zone_associations,
            filters=filters, fields=fields)

    def get_hardware_firewall_rule_packetfilter_asso(self,
                                                     context, filters=None,
                                                     fields=None
                                                     ):
        return self._get_collection(
            context, FirewallRulesPacketfilterAssociations,
            self._make_hardware_firewall_rule_packetfilter_associations,
            filters=filters, fields=fields)

    def get_hardware_firewall_packetfilter(
            self, context, id,):
        fwp_db = self._get_hardware_firewall_packetfilter(
            context, id
        )
        return self._make_hardware_firewall_packetfilter(
            fwp_db
        )


def migration_callback(resource, event, trigger, **kwargs):
    context = kwargs['context']
    router = kwargs['router']
    fw_plugin = manager.NeutronManager.get_service_plugins().get(
        p_const.FIREWALL)
    if fw_plugin:
        tenant_firewalls = fw_plugin.get_firewalls(
            context, filters={'tenant_id': [router['tenant_id']]})
        if tenant_firewalls:
            raise l3.RouterInUse(router_id=router['id'])


def subscribe():
    registry.subscribe(
        migration_callback, resources.ROUTER, events.BEFORE_UPDATE)

# NOTE(armax): multiple FW service plugins (potentially out of tree) may
# inherit from firewall_db and may need the callbacks to be processed. Having
# an implicit subscription (through the module import) preserves the existing
# behavior, and at the same time it avoids fixing it manually in each and
# every fw plugin out there. That said, The subscription is also made
# explicitly in the reference fw plugin. The subscription operation is
# idempotent so there is no harm in registering the same callback multiple
# times.
subscribe()
