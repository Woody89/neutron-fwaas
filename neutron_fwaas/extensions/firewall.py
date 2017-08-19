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

import abc

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import resource_helper
from neutron.common import constants
from neutron.common import exceptions as nexception
from neutron.plugins.common import constants as p_const
from neutron.services import service_base
from oslo_config import cfg
from oslo_log import log as logging
from neutron.i18n import _
import six

LOG = logging.getLogger(__name__)

# Firewall rule action
FWAAS_ALLOW = "allow"
FWAAS_DENY = "deny"
FWAAS_REJECT = "reject"

# Firewall resource path prefix
FIREWALL_PREFIX = "/fw"


# Firewall Exceptions
class FirewallNotFound(nexception.NotFound):
    message = _("Firewall %(firewall_id)s could not be found.")


class FirewallInUse(nexception.InUse):
    message = _("Firewall %(firewall_id)s is still active.")


class FirewallInPendingState(nexception.Conflict):
    message = _("Operation cannot be performed since associated Firewall "
                "%(firewall_id)s is in %(pending_state)s.")


class FirewallNotActive(nexception.NotFound):
    message = _("Firewall %(firewall_name)s is not active.")


class FirewallPolicyNotFound(nexception.NotFound):
    message = _("Firewall Policy %(firewall_policy_id)s could not be found.")


class FirewallPolicyInUse(nexception.InUse):
    message = _("Firewall Policy %(firewall_policy_id)s is being used.")


class FirewallPolicyConflict(nexception.Conflict):
    """FWaaS exception for firewall policy

    Occurs when admin policy tries to use another tenant's unshared
    policy.
    """
    message = _("Operation cannot be performed since Firewall Policy "
                "%(firewall_policy_id)s is not shared and does not belong to "
                "your tenant.")


class FirewallRuleSharingConflict(nexception.Conflict):
    """FWaaS exception for firewall rules

    When a shared policy is created or updated with unshared rules,
    this exception will be raised.
    """
    message = _("Operation cannot be performed since Firewall Policy "
                "%(firewall_policy_id)s is shared but Firewall Rule "
                "%(firewall_rule_id)s is not shared")


class FirewallPolicySharingConflict(nexception.Conflict):
    """FWaaS exception for firewall policy

    When a policy is shared without sharing its associated rules,
    this exception will be raised.
    """
    message = _("Operation cannot be performed. Before sharing Firewall "
                "Policy %(firewall_policy_id)s, share associated Firewall "
                "Rule %(firewall_rule_id)s")


class FirewallPolicyNameExist(nexception.Conflict):
    message = _("Firewall Policy %(name)s already exist.")


class FirewallRuleNotFound(nexception.NotFound):
    message = _("Firewall Rule %(firewall_rule_id)s could not be found.")


class FirewallNameNotEmpty(nexception.NotFound):
    message = _("Name cannot be empty.")


class FirewallPacketfilterNotFound(nexception.NotFound):
    message = _('Firewall packetfilter %(fw_packetfilter_id)s '
                'could not be found.')


class FirewallPacketfilterServiceNotFound(nexception.NotFound):
    message = _('Firewall packetfilter-service %(firewall_packetfilter_id)s '
                'could not be found.')


class FirewallPacketfilterDaddrobjNotFound(nexception.NotFound):
    message = _('Firewall packetfilter-daddrobj '
                '%(firewall_packetfilter_id)s '
                'could not be found.')


class FirewallPacketfilterSaddrobjNotFound(nexception.NotFound):
    message = _('Firewall packetfilter-saddrobj '
                '%(firewall_packetfilter_id)s '
                'could not be found.')


class FirewallPacketfilterSZNotFound(nexception.NotFound):
    message = _('Firewall packetfilter-sz %(firewall_packetfilter_id)s '
                'could not be found.')


class ResourceAllocateException(nexception.NotFound):
    message = _('%(content)s')


class FirewallRuleInUse(nexception.InUse):
    message = _("Firewall Rule %(firewall_rule_id)s is being used.")


class FirewallRuleCreateFaild(nexception.NotFound):
    message = _("Firewall Rule %(name)s create Faild.")


class FirewallRuleUpdateFaild(nexception.NotFound):
    message = _("Firewall Rule %(name)s update Faild.")


class FirewallRuleDeleteFaild(nexception.NotFound):
    message = _("Firewall Rule %(name)s delete Faild.")


class FirewallRuleNotAssociatedWithPolicy(nexception.InvalidInput):
    message = _("Firewall Rule %(firewall_rule_id)s is not associated "
                " with Firewall Policy %(firewall_policy_id)s.")


class FirewallRuleInvalidProtocol(nexception.InvalidInput):
    message = _("Firewall Rule protocol %(protocol)s is not supported. "
                "Only protocol values %(values)s and their integer "
                "representation (0 to 255) are supported.")


class FirewallRuleInvalidAction(nexception.InvalidInput):
    message = _("Firewall rule action %(action)s is not supported. "
                "Only action values %(values)s are supported.")


class FirewallRuleInvalidICMPParameter(nexception.InvalidInput):
    message = _("%(param)s are not allowed when protocol "
                "is set to ICMP.")


class FirewallRuleWithPortWithoutProtocolInvalid(nexception.InvalidInput):
    message = _("Source/destination port requires a protocol")


class FirewallRuleInvalidPortValue(nexception.InvalidInput):
    message = _("Invalid value for port %(port)s.")


class FirewallRuleInfoMissing(nexception.InvalidInput):
    message = _("Missing rule info argument for insert/remove "
                "rule operation.")


class FirewallIpAddressConflict(nexception.InvalidInput):
    message = _("Invalid input - IP addresses do not agree with IP Version")


class FirewallIpAddressDuplicate(nexception.InvalidInput):
    message = _("Invalid input - IP addresses cannot be duplicated")


class FirewallAssociatePacketfilter(nexception.InUse):
    message = _('Firewall %(fw_id)s has packetfilter can not delete.')


class HardwareFirewallDataTimeFormatError(nexception.NotFound):
    message = _("Hardware Input %(param)% format error.")


class HardwareFirewallDataTimeError(nexception.NotFound):
    message = _("Hardware The start time is greater than the end time.")


class HardwareFirewallAddrobjNotFound(nexception.NotFound):
    message = _("Hardware Firewall ip_obj %(addr_obj)s could not be found.")


class HardwareFirewallServerobjNotFound(nexception.NotFound):
    message = _("Hardware Firewall Server %(server_obj)s could not be found.")


class HardwareFirewallTimeobjNotFound(nexception.NotFound):
    message = _("Hardware Firewall dataTime %(time_id)s could not be found.")


class HardwareFirewallNotFound(nexception.NotFound):
    message = _("Could not be found Firewall by policy.")


class HardwareAreaNotFound(nexception.NotFound):
    message = _("Hardware Firewall security "
                "area could not be found via %(ip)s.")


class HardwareFirewallTimerCreateFaild(nexception.NotFound):
    message = _("Hardware Firewall Timer Create faild Name=%(name)s.")


class HardwareFirewallAddrCreateFaild(nexception.NotFound):
    message = _("Hardware Firewall Addr create faild Name=%(name)s.")


class HardwareFirewallServiceCreateFaild(nexception.NotFound):
    message = _("Hardware Firewall Service create faild Name=%(name)s.")


class HardwareFirewallVlanCreateFaild(nexception.NotFound):
    message = _("Hardware Firewall Vlan create faild.")


class HardwareFirewallVrfCreateFaild(nexception.NotFound):
    message = _(
        "Hardware Firewall Vrf create faild vrf_id=%(vrf_id)s.")


class HardwareFirewallVsysCreateFaild(nexception.NotFound):
    message = _(
        "Hardware Firewall Vsys create faild vsys_id=%(vsys_id)s.")


class HardwareFirewallSecurityAreaOutExist(nexception.InUse):
    message = _(
        "Hardware Firewall Out SecurityArea  already Exist.")


class HardwareFirewallSecurityAreaTypeError(nexception.InUse):
    message = _(
        "Hardware Firewall SecurityArea type is in or out.")


class HardwareFirewallSecurityAreaOutNotFound(nexception.NotFound):
    message = _("Hardware Firewall Out SecurityArea not found.")


class HardwareFirewallSecurityAreaNameExist(nexception.InUse):
    message = _("Hardware Firewall SecurityArea Name already Exist.")


class HardwareFirewallSecurityAreaCidr(nexception.InUse):
    message = _("Hardware Firewall SecurityArea Out cidr need one.")


class HardwareFirewallSecurityAreaNotFoundByRouterID(nexception.InUse):
    message = _("Hardware Firewall SecurityArea "
                "Not Found by router_id=%(router_id)s.")


class HardwareFirewallSecurityAreaCreateFailed(nexception.NotFound):
    message = _(
        "Hardware Firewall Security Area create "
        "faild security_area_name=%(security_area_name)s.")


class HardwareFirewallSecurityareaNotFound(nexception.NotFound):
    message = _(
        "Hardware Firewall SecurityArea "
        "%(security_area_id)s not found")


class HardwareFirewallSecurityareaNotFoundByRouter(nexception.NotFound):
    message = _("Hardware Firewall SecurityArea"
                " %(security_area_router_id)s not found")


class HardwareFirewallSecurityareaSrcDstDuplicate(nexception.NotFound):
    message = _("Hardware Firewall source SecurityArea"
                "and destination SecurityArea can't be same")


class HardwareFirewallSecurityareaNotSame(nexception.NotFound):
    message = _("Hardware Firewall SecurityArea"
                "not same via %(name)s")


class HardwareFirewallRouterIdDuplicate(nexception.NotFound):
    message = _("Hardware Firewall src_router_id"
                "and dst_router_id can't be same")


class HardwareFirewallSecurityareaDstNotOUT(nexception.NotFound):
    message = _("Hardware Firewall destination "
                "SecurityArea type can't be OUT")


class HardwareFirewallAddrNotNone(nexception.BadRequest):
    message = _("Hardware Firewall source_ip_address or "
                "destination_ip_address can't be None")


class HardwareFirewallRouterIDNotNone(nexception.BadRequest):
    message = _("Hardware Firewall src_router_id or "
                "dst_router_id can't be Null")


class HardwareFirewallAddrExceed(nexception.BadRequest):
    message = _("Hardware Firewall source_ip_address or "
                "destination_ip_address can't exceed 10")


class HardwareFirewallAddrIllegal(nexception.BadRequest):
    message = _("Hardware Firewall ipaddr=%(ipaddr)s"
                "is and illegal IP")


class HardwareFirewallVlanNotFound(nexception.NotFound):
    message = _("Hardware Firewall Vlan"
                " %(vlan_id)s not found")


class HardwareFirewallVrfNotFound(nexception.NotFound):
    message = _("Hardware Firewall Vrf"
                " %(vrf_id)s not found")


class HardwareFirewallVsysNotFound(nexception.NotFound):
    message = _("Hardware Firewall Vsys"
                " %(vsys_id)s not found")


class HardwareFirewallVsysAssociaNotFound(nexception.NotFound):
    message = _("Hardware Firewall Vsys Associa"
                " %(id)s not found")


class FirewallNameExist(nexception.InUse):
    message = _("Hardware Firewall Name"
                " %(name)s already exist")


class DeviceDeleteFailed(nexception.NotFound):
    message = _('Failed while delete %(obj_id)s')


class FirewallExist(nexception.InUse):
    message = _('Dptech Firewall allready exist')


class FirewallRulesPacketfilterAssociationsNotFound(nexception.NotFound):
    message = _('Hardware Pakcetfilter=%(rule_packetfilter_id)s'
                'associations not found')


class HardwareFirewallSecurityAreaInUSe(nexception.InUse):
    message = _("HF Firewall SecurityArea "
                "%(security_area_name)s is being used.")


class HardwareFirewallSecurityArearouterExist(nexception.InUse):
    message = _("HF Firewall SecurityArea Router already Exist.")


class HardwareFirewallSecurityArearouterIsNone(nexception.InUse):
    message = _("HF Firewall SecurityArea Router_id is None.")


class HardwareFirewallSecurityArearCidrExist(nexception.InUse):
    message = _("HF Firewall SecurityArea Cidr already Exist.")


class HardwareFirewallSecurityArearCidrIsNone(nexception.InUse):
    message = _("HF Firewall SecurityArea Cidr is None.")


class HardwareFirewallSecurityAreaDeleteFailed(nexception.NotFound):
    message = _("HF Firewall Security_area failed to Delete")


class HardwareFirewallVrfUpdateFailed(nexception.NotFound):
    message = _("HF Firewall Vrf failed to Update")


class FirewallRuleNameExist(nexception.Conflict):
    message = _("HF Firewall Rule Name=%(name)s already Exist.")


class FirewallDstPortNotEmpty(nexception.BadRequest):
    message = _("Destination port can't be null")


# TODO(dougwig) - once this exception is out of neutron, restore this
# class FirewallInternalDriverError(nexception.NeutronException):
#    """Fwaas exception for all driver errors.
#
#    On any failure or exception in the driver, driver should log it and
#    raise this exception to the agent
#    """
#    message = _("%(driver)s: Internal driver error.")
FirewallInternalDriverError = nexception.FirewallInternalDriverError


class FirewallRuleConflict(nexception.Conflict):
    """Firewall rule conflict exception.

    Occurs when admin policy tries to use another tenant's unshared
    rule.
    """

    message = _("Operation cannot be performed since Firewall Rule "
                "%(firewall_rule_id)s is not shared and belongs to "
                "another tenant %(tenant_id)s")


fw_valid_protocol_values = [None, constants.PROTO_NAME_TCP,
                            constants.PROTO_NAME_UDP,
                            constants.PROTO_NAME_ICMP]
fw_valid_action_values = [FWAAS_ALLOW, FWAAS_DENY, FWAAS_REJECT]


def convert_protocol(value):
    if value is None:
        return
    if value.isdigit():
        val = int(value)
        if 0 <= val <= 255:
            return val
        else:
            raise FirewallRuleInvalidProtocol(
                protocol=value,
                values=fw_valid_protocol_values)
    elif value.lower() in fw_valid_protocol_values:
        return value.lower()
    else:
        raise FirewallRuleInvalidProtocol(
            protocol=value,
            values=fw_valid_protocol_values)


def convert_action_to_case_insensitive(value):
    if value is None:
        return
    else:
        return value.lower()


def convert_port_to_string(value):
    if value is None:
        return
    else:
        return str(value)


def _validate_port_range(data, key_specs=None):
    if data is None:
        return
    data = str(data)
    ports = data.split(':')
    for p in ports:
        try:
            val = int(p)
        except (ValueError, TypeError):
            msg = _("Port '%s' is not a valid number") % p
            LOG.debug(msg)
            return msg
        if val <= 0 or val > 65535:
            msg = _("Invalid port '%s'") % p
            LOG.debug(msg)
            return msg


def _validate_ip_or_subnet_or_none(data, valid_values=None):
    if data is None:
        return None
    msg_ip = attr._validate_ip_address(data, valid_values)
    if not msg_ip:
        return
    msg_subnet = attr._validate_subnet(data, valid_values)
    if not msg_subnet:
        return
    return _("%(msg_ip)s and %(msg_subnet)s") % {'msg_ip': msg_ip,
                                                 'msg_subnet': msg_subnet}


attr.validators['type:port_range'] = _validate_port_range
attr.validators['type:ip_or_subnet_or_none'] = _validate_ip_or_subnet_or_none

RESOURCE_ATTRIBUTE_MAP = {
    'firewall_rules': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:not_empty_string': attr.NAME_MAX_LEN},
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string':
                                         attr.DESCRIPTION_MAX_LEN},
                        'is_visible': True, 'default': ''},
        'firewall_policy_id': {'allow_post': False, 'allow_put': False,
                               'validate': {'type:uuid_or_none': None},
                               'is_visible': True},
        'shared': {'allow_post': True, 'allow_put': True,
                   'default': False, 'convert_to': attr.convert_to_boolean,
                   'is_visible': True, 'required_by_policy': True,
                   'enforce_policy': True},
        'protocol': {'allow_post': True, 'allow_put': True,
                     'is_visible': True, 'default': None,
                     'convert_to': convert_protocol,
                     'validate': {'type:values': fw_valid_protocol_values}},
        'ip_version': {'allow_post': True, 'allow_put': True,
                       'default': 4, 'convert_to': attr.convert_to_int,
                       'validate': {'type:values': [4, 6]},
                       'is_visible': True},
        'source_ip_address': {'allow_post': True, 'allow_put': True,
                              'validate': {'type:string': None},
                              'is_visible': True, 'default': None},
        'destination_ip_address': {'allow_post': True, 'allow_put': True,
                                   'validate': {'type:string':
                                                    None},
                                   'is_visible': True, 'default': None},
        'src_router_id': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:not_empty_string': None},
                          'type:uuid': None,
                          'is_visible': True},
        'dst_router_id': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:not_empty_string': None},
                          'type:uuid': None,
                          'is_visible': True},
        'source_port': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:port_range': None},
                        'convert_to': convert_port_to_string,
                        'default': None, 'is_visible': True},
        'destination_port': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:port_range': None},
                             'convert_to': convert_port_to_string,
                             'default': None, 'is_visible': True},
        'position': {'allow_post': False, 'allow_put': False,
                     'default': None, 'is_visible': True},
        'action': {'allow_post': True, 'allow_put': True,
                   'convert_to': convert_action_to_case_insensitive,
                   'validate': {'type:values': fw_valid_action_values},
                   'is_visible': True, 'default': 'deny'},
        'enabled': {'allow_post': True, 'allow_put': True,
                    'default': True, 'convert_to': attr.convert_to_boolean,
                    'is_visible': True},
        'start_time': {'allow_post': True, 'allow_put': True,
                       'validate': {'type:string':
                                        attr.DESCRIPTION_MAX_LEN},
                       'is_visible': True, 'default': ''},
        'end_time': {'allow_post': True, 'allow_put': True,
                     'validate': {'type:string':
                                      attr.DESCRIPTION_MAX_LEN},
                     'is_visible': True, 'default': ''},
        'session_type': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:values': ['0', '1']},
                         'is_visible': True, 'default': '0'},
    },
    'firewall_policies': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:not_empty_string': attr.NAME_MAX_LEN},
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string':
                                         attr.DESCRIPTION_MAX_LEN},
                        'is_visible': True, 'default': ''},
        'shared': {'allow_post': True, 'allow_put': True,
                   'default': False, 'convert_to': attr.convert_to_boolean,
                   'is_visible': True, 'required_by_policy': True,
                   'enforce_policy': True},
        'firewall_rules': {'allow_post': True, 'allow_put': True,
                           'validate': {'type:uuid_list': None},
                           'convert_to': attr.convert_none_to_empty_list,
                           'default': None, 'is_visible': True},
        'audited': {'allow_post': True, 'allow_put': True,
                    'default': False, 'convert_to': attr.convert_to_boolean,
                    'is_visible': True},
    },

    'security_areas': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None}, 'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'firewall_id': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True,
                        },
        'router_id': {'allow_post': True, 'allow_put': True,
                      'validate': {'type:not_empty_string': attr.NAME_MAX_LEN},
                      'is_visible': True
                      },
        'name': {'allow_post': True, 'allow_put': True,
		'type:not_empty_string': None,
                 'validate': {'type:not_empty_string': attr.NAME_MAX_LEN},
                 'is_visible': True},
        'priority': {'allow_post': False, 'allow_put': False,
                     'validate': {'type:string': None},
                     'is_visible': True
                     },
        'security_area_type': {'allow_post': True, 'allow_put': True,
                               'validate': {
                                   'type:values': ['in', 'out']},
                               'is_visible': True
                               },
        'cidr': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:subnet_list': None},
                 'is_visible': True
                 },
        'ifnames': {'allow_post': False, 'allow_put': True,
                    'validate': {'type:subnet': None},
                    'is_visible': True
                    },
    },
    'firewalls': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:not_empty_string': None,
                              'type:string': attr.NAME_MAX_LEN},
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string':
                                         attr.DESCRIPTION_MAX_LEN},
                        'is_visible': True, 'default': ''},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'convert_to': attr.convert_to_boolean,
                           'validate': {'type:boolean': None
                                        },
                           'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'shared': {'allow_post': True, 'allow_put': True,
                   'default': False, 'convert_to': attr.convert_to_boolean,
                   'is_visible': False, 'required_by_policy': True,
                   'enforce_policy': True},
        'firewall_policy_id': {'allow_post': True, 'allow_put': True,
                               'validate': {'type:not_empty_string': None,
                                            'type:uuid': None},
                               'is_visible': True}
    },
}

firewall_quota_opts = [
    cfg.IntOpt('quota_firewall',
               default=-1,
               help=_('Number of firewalls allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_firewall_policy',
               default=-1,
               help=_('Number of firewall policies allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_firewall_rule',
               default=-1,
               help=_('Number of firewall rules allowed per tenant. '
                      'A negative value means unlimited.')),
]
cfg.CONF.register_opts(firewall_quota_opts, 'QUOTAS')


class Firewall(extensions.ExtensionDescriptor):
    @classmethod
    def get_name(cls):
        return "Firewall service"

    @classmethod
    def get_alias(cls):
        return "fwaas"

    @classmethod
    def get_description(cls):
        return "Extension for Firewall service"

    @classmethod
    def get_namespace(cls):
        return "http://wiki.openstack.org/Neutron/FWaaS/API_1.0"

    @classmethod
    def get_updated(cls):
        return "2013-02-25T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        special_mappings = {'firewall_policies': 'firewall_policy'}
        plural_mappings = resource_helper.build_plural_mappings(
            special_mappings, RESOURCE_ATTRIBUTE_MAP)
        attr.PLURALS.update(plural_mappings)
        action_map = {'firewall_policy': {'insert_rule': 'PUT',
                                          'remove_rule': 'PUT'}}
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   p_const.FIREWALL,
                                                   action_map=action_map,
                                                   register_quota=True)

    @classmethod
    def get_plugin_interface(cls):
        return FirewallPluginBase

    def update_attributes_map(self, attributes):
        super(Firewall, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class FirewallPluginBase(service_base.ServicePluginBase):
    def get_plugin_name(self):
        return p_const.FIREWALL

    def get_plugin_type(self):
        return p_const.FIREWALL

    def get_plugin_description(self):
        return 'Firewall service plugin'

    @abc.abstractmethod
    def get_firewalls(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_firewall(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_firewall(self, context, firewall):
        pass

    @abc.abstractmethod
    def update_firewall(self, context, id, firewall):
        pass

    @abc.abstractmethod
    def delete_firewall(self, context, id):
        pass

    @abc.abstractmethod
    def get_firewall_rules(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_firewall_rule(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_firewall_rule(self, context, firewall_rule):
        pass

    @abc.abstractmethod
    def create_security_area(self, context, security_area):
        pass

    @abc.abstractmethod
    def update_firewall_rule(self, context, id, firewall_rule):
        pass

    @abc.abstractmethod
    def delete_firewall_rule(self, context, id):
        pass

    @abc.abstractmethod
    def get_firewall_policy(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_firewall_policies(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def create_firewall_policy(self, context, firewall_policy):
        pass

    @abc.abstractmethod
    def update_firewall_policy(self, context, id, firewall_policy):
        pass

    @abc.abstractmethod
    def delete_firewall_policy(self, context, id):
        pass

    @abc.abstractmethod
    def insert_rule(self, context, id, rule_info):
        pass

    @abc.abstractmethod
    def remove_rule(self, context, id, rule_info):
        pass

    @abc.abstractmethod
    def delete_firewall_security_area(self, context, id, rule_info):
        pass