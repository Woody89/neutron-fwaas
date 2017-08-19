from neutron.agent import rpc as agent_rpc
from oslo_log import log as logging
from oslo_log import helpers as log_helpers
from neutron.i18n import _LE
from neutron_fwaas.services.firewall.agents import firewall_agent_api as api
from neutron import manager
from neutron.plugins.common import constants as consts
from neutron_fwaas.services.firewall.agents import firewall_service
from neutron.common import topics
from socket import getfqdn
from neutron_fwaas.services.firewall.plugins.hf_dp import constants as f_consts
from neutron import context as ncontext
from oslo_service import loopingcall
import oslo_messaging

LOG = logging.getLogger(__name__)

OPTS = []


class RpcCallBack(api.FWaaSPluginApiMixin):

    def __init__(self, topic=None, host=None):
        super(
            RpcCallBack,
            self).__init__(
            topic=topics.FIREWALL_PLUGIN,
            host=host)

    def set_insert_rule(self, context, firewall_id, status, rule):
        """Make a RPC to set the status of a
        firewall and set_rule if remove."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'set_insert_rule',
                          firewall_id=firewall_id, status=status, rule=rule)

    def set_remove_rule(self, context, firewall_id, status, rule):
        """Make a RPC to set the status of a
        firewall and set_rule if remove."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'set_remove_rule',
                          firewall_id=firewall_id, status=status, rule=rule)


class FwaasAgentManager(manager.Manager):
    target = oslo_messaging.Target(version="1.0")

    def __init__(self, host):
        LOG.debug("Initializing firewall agent")
        self.host = host
        self.context = ncontext.get_admin_context_without_session()
        fw_service = firewall_service.FirewallService()
        self.driver = fw_service.load_device_drivers()
        self.plugin_rpc = RpcCallBack()
        self.agent_state = {
            'binary': 'neutron-fwass-agent',
            'host': getfqdn(),
            'topic': f_consts.FIREWALL_AGENT,
            'configurations': {'device_drivers': "dptech"},
            'agent_type': f_consts.AGENT_TYPE,
            'start_flag': True}
        self.admin_state_up = True

        self._setup_state_rpc()
        self.needs_resync = False
        # pool_id->device_driver_name mapping used to store known instances
        self.instance_mapping = {}
        super(FwaasAgentManager, self).__init__()

    def _reload_driver(self):
        fw_service = firewall_service.FirewallService()
        self.driver = fw_service.load_device_drivers()

    @log_helpers.log_method_call
    def create_addr(self, context, addr, host=None):
        it_error = False
        try:
            ret = self.driver.create_addrobj(context, addr)
        except Exception as e:
            LOG.exception(
                _LE("The Create addr is wrong, %s"), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    def update_firewall(self, context, **kwargs):
        pass

    @log_helpers.log_method_call
    def delete_addr(self, context, addr, host=None):
        it_error = False
        try:
            ret = self.driver.delete_addrobj(context, addr)
        except Exception as e:
            LOG.exception(
                _LE("The Delete addr is wrong, %s"), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    @log_helpers.log_method_call
    def create_vlan(self, context, vlan, host=None):
        it_error = False
        try:
            ret = self.driver.create_vlan(context, vlan)
        except Exception as e:
            LOG.exception(
                _LE("The create vlan is wrong, %s"), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    @log_helpers.log_method_call
    def delete_vlan(self, context, vlan, host=None):
        it_error = False
        try:
            ret = self.driver.delete_vlan(context, vlan)
        except Exception as e:
            LOG.exception(
                _LE("The Delete vlan is wrong, %s"), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    @log_helpers.log_method_call
    def create_vrf(self, context, vrf, host=None):
        it_error = False
        try:
            ret = self.driver.create_vrf(context, vrf)
        except Exception as e:
            LOG.exception(
                _LE("The create vrf is wrong, %s"), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    @log_helpers.log_method_call
    def delete_vrf(self, context, vrf, host=None):
        it_error = False
        try:
            ret = self.driver.delete_vrf(context, vrf)
        except Exception as e:
            LOG.exception(
                _LE("The Delete vrf is wrong, %s"), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    @log_helpers.log_method_call
    def create_zone(self, context, zone, host=None):
        it_error = False
        try:
            ret = self.driver.create_zone(context, zone)
        except Exception as e:
            LOG.exception(
                _LE("The create zone is wrong, %s"), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    @log_helpers.log_method_call
    def create_vfw(self, context, vsys, host=None):
        it_error = False
        try:
            ret = self.driver.create_vfw(context, vsys)
        except Exception as e:
            LOG.exception(
                _LE("The create vsys is wrong, %s"), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    @log_helpers.log_method_call
    def delete_vfw(self, context, vsys, host=None):
        it_error = False
        try:
            ret = self.driver.delete_vfw(context, vsys)
        except Exception as e:
            LOG.exception(
                _LE("The Delete vsys is wrong, %s"), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    @log_helpers.log_method_call
    def create_service(self, context, service, host=None):
        it_error = False
        try:
            ret = self.driver.create_netservice(context, service)
        except Exception as e:
            LOG.exception(
                _LE("The Create service is wrong, %s"), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    @log_helpers.log_method_call
    def delete_service(self, context, service, host=None):
        it_error = False
        try:
            ret = self.driver.delete_netservice(context, service)
        except Exception as e:
            LOG.exception(
                _LE("The Delete service is wrong, %s"), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    @log_helpers.log_method_call
    def create_timer(self, context, timer, host=None):
        it_error = False
        try:
            ret = self.driver.create_timer(context, timer)
        except Exception as e:
            LOG.exception(
                _LE("The Create timer is wrong, %s"), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    @log_helpers.log_method_call
    def delete_timer(self, context, timer, host=None):
        it_error = False
        try:
            ret = self.driver.delete_timer(context, timer)
        except Exception as e:
            LOG.exception(
                _LE("The Delete timer is wrong, %s"), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    @log_helpers.log_method_call
    def insert_rule(self, context, rule, host=None):
        ret = False
        it_error = False
        try:
            if rule.get("longSession") == "1":
                rule['action'] = "2"
            ret = self.driver.create_packetfilter(context, rule)
            if rule['targetName'] != "":
                rule['moveName'] = rule['name']
                ret = self.driver.modPriority_packetfilter(context, rule)
        except Exception as e:
            if ret:
                self.driver.delete_packetfilter(context, rule)
            LOG.exception(
                _LE("The Insert rule is wrong in ,%s"), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    @log_helpers.log_method_call
    def update_rule(self, context, rule, host=None):
        it_error = False
        try:
            if rule.get("longSession") == "1":
                rule['action'] = "2"
            ret = self.driver.update_packetfilter(context, rule)
            # if rule['targetName'] != "":
            #     rule['moveName'] = rule['name']
            #     ret = self.driver.modPriority_packetfilter(context, rule)
        except Exception as e:
            LOG.exception(
                _LE("The Insert rule is wrong in ,%s"), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    @log_helpers.log_method_call
    def remove_rule(self, context, packetfilter, host=None):
        it_error = False
        try:
            ret = self.driver.delete_packetfilter(context, packetfilter)
        except Exception as e:
            LOG.exception(
                _LE("The Delete packetfilter is wrong, %s"), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    @log_helpers.log_method_call
    def delete_rule(self, context, rule, host=None):
        it_error = False
        try:
            self.driver_delete_rule(context, rule)
        except Exception as e:
            ret = LOG.exception(
                _LE("The Delete rule is wrong, %s"), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    @log_helpers.log_method_call
    def delete_zone(self, context, security_area, host=None):
        it_error = False
        try:
            ret = self.driver.delete_zone(context, security_area)
        except Exception as e:
            LOG.exception(
                _LE("The Delete security_area is wrong, %s"), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    @log_helpers.log_method_call
    def update_vrf(self, context, vrf, host=None):
        it_error = False
        try:
            ret = self.driver.update_vrf(context, vrf)
        except Exception as e:
            LOG.exception(
                _LE('The Update vrfs is wrong, s%'), e)
            it_error = self._pares_fail(e)
        if it_error:
            return it_error
        else:
            return self._parse_success(ret)

    def _pares_fail(self, error_msg):
        return {"status": consts.ERROR, "msg": str(error_msg)}

    def _parse_success(self, ret_msg):
        return {"status": consts.CREATED, "msg": str(ret_msg)}

    def _update_status(self, obj, error):
        pass

    def _parse_status(self, e):
        pass

    def _log_error(self, func_name, error_message):
        pass

    def _setup_state_rpc(self):
        self.state_rpc = agent_rpc.PluginReportStateAPI(
            topics.FIREWALL_PLUGIN)
        report_interval = 30
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

    def _report_state(self):
        try:
            instance_count = len(self.instance_mapping)
            self.agent_state['configurations']['instances'] = instance_count
            self.state_rpc.report_state(self.context, self.agent_state)
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_LE("Failed reporting state!"))
