from oslo_config import cfg
from oslo_log import log as logging
from neutron_fwaas.services.firewall.drivers.dptech import driver_client
from neutron_fwaas.services.firewall.drivers.dptech.driver_param \
    import dp_links, dp_params
from oslo_log import helpers as log_helpers
import sys

CONF = cfg.CONF
LOG = logging.getLogger(__name__)
FW_DRIVER = None

reload(sys)
sys.setdefaultencoding("utf-8")


class Driver(object):

    def __init__(self):
        self.ws_client = driver_client.Client.get_instance()
        self.LOG = LOG

    @classmethod
    def get_instance(cls):
        global FW_DRIVER
        if not FW_DRIVER:
            FW_DRIVER = cls()
        return FW_DRIVER

    @log_helpers.log_method_call
    def create_vlan(self, context, params):
        url = dp_links['vlan']
        service = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, 'create_vlan')
        try:
            response = service.addVlan(**params)
        except Exception:
            raise
        return response

    @log_helpers.log_method_call
    def delete_vlan(self, context, params):
        url = dp_links['vlan']
        service = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, 'delete_vlan')
        try:
            response = service.delVlan(**params)
        except Exception as e:
            raise e
        return response

    @log_helpers.log_method_call
    def create_netservice(self, context, params):
        """  creat netservice to webservice  """
        url = dp_links['service']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "create_netservice")
        try:
            response = client.addService(**params)
        except Exception:
            raise
        return response

    @log_helpers.log_method_call
    def update_netservice(self, context, params):
        """
        :param context:
        :param param_dic:
        :return:
        """
        url = dp_links['service']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "update_netservice")
        try:
            response = client.modService(**params)
        except Exception:
            raise
        return response

    @log_helpers.log_method_call
    def delete_netservice(self, context, params):
        """  delete netservice to webservice  """
        url = dp_links['service']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "delete_netservice")
        try:
            response = client.delService(**params)
        except Exception:
            raise
        return response

    # this is a addrobj operation
    @log_helpers.log_method_call
    def create_addrobj(self, context, params):
        """  create addrobj to webservice  """
        url = dp_links['addr']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "create_addrobj")
        try:
            response = client.addAddrObj(**params)
        except Exception:
            raise
        return response

    @log_helpers.log_method_call
    def update_addrobj(self, context, params):
        url = dp_links['addr']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "update_addrobj")
        try:
            response = client.modAddrObj(**params)
        except Exception:
            raise
        return response

    @log_helpers.log_method_call
    def delete_addrobj(self, context, params):
        """  delete addrobj to webservice  """
        url = dp_links['addr']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "delete_addrobj")
        try:
            response = client.delAddrObj(**params)
        except Exception as e:
            raise e
        return response

    @log_helpers.log_method_call
    def create_packetfilter(self, context, params):
        """create packetfilter"""
        url = dp_links['packetfilter']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "create_packetfilter")
        try:
            #the end without timeobj
            # response = client.addPacketFilter(**params)

            # the end with timeobj
            response = client.addHFBankPacketFilter(**params)

            # the first with timeobj
            # response = client.insertPacketFilterFirst(**params)
        except Exception as e:
            raise e
        return response

    @log_helpers.log_method_call
    def update_packetfilter(self, context, params):
        """
        :param context:
        :param param_dic:
        :return:
        """
        url = dp_links['packetfilter']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "update_packetfilter")
        try:
            # response = client.modPacketFilter(**params)
            response = client.modHFBankPacketFilter(**params)
        except Exception as e:
            raise e
        return response

    @log_helpers.log_method_call
    def delete_packetfilter(self, context, params):
        """delete packetfilter"""
        url = dp_links['packetfilter']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "delete_packetfilter")
        try:
            response = client.delPacketFilter(**params)
        except Exception as e:
            raise e
        return response

    @log_helpers.log_method_call
    def modPriority_packetfilter(self, context, params):
        url = dp_links['packetfilter']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "modPriority_packetfilter")
        try:
            response = client.modPriorityPacketFilter(**params)
        except:
            raise
        return response

    @log_helpers.log_method_call
    def create_zone(self, context, params):
        """create securityZone"""
        url = dp_links['zone']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "create_zone")
        try:
            response = client.addZone(**params)
        except Exception as e:
            raise e
        return response

    @log_helpers.log_method_call
    def delete_zone(self, context, params):
        """delete SecurityZone"""
        url = dp_links['zone']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "delete_zone")
        try:
            response = client.delZone(**params)
        except Exception as e:
            raise e
        return response

    @log_helpers.log_method_call
    def update_zone(self, context, params):
        url = dp_links['zone']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "update_zone")
        try:
            response = client.modZone(**params)
        except Exception as e:
            raise e
        return response

    @log_helpers.log_method_call
    def create_vfw(self, context, params):
        # create vfw
        url = dp_links['vfw']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "create_vfw")
        try:
            response = client.addNewVsys(**params)
        except Exception:
            raise
        return response

    @log_helpers.log_method_call
    def update_vfw(self, context, params):
        url = dp_links['vfw']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "create_vfw")
        try:
            response = client.updateVsys(**params)
        except Exception:
            raise
        return response

    @log_helpers.log_method_call
    def delete_vfw(self, context, params):
        url = dp_links['vfw']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "delete_vfw")
        try:
            response = client.delVsys(**params)
        except Exception:
            raise
        return response

    @log_helpers.log_method_call
    def create_vrf(self, context, params):
        # create vrf
        url = dp_links['vrf']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "create_vrf")
        try:
            response = client.addNewVRF(**params)
        except Exception:
            raise
        return response

    @log_helpers.log_method_call
    def update_vrf(self, context, params):
        """
        update vrf
        :param context:
        :param param_dic:
        :return:
        """
        url = dp_links['vrf']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "update_vrf")
        try:
            response = client.updateVRF(**params)
        except Exception:
            raise
        return response

    @log_helpers.log_method_call
    def delete_vrf(self, context, params):
        # delete vrf
        url = dp_links['vrf']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "delete_vrf")
        try:
            response = client.delVRF(**params)
        except Exception:
            raise
        return response

    @log_helpers.log_method_call
    def create_timer(self, context, params):
        url = dp_links['timer']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "create_timer")
        # params['name'] = "204b73baddb34ab2b26d9b9b17a01179"
        # params['endDay'] = "2027-07-02"
        # params['week'] = ''
        try:
            response = client.addTimeObjectApi(params)
        except:
            raise
        return response

    @log_helpers.log_method_call
    def udpate_timer(self, context, params):
        url = dp_links['timer']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "update_timer")
        try:
            response = client.modTimeObjectApi(**params)
        except:
            raise
        return response

    @log_helpers.log_method_call
    def delete_timer(self, context, params):
        url = dp_links['timer']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "delete_timer")
        try:
            response = client.delTimeObjectApi(**params)
        except:
            raise
        return response

    @log_helpers.log_method_call
    def create_router(self, context, params):
        url = dp_links['router']
        client = self.ws_client.get_client(url, params.get("host"))
        params = self._filter_params(params, "create_router")
        try:
            response = client.addRoute(params)
        except:
            raise
        return response

    def _filter_params(self, params, func_name):
        fields = dp_params[func_name]
        for key in params.keys():
            if key in fields:
                fields[key] = params[key]
        return fields

# if __name__ == '__main__':
#     driver = Driver.get_instance()
#     params = {
#         "id": "123",
#         "vsysName": "5656",
#         "resource": "HF_BIZ2",
#         "ipMask": "192.168.100.2/32",
#         "gateway": "192.168.100.1",
#         "interface": "tengige0_2"
#     }
#     driver.create_router(context={}, params=params)