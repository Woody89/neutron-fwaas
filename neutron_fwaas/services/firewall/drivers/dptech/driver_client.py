from neutron.i18n import _
from oslo_config import cfg
from zeep import Client as ZeepClient
from requests import Session
from zeep.transports import Transport
from requests.auth import HTTPBasicAuth
import logging
logging.basicConfig(level=logging.INFO)
logging.getLogger('zeep.transports').setLevel(logging.DEBUG)

device_opts = [
    cfg.StrOpt('host',
               default='localhost',
               help=_('The server hostname/ip to connect to.')),
    cfg.StrOpt('username',
               default='admin',
               help=_('The username which use for connect backend '
                      'firewall device')),
    cfg.StrOpt('password',
               default='admin_default',
               help=_('The password which use to connect backend '
                      'firewall device')),
    cfg.StrOpt('protocol',
               default='https',
               help=_("The protocol of request 'http|https'"))
]


device_group = cfg.OptGroup(
    name="device",
    title="device info in the Group"
)

CONF = cfg.CONF
CONF.register_group(device_group)
CONF.register_opts(device_opts, device_group)

ZEEP_CLIENT = None
username = None
password = None


class Client():

    def __init__(self):
        self.host = CONF.device.host
        self.username = CONF.device.username
        self.password = CONF.device.password

    @classmethod
    def get_instance(cls):
        global ZEEP_CLIENT
        if not ZEEP_CLIENT:
            ZEEP_CLIENT = cls()
        return ZEEP_CLIENT

    def get_client(self, url_dir, host_ip, username=None, password=None):
        try:
            if username:
                self.username = username
            if password:
                self.password = password
            if not host_ip:
                host_ip = CONF.device.host
            protocol = CONF.device.protocol
            # host_ip = "192.168.1.234"
            ip_link = protocol + '://%s' % host_ip
            full_url = "%s%s" % (ip_link, url_dir)
            session = Session()
            session.verify = False
            session.auth = HTTPBasicAuth(self.username, self.password)
            transport = Transport(session=session)
            client = ZeepClient(full_url, transport=transport)
            service = client.service
        except Exception as e:
            raise
        return service
