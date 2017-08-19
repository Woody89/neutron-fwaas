import sys
import eventlet
from neutron.agent.common import config
from neutron.common import config as common_config
from neutron.common import rpc as n_rpc
from oslo_config import cfg
from oslo_service import service
from neutron_fwaas.services.firewall.plugins.hf_dp import constants as f_consts
from neutron_fwaas.services.firewall.agents.hf import agent_manager as manager
eventlet.monkey_patch()

OPTS = [
    cfg.IntOpt(
        'periodic_interval',
        default=10,
        help=_('Seconds between periodic task runs')
    )
]


class FwaasAgentService(n_rpc.Service):

    def start(self):
        super(FwaasAgentService, self).start()
        self.tg.add_timer(
            cfg.CONF.periodic_interval,
            self.manager.run_periodic_tasks,
            None,
            None
        )


def main():
    cfg.CONF.register_opts(OPTS)
    cfg.CONF.register_opts(manager.OPTS)
    config.register_agent_state_opts_helper(cfg.CONF)
    common_config.init(sys.argv[1:])
    config.setup_logging()
    mgr = manager.FwaasAgentManager(cfg.CONF)
    svc = FwaasAgentService(
        host=cfg.CONF.host,
        topic=f_consts.FIREWALL_AGENT,
        manager=mgr
    )
    service.launch(cfg.CONF, svc).wait()
