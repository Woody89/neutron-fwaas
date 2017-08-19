import sys
from neutron_fwaas.services.firewall.agents.hf import agent as fwaas_agent


def main():
    fwaas_agent.main()

if __name__ == '__main__':
    sys.exit(main())
