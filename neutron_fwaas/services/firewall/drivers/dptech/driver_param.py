dp_params = {
    "create_vlan": {
        "vlanId": "",
        "ipAddr": "",
        "ifNames": "",
    },
    "delete_vlan": {
        "vlanId": "",
        "ifNames": ""
    },
    "create_vrf": {
        "name": "",
        "ifName": ""
    },
    "update_vrf": {
        "vrfName": "",
        "vrfInterface": ""
    },
    "delete_vrf": {
        "name": ""
    },
    "create_vfw": {
        "name": "",
        "type": "",
        "resource": ""
    },
    "update_vfw": {
        "vsysName": "",
        "vsysType": "",
        "vsysResource": "",
    },
    "delete_vfw": {
        "name": ""
    },
    "create_zone": {
        "name": "",
        "ifNames": "",
        "priority": "",
        "vfwName": ""
    },
    "delete_zone": {
        "name": "",
        "vfwName": ""
    },
    "create_addrobj": {
        "name": "",
        "ip": "",
        "expIp": "",
        "vfwName": ""
    },
    "update_addrobj": {
        "oldname": "",
        "name": "",
        "ip": "",
        "expIp": "",
        "vfwName": ""
    },
    "delete_addrobj": {
        "name": "",
        "vfwName": ""
    },
    "create_netservice": {
        "name": "",
        "proto": "",
        "port": "",
        "vfwName": ""
    },
    "update_netservice": {
        "oldname": "",
        "name": "",
        "proto": "",
        "port": "",
        "vfwName": ""
    },
    "delete_netservice": {
        "name": "",
        "vfwName": ""
    },
    "create_packetfilter": {
        "name": "",
        "srcZoneName": "",
        "dstZoneName": "",
        "srcIpObjNames": "",
        "dstIpObjNames": "",
        "serviceNames": "",
        "action": "",
        "log": "",
        "vfwName": "",
        "longSession": "",
        "timeObjName": ""
    },
    "update_packetfilter": {
        "oldname": "",
        "name": "",
        "srcZoneName": "",
        "dstZoneName": "",
        "srcIpObjNames": "",
        "dstIpObjNames": "",
        "serviceNames": "",
        "action": "",
        "log": "",
        "vfwName": "",
        "longSession": "",
        "timeObjName": ""
    },
    "delete_packetfilter": {
        "name": "",
        "vfwName": ""
    },
    "modPriority_packetfilter": {
        "targetName": "",
        "moveName": "",
        "moveFlag": "",
        "vfwName": ""
    },
    "create_timer": {
        "name": "",
        "vsysName": "",
        "mode": "",
        "week": "",
        "startDay": "",
        "endDay": "",
        "startTime": "",
        "endTime": "",
    },
    "update_timer": {
        "name": "",
        "vsysName": "",
        "mode": "",
        "week": "",
        "startDay": "",
        "endDay": "",
        "startTime": "",
        "endTime": "",
    },
    "delete_timer": {
        "name": "",
        "vsysName": ""
    },
    "create_router": {
        "id": "",
        "vsysName": "",
        "resource": "",
        "ipMask": "",
        "gateway": "",
        "interface": ""
    },
    "update_router": {
        "id": "",
        "vsysName": "",
        "resource": "",
        "ipMask": "",
        "gateway": "",
        "interface": ""
    },
    "delete_router": {
        "id": "",
        "vsysName": ""
    }
}

dp_links = {
    "vlan": "/func/web_main/wsdl/vlan/vlan.wsdl",
    "vrf": "/func/web_main/wsdl/vrf/vrf.wsdl",
    "vfw": "/func/web_main/wsdl/vfw/vfw.wsdl",
    "zone": "/func/web_main/wsdl/security_zone/security_zone.wsdl",
    "addr": "/func/web_main/wsdl/netaddr/netaddr.wsdl",
    "service": "/func/web_main/wsdl/netservice/netservice.wsdl",
    "packetfilter": "/func/web_main/wsdl/pf_policy/pf_policy/pf_policy.wsdl",
    "timer": "/func/web_main/wsdl/time_object/TimeObject.wsdl",
    "router": "/func/web_main/wsdl/zebra/route/zebra/RouteManager.wsdl"
}
