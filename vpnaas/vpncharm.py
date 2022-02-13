# Addition to Python code for the Juju proxy charm to implement WireGuard as a VPN-as-a-service.
#Must be combined with the descriptor files in the vpnaas folder to work.


import logging
from time import sleep
from random import randint

logger = logging.getLogger(__name__)


class HSSProxyCharm(SSHProxyCharm):

    def __init__(self, framework, key):
        # WireGuard application
        self.framework.observe(self.on.generatekeys_action, self.on_generatekeys_action)
        self.framework.observe(self.on.generatewgconfig_action, self.on_generateconfig_action)
        self.framework.observe(self.on.wgup_action, self.on_wireguardup_action)
        self.framework.observe(self.on.wgaddpeer_action, self.on_addpeer_action)
        self.framework.observe(self.on.wgdelpeer_action, self.on_delpeer_action)
        self.framework.observe(self.on.wgrestart_action, self.on_wgrestart_action)
        self.framework.observe(self.on.interface_relation_changed, self._on_interface_relation_changed)

        
        
    # WireGuard requirer config
    def on_generatekeys_action(self, event):
        err = ''
        result = ''
        wgifname = ''
        try:
            wgifname = event.params['wg-interface']
        except:
            wgifname = "wg0"
        try:
            proxy = self.get_ssh_proxy()
            cmd = ['sudo test -f /etc/wireguard/publickey{} && echo "$FILE exists."'.format(wgifname)]
            result, err = proxy.run(cmd)
        except:
            pass
        if len(result) > 5:
            event.set_results({'outout': result})
        else:
            try:
                proxy = self.get_ssh_proxy()
                cmd = ['wg genkey | sudo tee /etc/wireguard/privatekey{} | wg pubkey | sudo tee /etc/wireguard/publickey{}'.format(wgifname, wgifname)]
                result, err = proxy.run(cmd)
                event.set_results({'outout': result})
            except:
                event.fail('command failed:' + err)

    def on_generateconfig_action(self, event):
        err = ''
        try:
            proxy = self.get_ssh_proxy()
            gateway_ip = ''
            try:
                gateway_ip = event.params['gateway-ip']
                if not gateway_ip:
                    gateway_ip = self.model.config["ssh-hostname"]
            except:
                    gateway_ip = self.model.config["ssh-hostname"]                
            wgifname = ''
            listenport = ''
            try:
                wgifname = event.params['wg-interface']
            except:
                wgifname = "wg0"              
            try:
                listenport = event.params['listenport']
            except:
                listenport = "51820"              
            subnet_of_tunnel = event.params['tunnel-subnet']
            endpoint = event.params['endpoint']
            cmd = ['echo -e "[Interface]\nAddress = {}\nListenPort = {}\nPrivatekey = $(sudo cat /etc/wireguard/privatekey{})" | sudo tee -a /etc/wireguard/{}.conf'.format(endpoint, listenport, wgifname, wgifname)]
            result, err = proxy.run(cmd)
            cmd = ['echo -e "{}" | sudo tee /etc/wireguard/gateway_ip{}'.format(gateway_ip, wgifname)]
            result, err = proxy.run(cmd)
            cmd = ['echo -e "{}" | sudo tee /etc/wireguard/subnet{}'.format(subnet_of_tunnel, wgifname)]
            result, err = proxy.run(cmd)
            cmd = ['echo -e "{}" | sudo tee /etc/wireguard/listenport{}'.format(listenport, wgifname)]
            result, err = proxy.run(cmd)

            event.set_results({'outout': result})
        except:
            event.fail('command failed:' + err)

    def on_wireguardup_action(self, event):
        err = ''
        wgifname = ''
        try:
            wgifname = event.params['wg-interface']
        except:
            wgifname = "wg0"              
        try:
            proxy = self.get_ssh_proxy()
            cmd = ['sudo wg-quick up {}'.format(wgifname)]
            result, err = proxy.run(cmd)
            event.set_results({'outout': result})
        except:
            event.fail('command failed:' + err)

    def on_addpeer_action(self, event):
        err = ''
        try:
            proxy = self.get_ssh_proxy()
            if self.model.unit.is_leader():
                peer_public_key = event.params['peer-publickey']
                gateway_ip = self.model.config["ssh-hostname"]
                subnet_behind_tunnel = event.params['subnet-behind-tunnel']
                wgifname = ''
                listenport = ''
                try:
                    wgifname = event.params['wg-interface']
                except:
                    wgifname = "wg0"    
                try:
                    listenport = event.params['listenport']
                except:
                    listenport = "51820"              
                public_endpoint = event.params['public-endpoint']
                cmd = ['sudo wg set {} peer {} allowed-ips {},{} endpoint {}:{} persistent-keepalive 25'.format(wgifname, peer_public_key, gateway_ip,subnet_behind_tunnel,public_endpoint, listenport)]
                result, err = proxy.run(cmd)
                cmd = ['sudo ip -4 route add {} dev {}'.format(gateway_ip, wgifname)]
                result, err = proxy.run(cmd)
                cmd = ['sudo ip -4 route add {} dev {}'.format(subnet_behind_tunnel, wgifname)]
                result, err = proxy.run(cmd)
                cmd = ['sudo wg-quick save {}'.format(wgifname)]
                result, err = proxy.run(cmd)
                event.set_results({'outout': result})
        except:
            event.fail('command failed:' + err)
        else:
            event.fail("Unit is not leader")

    def on_delpeer_action(self, event):
        err = ''
        try:
            proxy = self.get_ssh_proxy()
            peer_public_key = event.params['peer-publickey']
            subnet_behind_tunnel = event.params['subnet-behind-tunnel']
            wgifname = ''
            try:
                wgifname = event.params['wg-interface']
            except:
                wgifname = "wg0"              
            cmd = ['sudo wg set {} peer {} remove'.format(wgifname, peer_public_key)]
            result, err = proxy.run(cmd)
            cmd = ['sudo ip -4 route del {} dev {}'.format(subnet_behind_tunnel, wgifname)]
            result, err = proxy.run(cmd)
            cmd = ['sudo wg-quick save {}'.format(wgifname)]
            result, err = proxy.run(cmd)
            event.set_results({'outout': result})
        except:
            event.fail('command failed:' + err)
    
    def on_wgrestart_action(self, event):
        err = ''
        try:
            proxy = self.get_ssh_proxy()
            wgifname = ''
            try:
                wgifname = event.params['wg-interface']
            except:
                wgifname = "wg0"              
            try:
                cmd = ['sudo systemctl restart wg-quick@{}.service'.format(wgifname)]
                result, err = proxy.run(cmd)
            except:
                cmd = ['sudo wg-quick down {}'.format(wgifname)]
                result, err = proxy.run(cmd)
                cmd = ['sudo wg-quick start {}'.format(wgifname)]
                result, err = proxy.run(cmd)
                event.set_results({'restarted wg0': result})
        except:
            event.fail('command failed:' + err)


    def _on_interface_relation_changed(self, event): # change to correct juju interface name
        # INPUT correct wireguard interface name:
        wgifname = "wg0"
        self.wgrelation(event, wgifname)
        
    def wgrelation(self, event, wgifname):
        #logger.debug("RELATION DATA: {}".format(dict(event.relation.data[event.unit])))
        #parameter = event.relation.data[event.unit].get("parameter")
        #if parameter:
        #    self.model.unit.status = ActiveStatus("Parameter received: {}".format(parameter))
        proxy = False
        proxypass = False
        try:
            proxy = self.get_ssh_proxy()
            proxypass = True
        except:
            sleep(5)
            c = randint(1,10000)
            event.relation.data[self.model.unit]["counter"] = str(c)
            proxypass = False
        if proxypass:
            err = ''
            result = ''
            readyint = 0
            sshready = event.relation.data[event.unit].get("wg-ready")
            sshready_unit = event.relation.data[self.unit].get("wg-ready")
            if not sshready:
                sshready = "False"
            if not sshready_unit:
                sshready_unit = "False"
            peered = event.relation.data[self.model.unit].get("wg-peered")
            if not peered:
                peered = "False"
            if "True" not in sshready or "True" not in peered or "True" not in sshready_unit:
                c = randint(1,10000)
                event.relation.data[self.model.unit]["counter"] = str(c)
                result = ''

                leader_pubkey = event.relation.data[event.unit].get("wg-pubkey")
                leader_listenport = event.relation.data[event.unit].get("wg-listenport")
                leader_gwip = event.relation.data[event.unit].get("wg-gwip")
                leader_subnet = event.relation.data[event.unit].get("wg-subnet")
                if not peered:
                    peered = "False"
                if leader_pubkey and leader_gwip and leader_subnet and leader_listenport:
                    if "True" not in peered:
                        proxy = self.get_ssh_proxy()
                        cmd = ['echo -e "[Peer]\nPublicKey = {}\nAllowedIPs = {}\nEndpoint = {}:{}" | sudo tee -a /etc/wireguard/{}.conf'.format(leader_pubkey, leader_subnet, leader_gwip, str(leader_listenport), wgifname)]
                        result, err = proxy.run(cmd)
                        event.relation.data[self.model.unit]["wg-peered"] = "True"
                        try:
                            cmd = ['sudo wg-quick down {}'.format(wgifname)]
                            result, err = proxy.run(cmd)
                            cmd = ['sudo systemctl start wg-quick@{}.service'.format(wgifname)]
                            result, err = proxy.run(cmd)
                        except:
                            pass
                        #event.relation.data[self.unit].update({"wg-peered": "True"})

                # send pubkey and other variables back to leader
                result = ''
                try:
                    cmd = ['sudo test -f /etc/wireguard/publickey{} && echo "$FILE present"'.format(wgifname)]
                    result, err = proxy.run(cmd)
                except:
                    event.relation.data[self.unit].update({"relation-joined": "failed1"})
                if len(result) > 5:
                    #try:
                    cmd = ['sudo cat /etc/wireguard/publickey{}'.format(wgifname)]
                    result, err = proxy.run(cmd)
                    readyint += 1
                    event.relation.data[self.model.unit]["wg-pubkey"] = result
                    #event.relation.data[self.unit].update({"wgpeer-pubkey": result})
                    #except:
                    #    event.relation.data[self.unit].update({"relation-joined": "failed2"})
                else:
                    try:
                        cmd = ['wg genkey | sudo tee /etc/wireguard/privatekey{} | wg pubkey | sudo tee /etc/wireguard/publickey{}'.format(wgifname, wgifname)]
                        result, err = proxy.run(cmd)
                        cmd = ['sudo cat /etc/wireguard/publickey{}'.format(wgifname)]
                        result, err = proxy.run(cmd)
                        readyint += 1
                        event.relation.data[self.model.unit]["wg-pubkey"] =     result
                    except:
                        pass
                    #event.relation.data[self.unit].update({"wgpeer-pubkey": result})
                    #event.relation.data[self.unit].update({"ready": "True"})
                result = ''
                try:
                    cmd = ['sudo test -f /etc/wireguard/gateway_ip{} && echo "$FILE present"'.format(wgifname)]
                    result, err = proxy.run(cmd)
                except:
                    pass
                if len(result) > 5:
                    cmd = ['sudo cat /etc/wireguard/gateway_ip{}'.format(wgifname)]
                    result, err = proxy.run(cmd)
                    event.relation.data[self.model.unit]["wg-gwip"] =     result
                    #event.relation.data[self.unit].update({"wgpeer-gwip": result})
                    readyint += 1
                result = ''
                try:
                    cmd = ['sudo test -f /etc/wireguard/subnet{} && echo "$FILE present"'.format(wgifname)]
                    result, err = proxy.run(cmd)
                except:
                    pass
                if len(result) > 5:
                    cmd = ['sudo cat /etc/wireguard/subnet{}'.format(wgifname)]
                    result, err = proxy.run(cmd)
                    event.relation.data[self.model.unit]["wg-subnet"] =     result
                    #event.relation.data[self.unit].update({"wgpeer-subnet": result})
                    readyint += 1
                    #if readyint >= 3:
                    #    event.relation.data[self.unit].update({"ready": "True"})
                else:
                    pass
                result = ''
                try:
                    cmd = ['sudo test -f /etc/wireguard/listenport{} && echo "$FILE present"'.format(wgifname)]
                    result, err = proxy.run(cmd)
                except:
                    pass
                if len(result) > 5:
                    cmd = ['sudo cat /etc/wireguard/listenport{}'.format(wgifname)]
                    result, err = proxy.run(cmd)
                    event.relation.data[self.model.unit]["wg-listenport"] =     result
                    #event.relation.data[self.unit].update({"wgpeer-listenport": result})
                    readyint += 1
                if readyint >= 4 and "True" in peered:
                    event.relation.data[self.model.unit]["wg-ready"] = "True"
                    cmd = ['sudo wg-quick down {}'.format(wgifname)]
                    result, err = proxy.run(cmd)
                    cmd = ['sudo wg-quick up {}'.format(wgifname)]
                    result, err = proxy.run(cmd)



