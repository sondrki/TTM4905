#!/usr/bin/env python3
import sys

sys.path.append("lib")

from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import (
    ActiveStatus,
    BlockedStatus,
    MaintenanceStatus,
    WaitingStatus,
    ModelError,
)
import os
import subprocess




def install_dependencies():
    # Make sure Python3 + PIP are available
    if not os.path.exists("/usr/bin/python3") or not os.path.exists("/usr/bin/pip3"):
        # This is needed when running as a k8s charm, as the ubuntu:latest
        # image doesn't include either package.

        # Update the apt cache
        subprocess.check_call(["apt-get", "update"])

        # Install the Python3 package
        subprocess.check_call(["apt-get", "install", "-y", "python3", "python3-pip"],)


    # Install the build dependencies for our requirements (paramiko)
    subprocess.check_call(["apt-get", "install", "-y", "libffi-dev", "libssl-dev"],)

    subprocess.check_call(["pip3", "install", "packaging"],)

    #REQUIREMENTS_TXT = "{}/requirements.txt".format(os.environ["JUJU_CHARM_DIR"])
    #if os.path.exists(REQUIREMENTS_TXT):
    #    subprocess.check_call(
    #        ["apt-get", "install", "-y", "python3-paramiko", "openssh-client"],
    #    )


try:
    from charms.osm.sshproxy import SSHProxyCharm
except Exception as ex:
    install_dependencies()
    from charms.osm.sshproxy import SSHProxyCharm
from ops.main import main

#if not SSHProxyCharm.has_ssh_key():
#    # Generate SSH Key
#    SSHProxyCharm.generate_ssh_key()


class MySSHProxyCharm(SSHProxyCharm):

    def __init__(self, framework, key):
        super().__init__(framework, key)

        # Listen to charm events
        self.framework.observe(self.on.config_changed, self.on_config_changed)
        self.framework.observe(self.on.install, self.on_install)
        self.framework.observe(self.on.start, self.on_start)

        # Listen to the test action event
        self.framework.observe(self.on.test_action, self.on_test_action)
        self.framework.observe(self.on.wgconfig_action, self.on_touch_action)
        self.framework.observe(self.on.generatekeys_action, self.on_generatekeys_action)
        self.framework.observe(self.on.generatewgconfig_action, self.on_generateconfig_action)
        self.framework.observe(self.on.wgup_action, self.on_wireguardup_action)
        self.framework.observe(self.on.wgaddpeer_action, self.on_addpeer_action)
        self.framework.observe(self.on.wgdelpeer_action, self.on_delpeer_action)

    def on_config_changed(self, event):
        """Handle changes in configuration"""
        super().on_config_changed(event)

    def on_install(self, event):
        """Called when the charm is being installed"""
        super().on_install(event)

    def on_start(self, event):
        """Called when the charm is being started"""
        super().on_start(event)

    def on_test_action(self, event):
        """Touch a file."""

        if self.model.unit.is_leader():
            stderr = None
            try:
                cmd = "touch /home/ubuntu/charm"
                proxy = self.get_ssh_proxy()
                stdout, stderr = proxy.run(cmd)
                gateway_ip = self.model.config["ssh-hostname"]
                cmd = ['echo -e {} >> /home/ubuntu/charm'.format(gateway_ip)]
                event.set_results({"output": stdout})
            except Exception as e:
                event.fail("Action failed {}. Stderr: {}".format(e, stderr))
        else:
            event.fail("Unit is not leader")
    
    def on_touch_action(self, event):
        #super().on_config(event)

        err = ''
        try:
            proxy = self.get_ssh_proxy()
            filename = event.params['filename']
            cmd = ['touch {}'.format(filename)]
            result, err = proxy.run(cmd)
            cmd = ['sudo sysctl -w net.ipv4.ip_forward=1']
            result, err = proxy.run(cmd)
            cmd = ['sudo sysctl -w net.ipv4.conf.all.proxy_arp=1']
            result, err = proxy.run(cmd)
            cmd = ['sudo ip link set ens4 up']
            result, err = proxy.run(cmd)
            #cmd = ['sudo ip link set ens5 up']
            #result, err = proxy.run(cmd)
            cmd = ['sudo netplan apply']
            result, err = proxy.run(cmd)
            event.set_results({'outout': result})

        except:
            event.fail('command failed:' + err)
    
    def on_generatekeys_action(self, event):
        err = ''
        try:
            proxy = self.get_ssh_proxy()
            cmd = ['wg genkey | sudo tee /etc/wireguard/privatekey | wg pubkey | sudo tee /etc/wireguard/publickey']
            result, err = proxy.run(cmd)
            event.set_results({'outout': result})
        except:
            event.fail('command failed:' + err)

    def on_generateconfig_action(self, event):
        err = ''
        try:
            #if self.model.unit.is_leader():
            proxy = self.get_ssh_proxy()
            gateway_ip = self.model.config["ssh-hostname"]
            cmd = ['echo -e "[Interface]\nAddress = {}\nListenPort = 51820\nPrivatekey = $(sudo cat /etc/wireguard/privatekey)" | sudo tee /etc/wireguard/wg0.conf'.format(gateway_ip)]
            result, err = proxy.run(cmd)
            event.set_results({'outout': result})
        except:
            event.fail('command failed:' + err)
        #else:
        #    event.fail("Unit is not leader")

    def on_wireguardup_action(self, event):
        err = ''
        try:
            proxy = self.get_ssh_proxy()
            cmd = ['sudo wg-quick up wg0']
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
                public_endpoint = event.params['public-endpoint']
                cmd = ['sudo wg set wg0 peer {} allowed-ips {},{} endpoint{}:51820 persistent-keepalive 25'.format(peer_public_key, gateway_ip,subnet_behind_tunnel,public_endpoint)]
                result, err = proxy.run(cmd)
                cmd = ['sudo ip -4 route add {} dev wg0'.format(gateway_ip)]
                result, err = proxy.run(cmd)
                cmd = ['sudo ip -4 route add {} dev wg0'.format(subnet_behind_tunnel)]
                result, err = proxy.run(cmd)
                cmd = ['sudo wg-quick save wg0']
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
            cmd = ['sudo wg set wg0 peer {} remove'.format(peer_public_key)]
            result, err = proxy.run(cmd)
            cmd = ['sudo ip -4 route del {} dev wg0'.format(subnet_behind_tunnel)]
            result, err = proxy.run(cmd)
            cmd = ['sudo wg-quick save wg0']
            result, err = proxy.run(cmd)
            event.set_results({'outout': result})
        except:
            event.fail('command failed:' + err)

if __name__ == "__main__":
    main(MySSHProxyCharm)



#if __name__ == "__main__":
#    main(SimpleProxyCharm)


#if __name__ == "__main__":
#    main(SampleProxyCharm)
