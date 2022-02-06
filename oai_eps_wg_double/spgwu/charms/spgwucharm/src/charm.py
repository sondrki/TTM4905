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

import logging
from time import sleep
from random import randint

logger = logging.getLogger(__name__)



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

    subprocess.check_call(["pip3", "install", "packaging",  "charmhelpers"],)

    # VINNI specific
    subprocess.check_call(["apt-add-repository", "-y", "ppa:dreibh/ppa"],)
    subprocess.check_call(["apt", "update"],)

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


from charmhelpers.core.hookenv import (
    function_get,
    function_fail,
    function_set,
    status_set
)

import subprocess
import sys
import traceback
from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface




class MySSHProxyCharm(SSHProxyCharm):

    def __init__(self, framework, key):
        super().__init__(framework, key)

        # Listen to charm events
        self.framework.observe(self.on.config_changed, self.on_config_changed)
        self.framework.observe(self.on.install, self.on_install)
        self.framework.observe(self.on.start, self.on_start)

        # Listen to the test action event
        #self.framework.observe(self.on.test_action, self.on_test_action)
        #MME actions
        self.framework.observe(self.on.prepare_spgwu_build_action, self.prepare_spgwu_build)
        self.framework.observe(self.on.configure_spgwu_action, self.configure_spgwu)
        self.framework.observe(self.on.restart_spgwu_action, self.restart_spgwu)


        # WireGuard application
        self.framework.observe(self.on.generatekeys_action, self.on_generatekeys_action)
        self.framework.observe(self.on.generatewgconfig_action, self.on_generateconfig_action)
        self.framework.observe(self.on.wgup_action, self.on_wireguardup_action)
        self.framework.observe(self.on.wgaddpeer_action, self.on_addpeer_action)
        self.framework.observe(self.on.wgdelpeer_action, self.on_delpeer_action)
        self.framework.observe(self.on.wgrestart_action, self.on_wgrestart_action)
        self.framework.observe(self.on.interfaces1u_relation_changed, self._on_interfaces1u_relation_changed)
        self.framework.observe(self.on.interfacesxab_relation_changed, self._on_interfacesxab_relation_changed)
        

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
                event.set_results({"output": stdout})
            except Exception as e:
                event.fail("Action failed {}. Stderr: {}".format(e, stderr))
        else:
            event.fail("Unit is not leader")

    def prepare_spgwu_build(self, event):
        from VDUHelper import VDUHelper
        vduHelper = VDUHelper(self)

        # ====== Add repository =======================================
        try:
            vduHelper.beginBlock('Add ppa:dreibh/ppa')
            proxy = self.get_ssh_proxy()
            result = ''
            i = 0
            while i < 15:
                try:
                    cmd = ['sudo fuser /var/lib/dpkg/lock | echo ${PIPESTATUS[0]}']
                    result, err = proxy.run(cmd)
                    cmd1 = ['sudo fuser /var/lib/dpkg/lock-frontend | echo ${PIPESTATUS[0]}']
                    result1, err1 = proxy.run(cmd1)
                except:
                    result = 0
                    result1 = 0
                if int(result) == 1 and int(result1) == 1:
                    i = 16
                else:
                    sleep(60)
                    i+=1
                
                
            vduHelper.executeFromString("""sudo apt-add-repository -y ppa:dreibh/ppa && sudo apt update""")
            vduHelper.endBlock()
        except:
            message = vduHelper.endBlockInException()
            function_fail(message)


        vduHelper.beginBlock('prepare_spgwu_build')
        try:

            # ====== Get SPGW-U parameters ========================================
            # For a documentation of the installation procedure, see:
            # https://github.com/OPENAIRINTERFACE/openair-cn-cups/wiki/OpenAirSoftwareSupport#install-spgw-u

            gitRepository = event.params['spgwu-git-repository']
            gitCommit = event.params['spgwu-git-commit']
            gitDirectory = 'openair-spgwu-tiny'

            loopback    = 'dummy2'
            configurationloopback = vduHelper.makeInterfaceConfiguration(loopback, IPv4Interface('192.168.248.159/32'), createDummy=True)

            loopback2    = 'dummy3'
            configurationloopback2 = vduHelper.makeInterfaceConfiguration(loopback2, IPv4Interface('172.55.55.102/32'), createDummy=True)

            spgwuS1U_IPv4Interface = IPv4Interface(event.params['spgwu-S1U-ipv4-interface'])
            spgwuS1U_IPv4Gateway = IPv4Address(event.params['spgwu-S1U-ipv4-gateway'])

            spgwuSGi_IPv4Interface = IPv4Interface(event.params['spgwu-SGi-ipv4-interface'])
            spgwuSGi_IPv4Gateway = IPv4Address(event.params['spgwu-SGi-ipv4-gateway'])
            if event.params['spgwu-SGi-ipv6-interface'] == '':
                spgwuSGi_IPv6Interface = None
            else:
                spgwuSGi_IPv6Interface = IPv6Interface(event.params['spgwu-SGi-ipv6-interface'])
            if event.params['spgwu-SGi-ipv6-gateway'] == '':
                spgwuSGi_IPv6Gateway = None
            else:
                spgwuSGi_IPv6Gateway = IPv6Address(event.params['spgwu-SGi-ipv6-gateway'])

            # Prepare network configurations:
            spgwuSXab_IfName = 'ens4'
            spgwuS1U_IfName = 'ens5'
            #spgwuS1U_IfName = 'lo:2'
            #spgwuSGi_IfName = 'ens6'
            spgwuSGi_IfName = 'ens6'

            configurationSXab = vduHelper.makeInterfaceConfiguration(spgwuSXab_IfName, IPv4Interface('192.168.16.102/24'),metric=261)
            configurationS1U = vduHelper.makeInterfaceConfiguration(spgwuS1U_IfName, spgwuS1U_IPv4Interface, spgwuS1U_IPv4Gateway, metric=262)
            configurationSGi = vduHelper.makeInterfaceConfiguration(spgwuSGi_IfName, spgwuSGi_IPv4Interface, spgwuSGi_IPv6Interface, metric=260)
            #configurationSGi = vduHelper.makeInterfaceConfiguration(spgwuSGi_IfName, spgwuSGi_IPv4Interface, spgwuSGi_IPv4Gateway, spgwuSGi_IPv6Interface, spgwuSGi_IPv6Gateway, metric=200, pdnInterface='pdn')

            # ====== Prepare system ===============================================
            vduHelper.beginBlock('Preparing system')
            vduHelper.configureInterface(spgwuSXab_IfName, configurationSXab, 61)
            vduHelper.configureInterface(spgwuS1U_IfName, configurationS1U, 62)
            vduHelper.configureInterface(spgwuSGi_IfName, configurationSGi, 63)
            vduHelper.configureInterface(loopback,    configurationloopback, 64)
            vduHelper.configureInterface(loopback2,    configurationloopback2, 65)
            vduHelper.testNetworking()
            vduHelper.waitForPackageUpdatesToComplete()
            vduHelper.endBlock()

            # ====== Prepare sources ==============================================
            vduHelper.beginBlock('Preparing sources')
            vduHelper.fetchGitRepository(gitDirectory, gitRepository, gitCommit)
            vduHelper.endBlock()

            message = vduHelper.endBlock()
            function_set({'outout': message})
        except:
            message = vduHelper.endBlockInException()
            function_fail(message)


    def configure_spgwu(self, event):
       from VDUHelper import VDUHelper
       vduHelper = VDUHelper(self)
       vduHelper.beginBlock('configure_spgwu')
       try:

          # ====== Get SPGW-U parameters ========================================
          # For a documentation of the installation procedure, see:
          # https://github.com/OPENAIRINTERFACE/openair-cn-cups/wiki/OpenAirSoftwareSupport#install-spgw-u

          gitDirectory     = 'openair-spgwu-tiny'

          #spgwuSXab_IfName = 'ens4'
          spgwuSXab_IfName = 'dummy3'
          spgwuS1U_IfName  = 'dummy2'
          #spgwuSXab_IfName = 'wg3'
          #spgwuS1U_IfName  = 'wg0'
          #spgwuSGi_IfName  = 'ens6'
          spgwuSGi_IfName  = 'ens3'

          spgwcListString  = event.params['spgwu-spgwc-list'].split(',')
          spgwcList        = ''
          for spgwc in spgwcListString:
             spgwcAddress = IPv4Address(spgwc)
             if len(spgwcList) > 0:
                spgwcList = spgwcList +  ', '
             spgwcList = spgwcList + '{{ IPV4_ADDRESS=\\\\\\"{spgwcAddress}\\\\\\"; }}'.format(spgwcAddress = str(spgwcAddress))


          # ====== Build SPGW-U dependencies ====================================
          vduHelper.beginBlock('Building SPGW-U dependencies')
          vduHelper.executeFromString("""\
    export MAKEFLAGS="-j`nproc`" && \\
    cd  /home/ubuntu/{gitDirectory}/build/scripts && \\
    mkdir -p logs && \\
    ./build_spgwu -I -f >logs/build_spgwu-1.log 2>&1""".format(gitDirectory = gitDirectory))
          vduHelper.endBlock()

          # ====== Build SPGW-U itself ==========================================
          vduHelper.beginBlock('Building SPGW-U itself')
          vduHelper.executeFromString("""\
    export MAKEFLAGS="-j`nproc`" && \\
    cd  /home/ubuntu/{gitDirectory}/build/scripts && \\
    ./build_spgwu -c -V -b Debug -j >logs/build_spgwu-2.log 2>&1""".format(gitDirectory = gitDirectory))
          vduHelper.endBlock()

          # ====== Configure SPGW-U =============================================
          vduHelper.beginBlock('Configuring SPGW-U')
          vduHelper.executeFromString("""\
    cd  /home/ubuntu/{gitDirectory}/build/scripts && \\
    INSTANCE=1 && \\
    PREFIX='/usr/local/etc/oai' && \\
    sudo mkdir -m 0777 -p $PREFIX && \\
    sudo cp ../../etc/spgw_u.conf  $PREFIX && \\
    declare -A SPGWU_CONF && \\
    SPGWU_CONF[@INSTANCE@]=$INSTANCE && \\
    SPGWU_CONF[@PREFIX@]=$PREFIX && \\
    SPGWU_CONF[@PID_DIRECTORY@]='/var/run' && \\
    SPGWU_CONF[@SGW_INTERFACE_NAME_FOR_S1U_S12_S4_UP@]='{spgwuS1U_IfName}' && \\
    SPGWU_CONF[@SGW_INTERFACE_NAME_FOR_SX@]='{spgwuSXab_IfName}' && \\
    SPGWU_CONF[@SGW_INTERFACE_NAME_FOR_SGI@]='{spgwuSGi_IfName}' && \\
    for K in "${{!SPGWU_CONF[@]}}"; do sudo egrep -lRZ "$K" $PREFIX | xargs -0 -l sudo sed -i -e "s|$K|${{SPGWU_CONF[$K]}}|g" ; ret=$?;[[ ret -ne 0 ]] && echo "Tried to replace $K with ${{SPGWU_CONF[$K]}}" || true ; done && \\
    sudo sed -e "s/{{.*IPV4_ADDRESS=\\"192.168.160.100|\\".*;.*}}\|{{.*IPV4_ADDRESS=\\"@SPGWC0_IP_ADDRESS@\\".*;.*}}/{spgwcList}/g" -i /usr/local/etc/oai/spgw_u.conf""".format(
             gitDirectory      = gitDirectory,
             spgwuSXab_IfName  = spgwuSXab_IfName,
             spgwuS1U_IfName   = spgwuS1U_IfName,
             spgwuSGi_IfName   = spgwuSGi_IfName,
             spgwcList         = spgwcList
          ))
          vduHelper.endBlock()

          vduHelper.runInShell('sudo sysctl net.ipv4.ip_forward=1')
          vduHelper.runInShell('sudo iptables -P FORWARD ACCEPT')


          # ====== Configure HENCSAT QoS Setup ==================================
          #vduHelper.beginBlock('Configuring QoS Setup')
          #vduHelper.runInShell('sudo mkdir -p /etc/hencsat')
          #vduHelper.createFileFromString('/etc/hencsat/hencsat-router.conf',
          """# HENCSAT Router Configuration
          
          #ROUTER_INTERFACE_LEFT=ens6
          ROUTER_INTERFACE_LEFT=ens3
          ROUTER_INTERFACE_RIGHT=pdn
          """#)
          
          #vduHelper.aptInstallPackages([ 'hencsat-router' ], False)
          #vduHelper.endBlock()
          #vduHelper.aptInstallPackages([ 'hencsat-router' ], False)    
          #vduHelper.endBlock()


          # ====== Set up SPGW-U service ========================================
          vduHelper.beginBlock('Setting up SPGW-U service')
          vduHelper.configureSystemInfo('SPGW-U', ' This is the SPGW-U VNF!')
          vduHelper.createFileFromString('/lib/systemd/system/spgwu.service', """\
    [Unit]
    Description=Serving and Packet Data Network Gateway -- User Plane (SPGW-U)
    After=ssh.target
    
    [Service]
    ExecStart=/bin/sh -c 'exec /usr/local/bin/spgwu -c /usr/local/etc/oai/spgw_u.conf -o >>/var/log/spgwu.log 2>&1'
    KillMode=process
    Restart=on-failure
    RestartPreventExitStatus=255
    WorkingDirectory= /home/ubuntu/{gitDirectory}/build/scripts
    
    [Install]
    WantedBy=multi-user.target
    """.format(gitDirectory = gitDirectory))

          vduHelper.createFileFromString('/home/ubuntu/log',
    """\
    #!/bin/sh
    tail -f /var/log/spgwu.log
    """, True)

          vduHelper.createFileFromString('/home/ubuntu/restart',
    """\
    #!/bin/sh
    DIRECTORY=`dirname $0`
    #sudo service spgwu restart && sleep 5 && sudo service hencsat-router restart && $DIRECTORY/log
    sudo service spgwu restart && $DIRECTORY/log
    """, True)
          vduHelper.runInShell('sudo chown ubuntu:ubuntu /home/ubuntu/log /home/ubuntu/restart')
          vduHelper.endBlock()

          # ====== Set up sysstat service =======================================
          vduHelper.installSysStat()

          # ====== Clean up =====================================================
          vduHelper.cleanUp()

          message = vduHelper.endBlock()
          function_set( { 'outout': message } )
       except:
          message = vduHelper.endBlockInException()
          function_fail(message)

    def restart_spgwu(self, event):
       from VDUHelper import VDUHelper
       vduHelper = VDUHelper(self)
       vduHelper.beginBlock('restart_spgwu')
       try:

          vduHelper.runInShell('sudo service spgwu restart')

          message = vduHelper.endBlock()
          function_set( { 'outout': message } )
       except:
          message = vduHelper.endBlockInException()
          function_fail(message)

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
                cmd = ['sudo wg-quick up {}'.format(wgifname)]
                result, err = proxy.run(cmd)
                event.set_results({'restarted wg0': result})
        except:
            event.fail('command failed:' + err)


    def _on_interfaces1u_relation_changed(self, event): # change to correct juju interface name
        # INPUT correct wireguard interface name:
        wgifname = "wg0"
        self.wgrelation(event, wgifname)

                    
    def _on_interfacesxab_relation_changed(self, event): # change to correct juju interface name
        # INPUT correct wireguard interface name:
        wgifname = "wg3"
        self.wgrelation(event, wgifname)

    def _on_interfacesxab_relation_joined(self, event): # change to correct juju interface name
        # INPUT correct wireguard interface name:
        wgifname = "wg3"
        self.wgrelation(event, wgifname)

    def wgrelation(self, event, wgifname):
        # logger.debug("RELATION DATA: {}".format(dict(event.relation.data[event.unit])))
        # parameter = event.relation.data[event.unit].get("parameter")
        # if parameter:
        #    self.model.unit.status = ActiveStatus("Parameter received: {}".format(parameter))
        proxy = False
        proxypass = False
        try:
            proxy = self.get_ssh_proxy()
            proxypass = True
        except:
            sleep(5)
            c = randint(1, 10000)
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
                c = randint(1, 10000)
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
                        cmd = [
                            'echo -e "[Peer]\nPublicKey = {}\nAllowedIPs = {}\nEndpoint = {}:{}" | sudo tee -a /etc/wireguard/{}.conf'.format(
                                leader_pubkey, leader_subnet, leader_gwip, str(leader_listenport), wgifname)]
                        result, err = proxy.run(cmd)
                        try:
                            cmd = ['sudo wg-quick down {}'.format(wgifname)]
                            result, err = proxy.run(cmd)
                            cmd = ['sudo systemctl start wg-quick@{}.service'.format(wgifname)]
                            result, err = proxy.run(cmd)
                        except:
                            pass
                        event.relation.data[self.model.unit]["wg-peered"] = "True"
                        # event.relation.data[self.unit].update({"wg-peered": "True"})

                # send pubkey and other variables back to leader
                result = ''
                try:
                    cmd = ['sudo test -f /etc/wireguard/publickey{} && echo "$FILE present"'.format(wgifname)]
                    result, err = proxy.run(cmd)
                except:
                    event.relation.data[self.unit].update({"relation-joined": "failed1"})
                if len(result) > 5:
                    # try:
                    cmd = ['sudo cat /etc/wireguard/publickey{}'.format(wgifname)]
                    result, err = proxy.run(cmd)
                    readyint += 1
                    event.relation.data[self.model.unit]["wg-pubkey"] = result
                    # event.relation.data[self.unit].update({"wgpeer-pubkey": result})
                    # except:
                    #    event.relation.data[self.unit].update({"relation-joined": "failed2"})
                else:
                    try:
                        cmd = [
                            'wg genkey | sudo tee /etc/wireguard/privatekey{} | wg pubkey | sudo tee /etc/wireguard/publickey{}'.format(
                                wgifname, wgifname)]
                        result, err = proxy.run(cmd)
                        cmd = ['sudo cat /etc/wireguard/publickey{}'.format(wgifname)]
                        result, err = proxy.run(cmd)
                        readyint += 1
                        event.relation.data[self.model.unit]["wg-pubkey"] = result
                    except:
                        pass
                    # event.relation.data[self.unit].update({"wgpeer-pubkey": result})
                    # event.relation.data[self.unit].update({"ready": "True"})
                result = ''
                try:
                    cmd = ['sudo test -f /etc/wireguard/gateway_ip{} && echo "$FILE present"'.format(wgifname)]
                    result, err = proxy.run(cmd)
                except:
                    pass
                if len(result) > 5:
                    cmd = ['sudo cat /etc/wireguard/gateway_ip{}'.format(wgifname)]
                    result, err = proxy.run(cmd)
                    event.relation.data[self.model.unit]["wg-gwip"] = result
                    # event.relation.data[self.unit].update({"wgpeer-gwip": result})
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
                    event.relation.data[self.model.unit]["wg-subnet"] = result
                    # event.relation.data[self.unit].update({"wgpeer-subnet": result})
                    readyint += 1
                    # if readyint >= 3:
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
                    event.relation.data[self.model.unit]["wg-listenport"] = result
                    # event.relation.data[self.unit].update({"wgpeer-listenport": result})
                    readyint += 1
                if readyint >= 4 and "True" in peered:
                    event.relation.data[self.model.unit]["wg-ready"] = "True"
                    cmd = ['sudo wg-quick down {}'.format(wgifname)]
                    result, err = proxy.run(cmd)
                    cmd = ['sudo wg-quick up {}'.format(wgifname)]
                    result, err = proxy.run(cmd)

                    # event.relation.data[self.unit].update({"ready": "True"})


if __name__ == "__main__":
    main(MySSHProxyCharm)



#if __name__ == "__main__":
#    main(SimpleProxyCharm)


#if __name__ == "__main__":
#    main(SampleProxyCharm)
