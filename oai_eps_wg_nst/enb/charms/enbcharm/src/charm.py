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
from time import sleep



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

        #MME actions
        self.framework.observe(self.on.prepare_enb_build_action, self.prepare_enb_build)
        self.framework.observe(self.on.configure_enb_action, self.configure_enb)
        self.framework.observe(self.on.start_enb_action, self.start_enb)
        self.framework.observe(self.on.stop_enb_action, self.stop_enb)
        self.framework.observe(self.on.restart_enb_action, self.restart_enb)

        # WireGuard actions
        self.framework.observe(self.on.generatekeys_action, self.on_generatekeys_action)
        self.framework.observe(self.on.generatewgconfig_action, self.on_generateconfig_action)
        self.framework.observe(self.on.wgup_action, self.on_wireguardup_action)
        self.framework.observe(self.on.wgaddpeer_action, self.on_addpeer_action)
        self.framework.observe(self.on.wgdelpeer_action, self.on_delpeer_action)
        self.framework.observe(self.on.wgrestart_action, self.on_wgrestart_action)
        self.framework.observe(self.on.interfaces1u_relation_changed, self._on_interfaces1u_relation_changed)
        self.framework.observe(self.on.interfaces1c_relation_changed, self._on_interfaces1c_relation_changed)


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



    def prepare_enb_build(self, event):
        from VDUHelper import VDUHelper
        vduHelper = VDUHelper(self)

        # ====== Add repository =======================================
        try:
            vduHelper.beginBlock('Add ppa:dreibh/ppa')
            proxy = self.get_ssh_proxy()
            result = ''
            result1 = ''
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


        vduHelper.beginBlock('prepare_enb_build')
        try:

            # ====== Get SPGW-U parameters ========================================
            # For a documentation of the installation procedure, see:
            # https://github.com/OPENAIRINTERFACE/openair-cn-cups/wiki/OpenAirSoftwareSupport#install-spgw-u

            gitRepository = event.params['enb-git-repository']
            gitCommit = 'master'
            gitDirectory = 'openairinterface5G'


            # ====== Prepare sources ==============================================
            vduHelper.beginBlock('Preparing sources')
            vduHelper.fetchGitRepository(gitDirectory, gitRepository, gitCommit)
            vduHelper.endBlock()

            message = vduHelper.endBlock()
            function_set({'outout': message})
        except:
            message = vduHelper.endBlockInException()
            function_fail(message)


    def configure_enb(self, event):
       from VDUHelper import VDUHelper
       vduHelper = VDUHelper(self)
       vduHelper.beginBlock('configure_enb')
       try:
          # Prepare network configurations:
          eNBMCC = event.params['mcc']
          eNBMNC = event.params['mnc']
          eNBMNC_len = len(eNBMNC)
          eNB_TAC = event.params['tracking-area']
          MME_IP = event.params['mme-ip']
          eNBS1C_IP = event.params['s1c-ip']
          eNBS1U_IP = event.params['s1u-ip']
          eNBS1C_IfName = event.params['s1c-interface']
          eNBS1U_IfName = event.params['s1u-interface']
          S1Subnet = event.params['s1-subnetsize']
          
          eNBUu_IP = event.params['uu-ip']
          eNBUu_subnet = event.params['uu-subnetsize']
          eNBUu_IfName = event.params['uu-interface']
          

          # ====== Prepare system ===============================================
          vduHelper.beginBlock('Preparing system')
          eNBS1C_IPConf = IPv4Interface(str(eNBS1C_IP)+"/"+str(S1Subnet))
          configurationS1c = vduHelper.makeInterfaceConfiguration(eNBS1C_IfName, eNBS1C_IPConf)
          vduHelper.configureInterface(eNBS1C_IfName, configurationS1c, 60)

          eNBS1U_IPConf = IPv4Interface(str(eNBS1U_IP)+"/"+str(S1Subnet))
          configurationS1u = vduHelper.makeInterfaceConfiguration(eNBS1U_IfName, eNBS1U_IPConf)
          vduHelper.configureInterface(eNBS1U_IfName, configurationS1u, 61)

          eNBUu_IPConf = IPv4Interface(str(eNBUu_IP)+"/"+str(eNBUu_subnet))
          configurationUu = vduHelper.makeInterfaceConfiguration(eNBUu_IfName, eNBUu_IPConf)
          vduHelper.configureInterface(eNBUu_IfName, configurationUu, 62)

          try:
              s1cwg_IfName = 'dummy2'
              s1cwg_IP = event.params['s1cwg-ip']
              s1cwg_IPConf = IPv4Interface(str(s1cwg_IP)+"/32")
              configurationS1cwg = vduHelper.makeInterfaceConfiguration(s1cwg_IfName, s1cwg_IPConf, createDummy=True)
              vduHelper.configureInterface(s1cwg_IfName, configurationS1cwg, 63)
              eNBS1C_IP = s1cwg_IP
              S1Subnet = '32'
              eNBS1C_IfName = s1cwg_IfName
          except:
              pass
          try:
              #s1uwg_IfName = event.params['s1uwg-interface']
              #s1uwg_IP = event.params['s1uwg-ip']
              s1uwg_IfName = 'dummy3'
              s1uwg_IP = event.params['s1uwg-ip']
              s1uwg_IPConf = IPv4Interface(str(s1uwg_IP)+"/32")
              configurationS1uwg = vduHelper.makeInterfaceConfiguration(s1uwg_IfName, s1uwg_IPConf, createDummy=True)
              vduHelper.configureInterface(s1uwg_IfName, configurationS1uwg, 64)
              eNBS1U_IP = s1uwg_IP
              S1Subnet = '32'
              eNBS1U_IfName = s1uwg_IfName
          except:
              pass

          vduHelper.testNetworking()
          vduHelper.waitForPackageUpdatesToComplete()
          vduHelper.endBlock()
          # ====== Get SPGW-U parameters ========================================
          # For a documentation of the installation procedure, see:
          # https://github.com/OPENAIRINTERFACE/openair-cn-cups/wiki/OpenAirSoftwareSupport#install-spgw-u

          gitDirectory     = 'openairinterface5G'




          # ====== Build eNB dependencies ====================================
          vduHelper.beginBlock('Building eNB dependencies')
          vduHelper.executeFromString("""\
    export MAKEFLAGS="-j`nproc`" && \\
    cd  /home/ubuntu/{gitDirectory} && \\
    mkdir -p logs && \\
    source oaienv && \\
    cd cmake_targets && \\
    ./build_oai -I --phy_simulators >../logs/build_enb-1.log 2>&1""".format(gitDirectory = gitDirectory))
          vduHelper.endBlock()

          # ====== Build eNB-U itself ==========================================
          vduHelper.beginBlock('Building eNB itself')
          vduHelper.executeFromString("""\
    export MAKEFLAGS="-j`nproc`" && \\
    cd  /home/ubuntu/{gitDirectory}/cmake_targets && \\
    ./build_oai -w SIMU --UE --eNB >../logs/build_enb-2.log 2>&1""".format(gitDirectory = gitDirectory))
          vduHelper.endBlock()

          # ====== Configure eNB =============================================
          vduHelper.beginBlock('Configuring eNB')
          vduHelper.executeFromString("""\
    cd  /home/ubuntu/{gitDirectory}/cmake_targets && \\
    INSTANCE=1 && \\
    PREFIX='/usr/local/etc/oai' && \\
    sudo mkdir -m 0777 -p $PREFIX && \\
    sudo cp ../targets/PROJECTS/GENERIC-LTE-EPC/CONF/enb.band7.tm1.50PRB.usrpb210.conf  $PREFIX/enb.conf && \\
    sed -i 's/tracking\_area\_code  \=  1/tracking\_area\_code  \=  {eNB_TAC}/g' $PREFIX/enb.conf &&
    sed -i 's/mcc \= 208/mcc \= {eNBMCC}/g' $PREFIX/enb.conf &&
    sed -i 's/mnc \= 93/mnc \= {eNBMNC}/g' $PREFIX/enb.conf &&
    sed -i 's/mnc\_length \= 2/mnc\_length \= {eNBMNC_len}/g' $PREFIX/enb.conf &&
    sed -i 's/ENB\_INTERFACE\_NAME\_FOR\_S1\_MME            \= \"eno1\"/ENB\_INTERFACE\_NAME\_FOR\_S1\_MME            \= \"{eNBS1C_IfName}\"/g' $PREFIX/enb.conf &&
    sed -i 's/ENB\_IPV4\_ADDRESS\_FOR\_S1\_MME              \= \"10.64.45.62\/23\"/ENB\_IPV4\_ADDRESS\_FOR\_S1\_MME              \= \"{eNBS1C_IP}\/{S1Subnet}\"/g' $PREFIX/enb.conf &&
    sed -i 's/ENB\_INTERFACE\_NAME\_FOR\_S1U               \= \"eno1\"/ENB\_INTERFACE\_NAME\_FOR\_S1U               \= \"{eNBS1U_IfName}\"/g' $PREFIX/enb.conf &&
    sed -i 's/ENB\_IPV4\_ADDRESS\_FOR\_S1U                 \= \"10.64.45.62\/23\"/ENB\_IPV4\_ADDRESS\_FOR\_S1U                 \= \"{eNBS1U_IP}\/{S1Subnet}\"/g' $PREFIX/enb.conf &&
    sed -i 's/ENB\_IPV4\_ADDRESS\_FOR\_X2C                 \= \"192.168.12.111\/24\"/ENB\_IPV4\_ADDRESS\_FOR\_X2C                 \= \"{eNBS1U_IP}\/{S1Subnet}\"/g' $PREFIX/enb.conf &&
    sed -i 's/ ipv4       \= \"10.64.93.19\"/ ipv4       \= \"{MME_IP}\"/g' $PREFIX/enb.conf
    """.format(
             gitDirectory      = gitDirectory,
             eNB_TAC  = eNB_TAC,
             eNBMCC   = eNBMCC,
             eNBMNC   = eNBMNC,
             eNBMNC_len         = eNBMNC_len,
             eNBS1C_IfName   = eNBS1C_IfName,
             eNBS1C_IP   = eNBS1C_IP,
             eNBS1U_IfName   = eNBS1U_IfName,
             eNBS1U_IP   = eNBS1U_IP,
             MME_IP   = MME_IP,
             S1Subnet = S1Subnet
          ))
          vduHelper.endBlock()



          # ====== Set up eNB service ========================================
          vduHelper.beginBlock('Setting up eNB service')
          vduHelper.configureSystemInfo('eNB', ' This is the eNB VNF')
          vduHelper.createFileFromString('/lib/systemd/system/enb.service', """\
    [Unit]
    Description=eNodeB
    After=ssh.target
    
    [Service]
    ExecStart=/bin/sh -c 'RFSIMULATOR=enb /home/ubuntu/{gitDirectory}/cmake_targets/lte_build_oai/build/lte-softmodem -O /usr/local/etc/oai/enb.conf --rfsim >>/var/log/enb.log 2>&1'
    KillMode=process
    Restart=on-failure
    RestartPreventExitStatus=255
    WorkingDirectory= /home/ubuntu/{gitDirectory}/cmake_targets
    
    [Install]
    WantedBy=multi-user.target
    """.format(gitDirectory = gitDirectory))

          vduHelper.createFileFromString('/home/ubuntu/log',
    """\
    #!/bin/sh
    tail -f /var/log/enb.log
    """, True)

          vduHelper.createFileFromString('/home/ubuntu/restart',
    """\
    #!/bin/sh
    DIRECTORY=`dirname $0`
    sudo service enb restart && sleep 5 && $DIRECTORY/log
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

    def start_enb(self, event):
       from VDUHelper import VDUHelper
       vduHelper = VDUHelper(self)
       vduHelper.beginBlock('start_enb')
       try:

          vduHelper.runInShell('sudo service enb start')

          message = vduHelper.endBlock()
          function_set( { 'outout': message } )
       except:
          message = vduHelper.endBlockInException()
          function_fail(message)
          
    def stop_enb(self, event):
       from VDUHelper import VDUHelper
       vduHelper = VDUHelper(self)
       vduHelper.beginBlock('stop_enb')
       try:

          vduHelper.runInShell('sudo service enb stop')

          message = vduHelper.endBlock()
          function_set( { 'outout': message } )
       except:
          message = vduHelper.endBlockInException()
          function_fail(message)

    def restart_enb(self, event):
       from VDUHelper import VDUHelper
       vduHelper = VDUHelper(self)
       vduHelper.beginBlock('restart_enb')
       try:

          vduHelper.runInShell('sudo service enb restart')

          message = vduHelper.endBlock()
          function_set( { 'outout': message } )
       except:
          message = vduHelper.endBlockInException()
          function_fail(message)

    # WireGuard provider functions
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
        try:
            wgifname = ''
            try:
                wgifname = event.params['wg-interface']
            except:
                wgifname = "wg0"    
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
                    
    def _on_interfaces1c_relation_changed(self, event): # change to correct juju interface name
        # INPUT correct wireguard interface name:
        wgifname = "wg2"
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

