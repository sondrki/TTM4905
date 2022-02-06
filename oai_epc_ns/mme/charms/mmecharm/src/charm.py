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

    subprocess.check_call(["pip3", "install", "packaging", "charmhelpers"],)

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
        self.framework.observe(self.on.test_action, self.on_test_action)
        #MME actions
        self.framework.observe(self.on.prepare_mme_build_action, self.on_preparemmebuild_action)
        self.framework.observe(self.on.configure_mme_action, self.on_configuremme_action)
        self.framework.observe(self.on.restart_mme_action, self.on_restartmme_action)

        # Listen to the test action event
        #self.framework.observe(self.on.test_action, self.on_test_action)
        #self.framework.observe(self.on.wgconfig_action, self.on_touch_action)
        #self.framework.observe(self.on.generatekeys_action, self.on_generatekeys_action)
        #self.framework.observe(self.on.generatewgconfig_action, self.on_touch_action)
        #self.framework.observe(self.on.generatewgconfig_action, self.on_generateconfig_action)
        #self.framework.observe(self.on.wgup_action, self.on_wireguardup_action)
        #self.framework.observe(self.on.wgaddpeer_action, self.on_addpeer_action)
        #self.framework.observe(self.on.wgdelpeer_action, self.on_delpeer_action)
        #self.framework.observe(self.on.wgrestart_action, self.on_wgrestart_action)

        # proxypeer functions
        #self.framework.observe(self.on.leader_elected, self._on_leader_elected)
        #self.framework.observe(self.on.proxypeer_relation_joined, self._on_proxypeer_relation_joined)
        #self.framework.observe(self.on.proxypeer_relation_departed, self._on_proxypeer_relation_departed)
        #self.framework.observe(self.on.proxypeer_relation_changed, self._on_proxypeer_relation_changed)
        #self.framework.observe(self.on.wgrelation_relation_changed, self._on_wgrelation_relation_changed)
        #self.framework.observe(self.on.interface_relation_changed, self._on_interface_relation_changed)


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

    def on_preparemmebuild_action(self, event):
        from VDUHelper import VDUHelper
        vduHelper = VDUHelper(self)
        
        
        # ====== Add repository =======================================
        try:
            vduHelper.beginBlock('Add ppa:dreibh/ppa')
            vduHelper.executeFromString("""sudo apt-add-repository -y ppa:dreibh/ppa && sudo apt update""")
            vduHelper.endBlock()
        except:
            message = vduHelper.endBlockInException()
            function_fail(message)
        
        vduHelper.beginBlock('prepare_mme_build')
        try:

            # ====== Get MME parameters ===========================================
            # For a documentation of the installation procedure, see:
            # https://github.com/OPENAIRINTERFACE/openair-cn/wiki/OpenAirSoftwareSupport#install-mme

            gitRepository = event.params['mme-git-repository']
            gitCommit = event.params['mme-git-commit']
            gitDirectory = 'openair-mme'

            mmeS1C_IPv4Interface = IPv4Interface(event.params['mme-S1C-ipv4-interface'])
            mmeS1C_IPv4Gateway = IPv4Address(event.params['mme-S1C-ipv4-gateway'])
            if event.params['mme-S1C-ipv6-interface'] != '':
                mmeS1C_IPv6Interface = IPv6Interface(event.params['mme-S1C-ipv6-interface'])
            else:
                mmeS1C_IPv6Interface = None
            if event.params['mme-S1C-ipv6-gateway'] != '':
                mmeS1C_IPv6Gateway = IPv6Address(event.params['mme-S1C-ipv6-gateway'])
            else:
                mmeS1C_IPv6Gateway = None

            # Prepare network configurations:
            #mmeS6a_IfName = 'ens4'
            loopback = 'lo:2'
            mmeS6a_IfName = 'ens4'
            mmeS11_IfName = 'ens5'
            mmeS1C_IfName = 'ens6'

            #configurationS6a = vduHelper.makeInterfaceConfiguration(mmeS6a_IfName, IPv4Interface('0.0.0.0/0'))
            #configurationloopback = vduHelper.makeInterfaceConfiguration(loopback, IPv4Interface('172.16.6.2/32'))
            configurationS6a = vduHelper.makeInterfaceConfiguration(mmeS6a_IfName, IPv4Interface('172.16.6.2/24'))
            configurationS11 = vduHelper.makeInterfaceConfiguration(mmeS11_IfName, IPv4Interface('172.16.1.102/24'))
            #configurationS11 = vduHelper.makeInterfaceConfiguration(mmeS11_IfName, IPv4Interface('0.0.0.0/0'))
            configurationS1C = vduHelper.makeInterfaceConfiguration(mmeS1C_IfName, mmeS1C_IPv4Interface,
                                                                    mmeS1C_IPv4Gateway,
                                                                    mmeS1C_IPv6Interface, mmeS1C_IPv6Gateway)

            # S10 dummy interface:
            mmeS10_IfName = 'dummy0'
            configurationS10 = vduHelper.makeInterfaceConfiguration(mmeS10_IfName, IPv4Interface('192.168.10.110/24'),
                                                                    createDummy=True)

            # ====== Prepare system ===============================================
            vduHelper.beginBlock('Preparing system')
            vduHelper.configureInterface(mmeS6a_IfName, configurationS6a, 61)
            vduHelper.configureInterface(mmeS11_IfName, configurationS11, 62)
            vduHelper.configureInterface(mmeS1C_IfName, configurationS1C, 63)
            vduHelper.configureInterface(mmeS10_IfName, configurationS10, 64)
            #vduHelper.configureInterface(loopback, configurationloopback, 65)
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

    def on_configuremme_action(self, event):
        from VDUHelper import VDUHelper
        vduHelper = VDUHelper(self)

        vduHelper.beginBlock('configure-mme')
        try:

            # ====== Get MME parameters ===========================================
            # For a documentation of the installation procedure, see:
            # https://github.com/OPENAIRINTERFACE/openair-cn/wiki/OpenAirSoftwareSupport#install-mme

            gitDirectory = 'openair-mme'

            hssS6a_IPv4Address = IPv4Address(event.params['hss-S6a-address'])
            mmeS1C_IPv4Interface = IPv4Interface(event.params['mme-S1C-ipv4-interface'])
            mmeS11_IPv4Interface = IPv4Interface(event.params['mme-S11-ipv4-interface'])
            mmeS10_IPv4Interface = IPv4Interface('192.168.10.110/24')
            spwgcS11_IPv4Interface = IPv4Interface(event.params['spgwc-S11-ipv4-interface'])
            networkRealm = event.params['network-realm']
            networkMCC = int(event.params['network-mcc'])
            networkMNC = int(event.params['network-mnc'])
            networkOP = event.params['network-op']
            networkK = event.params['network-k']
            networkIMSIFirst = event.params['network-imsi-first']
            networkMSISDNFirst = event.params['network-msisdn-first']
            networkUsers = int(event.params['network-users'])

            TAC_SGW_TEST = 7
            TAC_SGW_0 = 600
            TAC_MME_0 = 601
            TAC_MME_1 = 602

            tac_sgw_test = '{:04x}'.format(TAC_SGW_TEST)
            tac_sgw_0 = '{:04x}'.format(TAC_SGW_0)
            tac_mme_0 = '{:04x}'.format(TAC_MME_0)
            tac_mme_1 = '{:04x}'.format(TAC_MME_1)

            # Prepare network configurations:
            mmeS6a_IfName = 'ens4'
            mmeS11_IfName = 'ens5'
            mmeS1C_IfName = 'ens6'
            mmeS10_IfName = 'dummy0'

            # ====== Build MME dependencies =======================================
            vduHelper.beginBlock('Building MME dependencies')
            vduHelper.executeFromString("""\
    export MAKEFLAGS="-j`nproc`" && \\
    cd  /home/ubuntu/{gitDirectory}/scripts && \\
    mkdir -p logs && \\
    ./build_mme --check-installed-software --force >logs/build_mme-1.log 2>&1
    """.format(gitDirectory=gitDirectory))
            vduHelper.endBlock()

            # ====== Build MME itself =============================================
            vduHelper.beginBlock('Building MME itself')
            vduHelper.executeFromString("""\
    export MAKEFLAGS="-j`nproc`" && \\
    cd  /home/ubuntu/{gitDirectory}/scripts && \\
    ./build_mme --clean >logs/build_mme-2.log 2>&1
    """.format(gitDirectory=gitDirectory))
            vduHelper.endBlock()

            # ====== Configure MME ================================================
            vduHelper.beginBlock('Configuring MME')
            vduHelper.executeFromString("""\
    export MAKEFLAGS="-j`nproc`" && \\
    cd  /home/ubuntu/{gitDirectory}/scripts && \\
    echo "127.0.1.1        mme.{networkRealm} mme" | sudo tee -a /etc/hosts && \\
    echo "{hssS6a_IPv4Address}     hss.{networkRealm} hss" | sudo tee -a /etc/hosts && \\
    openssl rand -out $HOME/.rnd 128 && \\
    INSTANCE=1 && \\
    PREFIX='/usr/local/etc/oai' && \\
    sudo mkdir -m 0777 -p $PREFIX && \\
    sudo mkdir -m 0777 -p $PREFIX/freeDiameter && \\
    sudo cp ../etc/mme_fd.sprint.conf  $PREFIX/freeDiameter/mme_fd.conf && \\
    sudo cp ../etc/mme.conf  $PREFIX && \\
    declare -A MME_CONF && \\
    MME_CONF[@MME_S6A_IP_ADDR@]="127.0.0.11" && \\
    MME_CONF[@INSTANCE@]=$INSTANCE && \\
    MME_CONF[@PREFIX@]=$PREFIX && \\
    MME_CONF[@REALM@]='{networkRealm}' && \\
    MME_CONF[@PID_DIRECTORY@]='/var/run' && \\
    MME_CONF[@MME_FQDN@]="mme.{networkRealm}" && \\
    MME_CONF[@HSS_HOSTNAME@]='hss' && \\
    MME_CONF[@HSS_FQDN@]="hss.{networkRealm}" && \\
    MME_CONF[@HSS_IP_ADDR@]='{hssS6a_IPv4Address}' && \\
    MME_CONF[@MCC@]='{networkMCC}' && \\
    MME_CONF[@MNC@]='{networkMNC}' && \\
    MME_CONF[@MME_GID@]='32768' && \\
    MME_CONF[@MME_CODE@]='3' && \\
    MME_CONF[@TAC_0@]='600' && \\
    MME_CONF[@TAC_1@]='601' && \\
    MME_CONF[@TAC_2@]='602' && \\
    MME_CONF[@MME_INTERFACE_NAME_FOR_S1_MME@]='{mmeS1C_IfName}' && \\
    MME_CONF[@MME_IPV4_ADDRESS_FOR_S1_MME@]='{mmeS1C_IPv4Interface}' && \\
    MME_CONF[@MME_INTERFACE_NAME_FOR_S11@]='{mmeS11_IfName}' && \\
    MME_CONF[@MME_IPV4_ADDRESS_FOR_S11@]='{mmeS11_IPv4Interface}' && \\
    MME_CONF[@MME_INTERFACE_NAME_FOR_S10@]='{mmeS10_IfName}' && \\
    MME_CONF[@MME_IPV4_ADDRESS_FOR_S10@]='{mmeS10_IPv4Interface}' && \\
    MME_CONF[@OUTPUT@]='CONSOLE' && \\
    MME_CONF[@SGW_IPV4_ADDRESS_FOR_S11_TEST_0@]='{spwgcS11_IPv4Address}' && \\
    MME_CONF[@SGW_IPV4_ADDRESS_FOR_S11_0@]='{spwgcS11_IPv4Address}' && \\
    MME_CONF[@PEER_MME_IPV4_ADDRESS_FOR_S10_0@]='0.0.0.0/24' && \\
    MME_CONF[@PEER_MME_IPV4_ADDRESS_FOR_S10_1@]='0.0.0.0/24' && \\
    MME_CONF[@TAC-LB_SGW_TEST_0@]={tac_sgw_test_lo} && \\
    MME_CONF[@TAC-HB_SGW_TEST_0@]={tac_sgw_test_hi} && \\
    MME_CONF[@MCC_SGW_0@]={networkMCC} && \\
    MME_CONF[@MNC3_SGW_0@]={networkMNC:03d} && \\
    MME_CONF[@TAC-LB_SGW_0@]={tac_sgw_0_lo} && \\
    MME_CONF[@TAC-HB_SGW_0@]={tac_sgw_0_hi} && \\
    MME_CONF[@MCC_MME_0@]={networkMCC} && \\
    MME_CONF[@MNC3_MME_0@]={networkMNC:03d} && \\
    MME_CONF[@TAC-LB_MME_0@]={tac_mme_0_lo} && \\
    MME_CONF[@TAC-HB_MME_0@]={tac_mme_0_hi} && \\
    MME_CONF[@MCC_MME_1@]={networkMCC} && \\
    MME_CONF[@MNC3_MME_1@]={networkMNC:03d} && \\
    MME_CONF[@TAC-LB_MME_1@]={tac_mme_1_lo} && \\
    MME_CONF[@TAC-HB_MME_1@]={tac_mme_1_hi} && \\
    for K in "${{!MME_CONF[@]}}"; do sudo egrep -lRZ "$K" $PREFIX | xargs -0 -l sudo sed -i -e "s|$K|${{MME_CONF[$K]}}|g" ; ret=$?;[[ ret -ne 0 ]] && echo "Tried to replace $K with ${{MME_CONF[$K]}}" || true ; done && \\
    sudo ./check_mme_s6a_certificate $PREFIX/freeDiameter mme.{networkRealm} >logs/check_mme_s6a_certificate.log 2>&1
    """.format(
                gitDirectory=gitDirectory,
                hssS6a_IPv4Address=hssS6a_IPv4Address,
                mmeS1C_IfName=mmeS1C_IfName,
                mmeS1C_IPv4Interface=mmeS1C_IPv4Interface,
                mmeS11_IfName=mmeS11_IfName,
                mmeS11_IPv4Interface=mmeS11_IPv4Interface,
                mmeS10_IfName=mmeS10_IfName,
                mmeS10_IPv4Interface=mmeS10_IPv4Interface,

                spwgcS11_IPv4Address=spwgcS11_IPv4Interface.ip,
                networkRealm=networkRealm,
                networkMCC=networkMCC,
                networkMNC=networkMNC,
                networkOP=networkOP,
                networkK=networkK,
                networkIMSIFirst=networkIMSIFirst,
                networkMSISDNFirst=networkMSISDNFirst,
                networkUsers=networkUsers,

                tac_sgw_test_hi=tac_sgw_test[0:2],
                tac_sgw_test_lo=tac_sgw_test[2:4],
                tac_sgw_0_hi=tac_sgw_0[0:2],
                tac_sgw_0_lo=tac_sgw_0[2:4],
                tac_mme_0_hi=tac_mme_0[0:2],
                tac_mme_0_lo=tac_mme_0[2:4],
                tac_mme_1_hi=tac_mme_1[0:2],
                tac_mme_1_lo=tac_mme_1[2:4]
            ))
            vduHelper.endBlock()

            # ====== Set up MME service ===========================================
            vduHelper.beginBlock('Setting up MME service')
            vduHelper.configureSystemInfo('MME', 'This is the MME of the SimulaMet OAI VNF!')
            vduHelper.createFileFromString('/lib/systemd/system/mme.service', """\
    [Unit]
    Description=Mobility Management Entity (MME)
    After=ssh.target

    [Service]
    ExecStart=/bin/sh -c 'exec /usr/local/bin/mme -c /usr/local/etc/oai/mme.conf >>/var/log/mme.log 2>&1'
    KillMode=process
    Restart=on-failure
    RestartPreventExitStatus=255
    WorkingDirectory= /home/ubuntu/{gitDirectory}/scripts

    [Install]
    WantedBy=multi-user.target
    """.format(gitDirectory=gitDirectory))

            vduHelper.createFileFromString('/home/ubuntu/log',
                                           """\
                                           #!/bin/sh
                                           tail -f /var/log/mme.log
                                           """, True)

            vduHelper.createFileFromString('/home/ubuntu/restart',
                                           """\
                                           #!/bin/sh
                                           DIRECTORY=`dirname $0`
                                           sudo service mme restart && $DIRECTORY/log
                                           """, True)
            vduHelper.runInShell('sudo chown ubuntu:ubuntu /home/ubuntu/log /home/ubuntu/restart')
            vduHelper.endBlock()

            # ====== Set up sysstat service =======================================
            vduHelper.installSysStat()

            # ====== Clean up =====================================================
            vduHelper.cleanUp()

            message = vduHelper.endBlock()
            function_set({'outout': message})
        except:
            message = vduHelper.endBlockInException()
            function_fail(message)

    def on_restartmme_action(self, event):
        from VDUHelper import VDUHelper
        vduHelper = VDUHelper(self)

        vduHelper.beginBlock('restart_mme')
        try:

            vduHelper.runInShell('sudo service mme restart')

            message = vduHelper.endBlock()
            function_set({'outout': message})
        except:
            message = vduHelper.endBlockInException()
            function_fail(message)
    """
    def on_generatekeys_action(self, event):
        err = ''
        result = ''
        try:
            proxy = self.get_ssh_proxy()
            cmd = ['sudo test -f /etc/wireguard/publickey && echo "$FILE exists."']
            result, err = proxy.run(cmd)
        except:
            pass
        if len(result) > 5:
            event.set_results({'outout': result})
        else:
            try:
                proxy = self.get_ssh_proxy()
                cmd = ['wg genkey | sudo tee /etc/wireguard/privatekey | wg pubkey | sudo tee /etc/wireguard/publickey']
                result, err = proxy.run(cmd)
                event.set_results({'outout': result})
            except:
                event.fail('command failed:' + err)

    def on_generateconfig_action(self, event):
        err = ''
        #event.relation.data[self.model.unit]["wg-pubkey"] = "wgkeyparam"
        #subnet_of_tunnel = event.params['tunnel-subnet']
        try:
            #if self.model.unit.is_leader():
            proxy = self.get_ssh_proxy()
            gateway_ip = ''
            try:
                gateway_ip = event.params['gateway-ip']
                if not gateway_ip:
                    gateway_ip = self.model.config["ssh-hostname"]
            except:
                    gateway_ip = self.model.config["ssh-hostname"]                
            subnet_of_tunnel = event.params['tunnel-subnet']
            endpoint = event.params['endpoint']
            cmd = ['echo -e "[Interface]\nAddress = {}\nListenPort = 51820\nPrivatekey = $(sudo cat /etc/wireguard/privatekey)" | sudo tee /etc/wireguard/wg0.conf'.format(endpoint)]
            result, err = proxy.run(cmd)
            cmd = ['echo -e "{}" | sudo tee /etc/wireguard/gateway_ip'.format(gateway_ip)]
            result, err = proxy.run(cmd)
            cmd = ['echo -e "{}" | sudo tee /etc/wireguard/subnet'.format(subnet_of_tunnel)]
            result, err = proxy.run(cmd)
            event.set_results({'outout': result})
        except:
            event.fail('command failed:' + err)
            #event.set_results({'outout': result})
            
        #    #cmd = ['sudo cat /etc/wireguard/publickey']
        #    #result, err = proxy.run(cmd)
        #    ##event.relation.data[self.unit].update({"unit-data": result})
        #    #event.relation.data[self.unit].update({"wg-pubkey": result})
        #    #event.relation.data[self.unit].update({"wg-listenport": 51820})
        #    #event.relation.data[self.unit].update({"wg-gwip": gateway_ip})
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
            
    def on_wgrestart_action(self, event):
        err = ''
        try:
            proxy = self.get_ssh_proxy()
            try:
                cmd = ['sudo systemctl restart wg-quick@wg0.service']
                result, err = proxy.run(cmd)
            except:
                cmd = ['sudo wg-quick down wg0']
                result, err = proxy.run(cmd)
                cmd = ['sudo wg-quick start wg0']
                result, err = proxy.run(cmd)
                event.set_results({'restartet wg0': result})
        except:
            event.fail('command failed:' + err)

    def _on_interface_relation_changed(self, event):
    #def _on_proxypeer_relation_changed(self, event):
        parameter = "Hello"
        event.relation.data[self.model.unit]["parameter"] = parameter
        self.model.unit.status = ActiveStatus("Parameter sent: {}".format(parameter))
        err = ''
        result = ''
        sshready = False
        readyint = 0
        try:
            #gateway_ip = self.model.config["ssh-hostname"]
            gateway_ip = self.gw_ip
            #gateway_ip = str(gateway_ip)
            event.relation.data[self.unit].update({"wg-gwip": gateway_ip})
        except:
            pass
        event.relation.data[self.unit].update({"wg-listenport": '51820'})
        try:
            proxy = self.get_ssh_proxy()
            sshready = True
        except:
            sshready = False
            event.relation.data[self.unit].update({"ready": "False"})
        if sshready is False:
            c = randint(1,100)
            event.relation.data[self.unit].update({"counter": str(c)})
        else:
            try:
                cmd = ['sudo test -f /etc/wireguard/publickey && echo "$FILE present"']
                result, err = proxy.run(cmd)
                event.relation.data[self.unit].update({"wg-exists": result})   
            except:
                c = randint(1,100)
                event.relation.data[self.unit].update({"counter": str(c)})
                event.relation.data[self.unit].update({"relation-joined": "failed1"})
            if len(result) > 5:
                try:
                    cmd = ['sudo cat /etc/wireguard/publickey']
                    result, err = proxy.run(cmd)
                    readyint += 1
                except:
                    c = randint(1,100)
                    event.relation.data[self.unit].update({"counter": str(c)})
                    event.relation.data[self.unit].update({"relation-joined": "failed2"})
            else:
                try:                
                    cmd = ['wg genkey | sudo tee /etc/wireguard/privatekey | wg pubkey | sudo tee /etc/wireguard/publickey']
                    result, err = proxy.run(cmd)
                    cmd = ['sudo cat /etc/wireguard/publickey']
                    result, err = proxy.run(cmd)
                    readyint += 1
                    #event.relation.data[self.unit].update({"ready": "True"})
                except:
                    event.relation.data[self.unit].update({"ready": "False"})
                    c = randint(1,100)
                    event.relation.data[self.unit].update({"counter": str(c)})
                #except:
                #    event.relation.data[self.unit].update({"relation-joined": "failed3"})
            try:
                #event.relation.data[self.unit].update({"unit-data": result})
                event.relation.data[self.unit].update({"wg-pubkey": result})
            except:
                event.relation.data[self.unit].update({"relation-joined": "failed"})
            result = ''
            try:
                cmd = ['sudo test -f /etc/wireguard/gateway_ip && echo "$FILE present"']
                result, err = proxy.run(cmd)
            except:
                c = randint(1,100)
                event.relation.data[self.unit].update({"counter": str(c)})
                event.relation.data[self.unit].update({"relation-joined": "failed4"})
            if len(result) > 5:
                try:
                    cmd = ['sudo cat /etc/wireguard/gateway_ip']
                    result, err = proxy.run(cmd)
                    event.relation.data[self.unit].update({"wg-gwip": result})
                    readyint += 1
                except:
                    c = randint(1,100)
                    event.relation.data[self.unit].update({"counter": str(c)})
                    event.relation.data[self.unit].update({"relation-joined": "failed5"})
            result = ''
            try:
                cmd = ['sudo test -f /etc/wireguard/subnet && echo "$FILE present"']
                result, err = proxy.run(cmd)
            except:
                event.relation.data[self.unit].update({"relation-joined": "failed6"})
                c = randint(1,100)
                event.relation.data[self.unit].update({"counter": str(c)})
            if len(result) > 5:
                try:
                    cmd = ['sudo cat /etc/wireguard/subnet']
                    result, err = proxy.run(cmd)
                    event.relation.data[self.unit].update({"wg-subnet": result})
                    readyint += 1
                    if readyint >= 3:
                        event.relation.data[self.unit].update({"ready": "True"})
                except:
                    event.relation.data[self.unit].update({"relation-joined": "failed7"})
                    c = randint(1,100)
                    event.relation.data[self.unit].update({"counter": str(c)})
            else:
                    c = randint(1,100)
                    event.relation.data[self.unit].update({"counter": str(c)})

                
        # get relationship-data
        try:
            leader_pubkey = event.relation.data[event.unit].get("wgpeer-pubkey")
        except KeyError:
            leader_pubkey = None
        try:
            leader_listenport = event.relation.data[event.unit].get("wgpeer-listenport")
        except KeyError:
            leader_listenport = None
        try:
            leader_gwip = event.relation.data[event.unit].get("wgpeer-gwip")
        except KeyError:
            leader_gwip = None
        try:
            leader_subnet = event.relation.data[event.unit].get("wgpeer-subnet")
        except KeyError:
            leader_subnet = None
        try:
            peered = event.relation.data[self.unit].get("wg-peered")
        except KeyError:
            peered = None
        if leader_pubkey and leader_gwip and leader_subnet and leader_listenport and not peered:
            try:
                proxy = self.get_ssh_proxy()
                #cmd = ['echo -e "{}\n\n{}\n\n{}\n{}" | sudo tee /home/ubuntu/wg0.pubkey'.format(leader_pubkey, leader_listenport, leader_gwip, leader_subnet)]
                cmd = ['echo -e "[Peer]\nPublicKey = {}\nAllowedIPs = {}\nEndpoint = {}:{}" | sudo tee -a /etc/wireguard/wg0.conf'.format(leader_pubkey, leader_subnet, leader_gwip, leader_listenport)]
                result, err = proxy.run(cmd)
                cmd = ['sudo wg-quick down wg0']
                result, err = proxy.run(cmd)
                cmd = ['sudo systemctl start wg-quick@wg0.service']
                result, err = proxy.run(cmd)
                event.relation.data[self.unit].update({"wg-peered": "True"})
            except:
                event.relation.data[self.unit].update({"relation-joined": "failed"})
        """

if __name__ == "__main__":
    main(MySSHProxyCharm)



#if __name__ == "__main__":
#    main(SimpleProxyCharm)


#if __name__ == "__main__":
#    main(SampleProxyCharm)
