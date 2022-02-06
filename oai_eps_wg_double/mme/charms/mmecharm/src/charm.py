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

        # WireGuard actions
        self.framework.observe(self.on.generatekeys_action, self.on_generatekeys_action)
        self.framework.observe(self.on.generatewgconfig_action, self.on_generateconfig_action)
        self.framework.observe(self.on.wgup_action, self.on_wireguardup_action)
        self.framework.observe(self.on.wgaddpeer_action, self.on_addpeer_action)
        self.framework.observe(self.on.wgdelpeer_action, self.on_delpeer_action)
        self.framework.observe(self.on.wgrestart_action, self.on_wgrestart_action)
        self.framework.observe(self.on.interfaces6a_relation_changed, self._on_interfaces6a_relation_changed)
        self.framework.observe(self.on.interfaces11_relation_changed, self._on_interfaces11_relation_changed)
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

    def on_preparemmebuild_action(self, event):
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
            loopback = 'dummy2'
            loopback2 = 'dummy3'
            loopback3 = 'dummy4'
            mmeS6a_IfName = 'ens4'
            mmeS11_IfName = 'ens5'
            mmeS1C_IfName = 'ens6'

            #configurationS6a = vduHelper.makeInterfaceConfiguration(mmeS6a_IfName, IPv4Interface('0.0.0.0/0'))
            configurationloopback = vduHelper.makeInterfaceConfiguration(loopback, IPv4Interface('172.16.6.2/32'), createDummy=True)
            configurationloopback2 = vduHelper.makeInterfaceConfiguration(loopback2, IPv4Interface('172.16.1.102/32'), mmeS1C_IPv4Gateway, createDummy=True)
            configurationloopback3 = vduHelper.makeInterfaceConfiguration(loopback3, IPv4Interface('192.168.247.102/32'), createDummy=True)
            #configurationS6a = vduHelper.makeInterfaceConfiguration(mmeS6a_IfName, IPv4Interface('172.16.6.2/24'))
            configurationS6a = vduHelper.makeInterfaceConfiguration(mmeS6a_IfName, IPv4Interface('192.168.8.2/24'))
            configurationS11 = vduHelper.makeInterfaceConfiguration(mmeS11_IfName, IPv4Interface('192.168.10.2/24'))
            #configurationS11 = vduHelper.makeInterfaceConfiguration(mmeS11_IfName, IPv4Interface('172.16.1.102/24'))
            #configurationS11 = vduHelper.makeInterfaceConfiguration(mmeS11_IfName, IPv4Interface('0.0.0.0/0'))
            #configurationS1C = vduHelper.makeInterfaceConfiguration(mmeS1C_IfName, mmeS1C_IPv4Interface,mmeS1C_IPv4Gateway, mmeS1C_IPv6Interface, mmeS1C_IPv6Gateway)
            configurationS1C = vduHelper.makeInterfaceConfiguration(mmeS1C_IfName, mmeS1C_IPv4Interface, mmeS1C_IPv6Interface, mmeS1C_IPv6Gateway)

            # S10 dummy interface:
            mmeS10_IfName = 'dummy0'
            configurationS10 = vduHelper.makeInterfaceConfiguration(mmeS10_IfName, IPv4Interface('192.168.100.110/24'), createDummy=True)

            # ====== Prepare system ===============================================
            vduHelper.beginBlock('Preparing system')
            vduHelper.configureInterface(mmeS6a_IfName, configurationS6a, 61)
            vduHelper.configureInterface(mmeS11_IfName, configurationS11, 62)
            vduHelper.configureInterface(mmeS1C_IfName, configurationS1C, 63)
            vduHelper.configureInterface(mmeS10_IfName, configurationS10, 64)
            vduHelper.configureInterface(loopback, configurationloopback, 65)
            vduHelper.configureInterface(loopback2, configurationloopback2, 66)
            vduHelper.configureInterface(loopback3, configurationloopback3, 66)
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
            #mmeS10_IPv4Interface = IPv4Interface('192.168.10.110/24')
            mmeS10_IPv4Interface = IPv4Interface('192.168.100.110/24')
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
            #mmeS6a_IfName = 'ens4'
            mmeS6a_IfName = 'lo:2'
            #mmeS11_IfName = 'ens5'
            mmeS11_IfName = 'lo:3'
            #mmeS1C_IfName = 'ens6'
            mmeS1C_IfName = 'lo:4'
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
            vduHelper.configureSystemInfo('MME', 'This is the MME VNF!')
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

    def _on_interfaces6a_relation_changed(self, event): # change to correct juju interface name
        # INPUT correct wireguard interface name:
        wgifname = "wg0"
        self.wgrelation(event, wgifname)


    def _on_interfaces11_relation_changed(self, event): # change to correct juju interface name
        # INPUT correct wireguard interface name:
        wgifname = "wg1"
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



#if __name__ == "__main__":
#    main(SimpleProxyCharm)


#if __name__ == "__main__":
#    main(SampleProxyCharm)
