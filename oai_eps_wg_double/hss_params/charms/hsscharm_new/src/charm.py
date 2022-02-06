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
import time


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
    subprocess.check_call(["apt", "upgrade", "-y"],)

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



class HSSProxyCharm(SSHProxyCharm):

    def __init__(self, framework, key):
        super().__init__(framework, key)

        # Listen to charm events
        self.framework.observe(self.on.config_changed, self.on_config_changed)
        self.framework.observe(self.on.install, self.on_install)
        self.framework.observe(self.on.start, self.on_start)

        # Listen to the test action event
        #self.framework.observe(self.on.test_action, self.on_test_action)
        
        # HSS application
        self.framework.observe(self.on.prepare_cassandra_hss_build_action, self.on_preparecassandrahssbuild_action)
        self.framework.observe(self.on.configure_cassandra_action, self.on_configurecassandra_action)
        self.framework.observe(self.on.configure_hss_action, self.on_configurehss_action)
        self.framework.observe(self.on.restart_hss_action, self.on_restarthss_action)
        
        # WireGuard application
        self.framework.observe(self.on.generatekeys_action, self.on_generatekeys_action)
        self.framework.observe(self.on.generatewgconfig_action, self.on_generateconfig_action)
        self.framework.observe(self.on.wgup_action, self.on_wireguardup_action)
        self.framework.observe(self.on.wgaddpeer_action, self.on_addpeer_action)
        self.framework.observe(self.on.wgdelpeer_action, self.on_delpeer_action)
        self.framework.observe(self.on.wgrestart_action, self.on_wgrestart_action)
        self.framework.observe(self.on.interfaces6a_relation_changed, self._on_interfaces6a_relation_changed)


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



    def on_preparecassandrahssbuild_action(self, event):
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

       vduHelper.beginBlock('prepare_cassandra_hss_build')
       try:

          # ====== Get HSS parameters ===========================================
          # For a documentation of the installation procedure, see:
          # https://github.com/simula/openairinterface-openair-cn/wiki/OpenAirSoftwareSupport#install-hss

          gitRepository = event.params['hss-git-repository']
          gitCommit     = event.params['hss-git-commit']
          gitDirectory  = 'openair-hss'

          # Prepare network configuration:
          loopback    = 'dummy1'
          configurationloopback = vduHelper.makeInterfaceConfiguration(loopback, IPv4Interface('172.16.6.129/32'), createDummy=True)
          hssS6a_IfName    = 'ens4'
          configurationS6a = vduHelper.makeInterfaceConfiguration(hssS6a_IfName, IPv4Interface('192.168.8.129/24'))
          #configurationS6a = vduHelper.makeInterfaceConfiguration(hssS6a_IfName, IPv4Interface('0.0.0.0/0'))

          # ====== Prepare system ===============================================
          vduHelper.beginBlock('Preparing system')
          vduHelper.configureInterface(hssS6a_IfName, configurationS6a, 61)
          vduHelper.configureInterface(loopback, configurationloopback, 62)
          vduHelper.testNetworking()
          vduHelper.waitForPackageUpdatesToComplete()
          i = 0
                
          #vduHelper.executeFromString("""if [ "'find /etc/apt/sources.list.d -name 'rmescandon-ubuntu-yq-*.list''" == "" ] ; then sudo add-apt-repository -y ppa:rmescandon/yq ; fi""")
          #vduHelper.aptInstallPackages([ 'yq' ])
          #vduHelper.executeFromString("sudo apt update")
          #vduHelper.executeFromString("sudo apt install yq -y")
          vduHelper.endBlock()

          # ====== Prepare sources ==============================================
          vduHelper.beginBlock('Preparing sources')
          vduHelper.fetchGitRepository(gitDirectory, gitRepository, gitCommit)
          vduHelper.endBlock()


          message = vduHelper.endBlock()
          function_set( { 'outout': message } )
       except:
          message = vduHelper.endBlockInException()
          function_fail(message)


    def on_configurecassandra_action(self, event):
       from VDUHelper import VDUHelper
       vduHelper = VDUHelper(self)
       vduHelper.beginBlock('configure_cassandra')
       try:

          # ====== Get HSS parameters ===========================================
          # For a documentation of the installation procedure, see:
          # https://github.com/simula/openairinterface-openair-cn/wiki/OpenAirSoftwareSupport#install-hss

          gitDirectory = 'openair-hss'
          cassandraServerIP = event.params['cassandra-server-ip']

          # ====== Build Cassandra ==============================================
          vduHelper.beginBlock('Building Cassandra')
          #vduHelper.executeFromString("""\
          #export MAKEFLAGS="-j'nproc'" && \\
          #cd  /home/ubuntu/{gitDirectory}/scripts && \\
          #mkdir -p logs && \\
          #sudo rm -f /etc/apt/sources.list.d/cassandra.sources.list  \\
          #./build_cassandra --cassandra-server-ip {cassandraServerIP} --#check-installed-software --force >logs/build_cassandra.log 2>&1
          #""".format(
          #         gitDirectory      = gitDirectory,
          #         cassandraServerIP = cassandraServerIP
          #      ))
          #vduHelper.executeFromString("""export MAKEFLAGS="-j'nproc'" && cd  /home/ubuntu/{gitDirectory}/scripts && mkdir -p logs && sudo echo "deb http://www.apache.org/dist/cassandra/debian 311x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list && curl https://downloads.apache.org/cassandra/KEYS | sudo apt-key add - && sudo apt install apt-transport-https""".format(gitDirectory = gitDirectory))
          #vduHelper.executeFromString("""cd  /home/ubuntu/{gitDirectory}/scripts && sudo apt-get update -y && sudo apt-get install cassandra -y > logs/build_cassandra.log 2>&1""".format(gitDirectory = gitDirectory))
          #vduHelper.executeFromString("""sudo systemctl enable cassandra && sleep 60""")
          #vduHelper.executeFromString("""sudo nodetool status >logs/build_cassandra.log""")
          #vduHelper.executeFromString("""export MAKEFLAGS="-j'nproc'""")
          vduHelper.executeFromString("""cd  /home/ubuntu/{gitDirectory}/scripts && mkdir -p logs""".format(
             gitDirectory = gitDirectory))
          vduHelper.endBlock()

          # ====== Configure Cassandra ==========================================
          vduHelper.beginBlock('Configuring Cassandra')
          vduHelper.executeFromString("""\
    cd  /home/ubuntu/{gitDirectory}/scripts && \\
    sudo update-alternatives --set java /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java && \\
    sudo service cassandra stop && \\
    sudo rm -rf /var/lib/cassandra/data/system/* && \\
    sudo rm -rf /var/lib/cassandra/commitlog/* && \\
    sudo rm -rf /var/lib/cassandra/data/system_traces/* && \\
    sudo rm -rf /var/lib/cassandra/saved_caches/* && \\
    sudo yq w -i /etc/cassandra/cassandra.yaml "cluster_name" "HSS Cluster" && \\
    sudo yq w -i /etc/cassandra/cassandra.yaml "seed_provider[0].class_name" "org.apache.cassandra.locator.SimpleSeedProvider" && \\
    sudo yq w -i /etc/cassandra/cassandra.yaml "seed_provider[0].parameters[0].seeds" "{cassandraServerIP}" && \\
    sudo yq w -i /etc/cassandra/cassandra.yaml "listen_address" "{cassandraServerIP}" && \\
    sudo yq w -i /etc/cassandra/cassandra.yaml "rpc_address" "{cassandraServerIP}" && \\
    sudo yq w -i /etc/cassandra/cassandra.yaml "endpoint_snitch" "GossipingPropertyFileSnitch" && \\
    sudo service cassandra start
    """.format(
             gitDirectory      = gitDirectory,
             cassandraServerIP = cassandraServerIP
          ))
          sleep(300)
          try:
            vduHelper.executeFromString("""\
    cd  /home/ubuntu/{gitDirectory}/scripts && \\
    sudo service cassandra status | cat && \\
    cqlsh --file ../src/hss_rel14/db/oai_db.cql {cassandraServerIP} >logs/oai_db.log 2>&1 && \\
    cqlsh -e "SELECT COUNT(*) FROM vhss.users_imsi;" {cassandraServerIP} >/dev/null && echo "Cassandra is okay!" || echo "Cassandra seems to be unavailable!"
    """.format(
             gitDirectory      = gitDirectory,
             cassandraServerIP = cassandraServerIP
            ))
          except:
             sleep(300)
             vduHelper.executeFromString("""\
    cd  /home/ubuntu/{gitDirectory}/scripts && \\
    sudo service cassandra status | cat && \\
    cqlsh --file ../src/hss_rel14/db/oai_db.cql {cassandraServerIP} >logs/oai_db.log 2>&1 && \\
    cqlsh -e "SELECT COUNT(*) FROM vhss.users_imsi;" {cassandraServerIP} >/dev/null && echo "Cassandra is okay!" || echo "Cassandra seems to be unavailable!"
    """.format(
              gitDirectory      = gitDirectory,
              cassandraServerIP = cassandraServerIP
             ))

          vduHelper.endBlock()

          message = vduHelper.endBlock()
          function_set( { 'outout': message } )
       except:
          message = vduHelper.endBlockInException()
          function_fail(message)

    def on_configurehss_action(self, event):
       from VDUHelper import VDUHelper
       vduHelper = VDUHelper(self)
       vduHelper.beginBlock('configure_hss')
       try:

          # ====== Get HSS parameters ===========================================
          # For a documentation of the installation procedure, see:
          # https://github.com/simula/openairinterface-openair-cn/wiki/OpenAirSoftwareSupport#install-hss

          gitDirectory       = 'openair-hss'
          cassandraServerIP  = event.params['cassandra-server-ip']
          networkRealm       = event.params['network-realm']
          networkOP          = event.params['network-op']
          networkK           = event.params['network-k']
          networkIMSIFirst   = event.params['network-imsi-first']
          networkMSISDNFirst = event.params['network-msisdn-first']
          networkUsers       = int(event.params['network-users'])

          hssS6a_IPv4Address = IPv4Address(event.params['hss-S6a-address'])
          mmeS6a_IPv4Address = IPv4Address(event.params['mme-S6a-address'])

          # ====== Build HSS dependencies =======================================
          vduHelper.beginBlock('Building HSS dependencies')
          # vduHelper.executeFromString("""\
          # export MAKEFLAGS="-j'nproc'" && \\
          i = 0

          vduHelper.executeFromString("""\
    cd  /home/ubuntu/{gitDirectory}/scripts && \\
    mkdir -p logs && \\
    ./build_hss_rel14 --check-installed-software --force >logs/build_hss_rel14-1.log 2>&1
    """.format(gitDirectory = gitDirectory))
          vduHelper.endBlock()

          # ====== Build HSS itself =============================================
          vduHelper.beginBlock('Building HSS itself')
          # vduHelper.executeFromString("""\
          # export MAKEFLAGS="-j'nproc'" && \\
          vduHelper.executeFromString("""\
    cd  /home/ubuntu/{gitDirectory}/scripts && \\
    ./build_hss_rel14 --clean >logs/build_hss_rel14-2.log 2>&1
    """.format(
             gitDirectory       = gitDirectory,
             cassandraServerIP  = cassandraServerIP
          ))
          vduHelper.endBlock()

          vduHelper.beginBlock('add users')
          vduHelper.executeFromString("""\
    cd  /home/ubuntu/{gitDirectory}/scripts && \\
    sudo service cassandra status | cat && \\
    cqlsh --file ../src/hss_rel14/db/oai_db.cql {cassandraServerIP} >logs/oai_db.log 2>&1 && \\
    cqlsh --file ../src/hss_rel14/db/oai_db.cql {cassandraServerIP} >logs/oai_db.log 2>&1 && \\
    cqlsh -e "SELECT COUNT(*) FROM vhss.users_imsi;" {cassandraServerIP} >/dev/null && echo "Cassandra is okay!" || echo "Cassandra seems to be unavailable!"
    """.format(
             gitDirectory      = gitDirectory,
             cassandraServerIP = cassandraServerIP
          ))
          vduHelper.endBlock()


          # ====== Provision users and MME ======================================
          vduHelper.beginBlock('Provisioning users and MME')
          vduHelper.executeFromString("""cd  /home/ubuntu/{gitDirectory}/scripts && sudo ./data_provisioning_users --apn default.{networkRealm} --apn2 internet.{networkRealm} --key {networkK} --imsi-first {networkIMSIFirst} --msisdn-first {networkMSISDNFirst} --mme-identity mme.{networkRealm} --no-of-users {networkUsers} --realm {networkRealm} --truncate True  --verbose True --cassandra-cluster {cassandraServerIP} >logs/data_provisioning_users.log 2>&1 && ./data_provisioning_mme --id 3 --mme-identity mme.{networkRealm} --realm {networkRealm} --ue-reachability 1 --truncate True  --verbose True -C {cassandraServerIP} >logs/data_provisioning_mme.log 2>&1""".format(
             gitDirectory       = gitDirectory,
             cassandraServerIP  = cassandraServerIP,
             networkRealm       = networkRealm,
             networkOP          = networkOP,
             networkK           = networkK,
             networkIMSIFirst   = networkIMSIFirst,
             networkMSISDNFirst = networkMSISDNFirst,
             networkUsers       = networkUsers
          ))
          vduHelper.endBlock()

          # ====== Configure HSS ================================================
          vduHelper.beginBlock('Configuring HSS')
          vduHelper.executeFromString("""\
    cd  /home/ubuntu/{gitDirectory}/scripts && \\
    echo "{hssS6a_IPv4Address}   hss.{networkRealm} hss" | sudo tee -a /etc/hosts && \\
    echo "{mmeS6a_IPv4Address}   mme.{networkRealm} mme" | sudo tee -a /etc/hosts && \\
    openssl rand -out $HOME/.rnd 128 && \\
    echo "====== Configuring Diameter ... ======" && \\
    PREFIX='/usr/local/etc/oai' && \\
    sudo mkdir -m 0777 -p $PREFIX && \\
    sudo mkdir -m 0777 -p $PREFIX/freeDiameter && \\
    sudo cp ../etc/acl.conf ../etc/hss_rel14_fd.conf $PREFIX/freeDiameter && \\
    sudo cp ../etc/hss_rel14.conf ../etc/hss_rel14.json $PREFIX && \\
    sudo sed -i -e 's/#ListenOn/ListenOn/g' $PREFIX/freeDiameter/hss_rel14_fd.conf && \\
    echo "====== Updating configuration files ... ======" && \\
    declare -A HSS_CONF && \\
    HSS_CONF[@PREFIX@]=$PREFIX && \\
    HSS_CONF[@REALM@]='{networkRealm}' && \\
    HSS_CONF[@HSS_FQDN@]='hss.{networkRealm}' && \\
    HSS_CONF[@HSS_HOSTNAME@]='hss' && \\
    HSS_CONF[@cassandra_Server_IP@]='{cassandraServerIP}' && \\
    HSS_CONF[@cassandra_IP@]='{cassandraServerIP}' && \\
    HSS_CONF[@OP_KEY@]='{networkOP}' && \\
    HSS_CONF[@ROAMING_ALLOWED@]='true' && \\
    for K in "${{!HSS_CONF[@]}}"; do echo "K=$K ..." && sudo egrep -lRZ "$K" $PREFIX | xargs -0 -l sudo sed -i -e "s|$K|${{HSS_CONF[$K]}}|g" ; done && \\
    ../src/hss_rel14/bin/make_certs.sh hss {networkRealm} $PREFIX && \\
    echo "====== Updating key ... ======" && \\
    oai_hss -j $PREFIX/hss_rel14.json --onlyloadkey >logs/onlyloadkey.log 2>&1
    """.format(
             gitDirectory       = gitDirectory,
             cassandraServerIP  = cassandraServerIP,
             hssS6a_IPv4Address = hssS6a_IPv4Address,
             mmeS6a_IPv4Address = mmeS6a_IPv4Address,
             networkRealm       = networkRealm,
             networkOP          = networkOP,
             networkK           = networkK,
             networkIMSIFirst   = networkIMSIFirst,
             networkMSISDNFirst = networkMSISDNFirst,
             networkUsers       = networkUsers
          ))
          vduHelper.endBlock()

          # ====== Set up HSS service ===========================================
          vduHelper.beginBlock('Setting up HSS service')
          vduHelper.configureSystemInfo('HSS', 'This is the HSS VNF!')
          vduHelper.createFileFromString('/lib/systemd/system/hss.service', """\
    [Unit]
    Description=Home Subscriber Server (HSS)
    After=ssh.target
    
    [Service]
    ExecStart=/bin/sh -c 'exec /usr/local/bin/oai_hss -j /usr/local/etc/oai/hss_rel14.json >>/var/log/hss.log 2>&1'
    KillMode=process
    Restart=on-failure
    RestartPreventExitStatus=255
    WorkingDirectory= /home/ubuntu/{gitDirectory}/scripts
    
    [Install]
    WantedBy=multi-user.target
    """.format(gitDirectory = gitDirectory))

          vduHelper.createFileFromString('/home/ubuntu/log',
    """\
    #!/bin/sh
    tail -f /var/log/hss.log
    """, True)

          vduHelper.createFileFromString('/home/ubuntu/restart',
    """\
    #!/bin/sh
    DIRECTORY='dirname $0'
    sudo service hss restart && $DIRECTORY/log
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


    def on_restarthss_action(self, event):
       from VDUHelper import VDUHelper
       vduHelper = VDUHelper(self)
       vduHelper.beginBlock('restart_hss')
       try:

          vduHelper.runInShell('sudo service hss restart')

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



    def _on_interfaces6a_relation_changed(self, event): # change to correct juju interface name
        # INPUT correct wireguard interface name:
        wgifname = "wg0"
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
    main(HSSProxyCharm)



