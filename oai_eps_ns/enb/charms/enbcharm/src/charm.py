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
        self.framework.observe(self.on.prepare_enb_build_action, self.prepare_enb_build)
        self.framework.observe(self.on.configure_enb_action, self.configure_enb)
        self.framework.observe(self.on.start_enb_action, self.start_enb)
        self.framework.observe(self.on.stop_enb_action, self.stop_enb)
        self.framework.observe(self.on.restart_enb_action, self.restart_enb)


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
            i = 0
            while i < 15:
                cmd = ['sudo fuser /var/lib/dpkg/lock | echo ${PIPESTATUS[0]}']
                result, err = proxy.run(cmd)
                cmd1 = ['sudo fuser /var/lib/dpkg/lock-frontend | echo ${PIPESTATUS[0]}']
                result1, err1 = proxy.run(cmd1)
                if int(result) == 1 and int(result1) == 1:
                    i = 15
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
          vduHelper.configureSystemInfo('eNB', ' This is the eNB service')
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


if __name__ == "__main__":
    main(MySSHProxyCharm)

