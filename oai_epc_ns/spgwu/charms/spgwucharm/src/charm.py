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
            spgwuSGi_IfName = 'ens6'

            configurationSXab = vduHelper.makeInterfaceConfiguration(spgwuSXab_IfName, IPv4Interface('172.55.55.102/24'),metric=261)
            configurationS1U = vduHelper.makeInterfaceConfiguration(spgwuS1U_IfName, spgwuS1U_IPv4Interface, spgwuS1U_IPv4Gateway, metric=262)
            configurationSGi = vduHelper.makeInterfaceConfiguration(spgwuSGi_IfName, spgwuSGi_IPv4Interface, spgwuSGi_IPv4Gateway, spgwuSGi_IPv6Interface, spgwuSGi_IPv6Gateway, metric=200, pdnInterface='pdn')

            # ====== Prepare system ===============================================
            vduHelper.beginBlock('Preparing system')
            vduHelper.configureInterface(spgwuSXab_IfName, configurationSXab, 61)
            vduHelper.configureInterface(spgwuS1U_IfName, configurationS1U, 62)
            vduHelper.configureInterface(spgwuSGi_IfName, configurationSGi, 63)
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

          spgwuSXab_IfName = 'ens4'
          spgwuS1U_IfName  = 'ens5'
          spgwuSGi_IfName  = 'ens6'

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


          # ====== Configure HENCSAT QoS Setup ==================================
          vduHelper.beginBlock('Configuring QoS Setup')
          vduHelper.runInShell('sudo mkdir -p /etc/hencsat')
          vduHelper.createFileFromString('/etc/hencsat/hencsat-router.conf',
    """# HENCSAT Router Configuration
    
    ROUTER_INTERFACE_LEFT=ens6
    ROUTER_INTERFACE_RIGHT=pdn
    """)
          
          #vduHelper.aptInstallPackages([ 'hencsat-router' ], False)
          #vduHelper.endBlock()
          vduHelper.aptInstallPackages([ 'hencsat-router' ], False)
          vduHelper.endBlock()


          # ====== Set up SPGW-U service ========================================
          vduHelper.beginBlock('Setting up SPGW-U service')
          vduHelper.configureSystemInfo('SPGW-U', ' This is the SPGW-U of the SimulaMet OAI VNF!')
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
    sudo service spgwu restart && sleep 5 && sudo service hencsat-router restart && $DIRECTORY/log
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


if __name__ == "__main__":
    main(MySSHProxyCharm)



#if __name__ == "__main__":
#    main(SimpleProxyCharm)


#if __name__ == "__main__":
#    main(SampleProxyCharm)
