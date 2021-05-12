if __name__ == "__main__":

    import os
    import subprocess
    import logging.handlers
    import socket

    host_os = os.name


    def get_ip():
        """This genius bit of code comes from fatal_error on
        stackoverflow.

        Finds the IP address of the primary interface of the local host.
        Be aware that using a VPN client will cause the wrong IP to be
        reported.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # doesn't even have to be reachable
            s.connect(('10.255.255.255', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip


    def tcp_listener(local_ip=get_ip(), port=9000, mode="active"):
        """
        Starts listening on the specified TCP port to try to catch an
        attacker
        :param local_ip: default IP of the local system (str)
        :param port: TCP port to listen on, 9000 by default (int)
        :param mode: Determines if this is an active or passive
        countermeasure. Active mode attempts to automatically block
        attackers. Passive mode does not. Set to active by default.
        (str)
        :return: Returns attacker's IP address as str (may or may not be
        in the final version)
        """
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host_address = (local_ip, port)
        tcp_socket.bind(host_address)
        while True:
            tcp_socket.listen()
            connection, attacker_ip = tcp_socket.accept()
            if connection:
                connection.close()
                print(attacker_ip[0] + " accessed the honeyport.")
                send_syslog(attacker_ip[0])
                if mode == "active":
                    if host_os == "nt":
                        add_windows_firewall_rule(attacker_ip[0])
                    elif host_os == "posix":
                        pass
                        # add_linux_firewall_rule(attacker_ip[0])
                    else:
                        raise OSError("OS not supported.")


    def check_windows_firewall():
        """
        Checks to see if the builtin netsh firewall is running.
        """
        if "ON" in str(subprocess.check_output('netsh advfirewall '
                                               'show all state')):
            return True
        else:
            return False


    def add_windows_firewall_rule(attacker_ip):
        """
        Automatically adds a firewall rule blocking the attacker.
        :param attacker_ip: str - IP address of attacker.
        """
        add_rule_result = subprocess.check_output(
            'netsh advfirewall firewall add rule name="flytrap - "'
            + attacker_ip + ' description="Rule automatically added by '
                            'flytrap." dir=in action=block '
                            'protocol=any localip=' + get_ip() +
            ' remoteip=' + attacker_ip)
        if "Ok." in str(add_rule_result):
            print(attacker_ip + " has been successfully blocked.")
        else:
            print("Error adding firewall rule to block " + attacker_ip)


    def check_linux_firewall():
        """
        Checks to see which builtin firewall is running.

        Supported packages: iptables, firewalld

        :return: firewall_package (str) - firewall package that is
        running
        """
        try:
            if "active (running)" in str(subprocess.check_output(
                    'systemctl status firewalld', shell=True)):
                firewall_package = "firewalld"
                return firewall_package
        except subprocess.CalledProcessError:
            try:
                if "active (exited)" in str(subprocess.check_output(
                        'systemctl status iptables', shell=True)):
                    firewall_package = "iptables"
                    return firewall_package
            except subprocess.CalledProcessError:
                return False


    def add_linux_firewall_rule(attacker_ip, firewall_package):
        """
        Automatically adds a firewall rule blocking the attacker.
        :param attacker_ip: str - IP address of attacker.
        :param firewall_package: str - name of firewall package running
        on system.
        """
        if firewall_package is not False:
            if firewall_package == "firewalld":
                rule_text = "firewall-cmd --permanent " \
                            "--add-rich-rule=\"rule family='ipv4' " \
                            "source address='" + attacker_ip + \
                            "' reject\""
                if "success" in str(subprocess.check_output(
                        rule_text)) and str(subprocess.check_output(
                        "firewall-cmd --reload")):
                    print(attacker_ip +
                          " has been successfully blocked.")
                else:
                    print("Error adding firewall rule to block "
                          + attacker_ip)
            elif firewall_package == "iptables":
                pass
            else:
                pass


    def send_syslog(attacker_ip, syslog_server="127.0.0.1",
                    syslog_port=514):
        """
        Sends log to syslog server.
        :param attacker_ip: str - IP address of attacker.
        :param syslog_server: str - IP address of syslog server.
        Defaults to localhost.
        :param syslog_port: int - Port number of syslog server. Defaults
         to 514.
        """
        logger = logging.getLogger("flytrap")
        logger.setLevel(logging.CRITICAL)
        handler = logging.handlers.SysLogHandler(address=(syslog_server,
                                                          syslog_port))
        logger.addHandler(handler)
        logger.critical("flytrap: " + attacker_ip + " accessed the "
                                                        "honeyport.")


    def main():
        if host_os == "nt" or host_os == "posix":
            tcp_listener()
        else:
            raise OSError("Operating system is not supported")

else:
    print("Can't call functions externally.")

add_linux_firewall_rule("127.0.0.1", "firewalld")
