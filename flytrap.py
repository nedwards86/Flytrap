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


    def tcp_listener(local_ip=get_ip(), port=9000, mode="active",
                     syslog_server="127.0.0.1", syslog_port=514):
        """
        Starts listening on the specified TCP port to try to catch an
        attacker
        :param local_ip: default IP of the local system (str)
        :param port: TCP port to listen on, 9000 by default (int)
        :param mode: Determines if this is an active or passive
        countermeasure. Active mode attempts to automatically block
        attackers. Passive mode does not. Set to active by default.
        (str)
        :param syslog_server: str - IP address of syslog server.
        Defaults to localhost.
        :param syslog_port: int - Port number of syslog server. Defaults
        to 514.
        """
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host_address = (local_ip, port)
        tcp_socket.bind(host_address)
        if host_os == "posix":
            print("Looks like you're on Linux. Checking your firewall package."
                  " You may see a couple warnings below. It's fine.")
            firewall_package = check_linux_firewall()
        else:
            pass

        while True:
            tcp_socket.listen()
            print("-" * 80)
            print("Listening on " + local_ip + ":" + str(port) + ". Ctrl + c "
                                                                 "to abort.")
            connection, attacker_ip = tcp_socket.accept()
            if connection:
                connection.close()
                print(attacker_ip[0] + " took the bait!")
                send_syslog(attacker_ip[0], syslog_server, syslog_port)
                if mode == "active":
                    if host_os == "nt":
                        add_windows_firewall_rule(attacker_ip[0])
                    elif host_os == "posix":
                        add_linux_firewall_rule(attacker_ip[0],
                                                firewall_package)
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
                try:
                    if "active (exited)" in str(subprocess.check_output(
                            'systemctl status ufw', shell=True)):
                        firewall_package = "ufw"
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
                        rule_text, shell=True)) and str(
                    subprocess.check_output("firewall-cmd --reload",
                                            shell=True)):
                    print(attacker_ip +
                          " has been successfully blocked.")
                else:
                    print("Error adding firewall rule to block "
                          + attacker_ip)
            elif firewall_package == "iptables":
                rule_text = "iptables -I INPUT -s " + attacker_ip + " -j DROP"
                subprocess.check_output(rule_text, shell=True)
                print(attacker_ip + " has been successfully blocked.")
            elif firewall_package == "ufw":
                rule_text = "ufw deny from " + attacker_ip
                if "Rule added" in str(subprocess.check_output(rule_text,
                                                               shell=True)):
                    print(attacker_ip + " has been successfully blocked.")
            else:
                pass


    def send_syslog(attacker_ip, syslog_server="127.0.0.1",
                    syslog_port=514):
        # TODO look into seeing if you can support syslog over TLS
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
        logger.critical("flytrap: " + attacker_ip + " took the bait!")


    def menu():
        """
        Interactive menu for users calling the program directly without
        arguments. Gathers input and passes it to tcp_listener()
        """
        # TODO add input validation
        print("-" * 80)
        print("This software provides ABSOLUTELY NO WARRANTY. Use at your "
              "own risk.")
        print("-" * 80)
        print("Press Enter to use default values, or type Q at any time to "
              "quit.")
        print("-" * 80)
        local_ip = input("Enter the local IP address you'd like to use ["
                         "Default - " + get_ip() + "]: ")
        if local_ip == "":
            local_ip = get_ip()
        elif local_ip == "q" or local_ip == "Q":
            print("Exiting.")
            quit()
        else:
            pass

        port = input("Enter the TCP port to listen on [Default - 9000]: ")
        if port == "":
            port = 9000
        elif port == "q" or port == "Q":
            print("Exiting.")
            quit()
        elif int(port) not in range(1, 65535):
            print("Not a valid port number.")
        else:
            pass

        mode = input("Run in active or passive mode [Default - active]: ")
        if mode == "":
            mode = "active"
        elif mode == "q" or mode == "Q":
            print("Exiting.")
            quit()
        else:
            mode = mode.casefold()

        syslog_server = input("Enter the IP address of your syslog server "
                              "[Default - 127.0.0.1]: ")
        if syslog_server == "":
            syslog_server = "127.0.0.1"
        elif syslog_server == "q" or syslog_server == "Q":
            print("Exiting.")
            quit()
        else:
            pass

        syslog_port = input("Enter the syslog port to use [Default - 514]: ")
        if syslog_port == "":
            syslog_port = 514
        elif syslog_port == "q" or syslog_port == "Q":
            print("Exiting.")
            quit()
        elif int(syslog_port) not in range(1, 65545):
            print("Not a valid port number.")
        else:
            pass
        print(local_ip, port, mode, syslog_server, syslog_port)

        tcp_listener(local_ip, port, mode, syslog_server, syslog_port)

    def main():
        if host_os == "nt" or host_os == "posix":
            print("Checking firewall...")
            if host_os == "nt" and check_windows_firewall() is True:
                print("Supported firewall detected.")
                menu()
            elif host_os == "posix" and check_linux_firewall() is not False:
                print("Supported firewall detected.")
                menu()
            else:
                print("No supported firewalls running. Stopping.")
                quit()
        else:
            raise OSError("Operating system is not supported. Use either "
                          "Windows or Linux.")

else:
    print("Can't call functions externally.")

# TODO add options for cli support
# add_linux_firewall_rule("127.0.0.1", "firewalld")

main()
