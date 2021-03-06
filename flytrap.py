if __name__ == "__main__":

    import os
    import subprocess
    import logging.handlers
    import socket
    import ipaddress

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


    def verify_ip_address(ip):
        """Verifies that the provided IP address is valid. Works on both IPv4
        and IPv6. Returns True if the address is valid, or False if it isn't.

        :param ip: str - passed IP address for validation
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False


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
        if ":" in local_ip:
            ipv6 = True
        else:
            ipv6 = False

        if ipv6 is True:
            tcp_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        if ipv6 is False:
            tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        host_address = (local_ip, port)
        try:
            tcp_socket.bind(host_address)
        except OSError:
            print("The IP address provided to listen on does not live on this "
                  "host. Quitting.")
            quit()
        if host_os == "posix":
            print("Looks like you're on Linux. You may see a couple warnings "
                  "below depending what distro you're on. It's fine.")
            firewall_package = check_linux_firewall()
        else:
            pass
        print("-" * 80)
        print("Listening on " + local_ip + ":" + str(port) + ". Ctrl + c "
                                                             "to abort.")
        try:
            while True:
                tcp_socket.listen()
                connection, attacker_ip = tcp_socket.accept()
                if connection:
                    connection.close()
                    print(attacker_ip[0] + " took the bait!")
                    send_syslog(attacker_ip[0], syslog_server, syslog_port)
                    if mode == "active":
                        if host_os == "nt":
                            add_windows_firewall_rule(attacker_ip[0], local_ip)
                        elif host_os == "posix":
                            add_linux_firewall_rule(attacker_ip[0],
                                                    firewall_package)
                        else:
                            raise OSError("OS not supported.")
        except KeyboardInterrupt:
            print("\nQuitting.")
            quit()


    def check_windows_firewall():
        """
        Checks to see if the builtin netsh firewall is running.
        """
        if "ON" in str(subprocess.check_output('netsh advfirewall '
                                               'show all state')):
            return True
        else:
            return False


    def add_windows_firewall_rule(attacker_ip, listening_ip):
        """
        Automatically adds a firewall rule blocking the attacker.
        :param attacker_ip: str - IP address of attacker.
        :param listening_ip: str - IP address flytrap is listening on.
        """
        try:
            add_rule_result = subprocess.check_output(
                'netsh advfirewall firewall add rule name="flytrap - "'
                + attacker_ip + ' description="Rule automatically added by '
                                'flytrap." dir=in action=block '
                                'protocol=any localip=' + listening_ip +
                ' remoteip=' + attacker_ip)
            if "Ok." in str(add_rule_result):
                print(attacker_ip + " has been successfully blocked.")
            else:
                print("Error adding firewall rule to block " + attacker_ip)
        except subprocess.CalledProcessError:
            print("Unable to add firewall rule. Flytrap needs to be run as "
                  "administrator.")


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

        try:
            if firewall_package is not False:
                if firewall_package == "firewalld":
                    if ":" in attacker_ip:
                        rule_text = "firewall-cmd --permanent " \
                                    "--add-rich-rule=\"rule family='ipv6' " \
                                    "source address='" + attacker_ip + \
                                    "' reject\""
                    else:
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
                    if ":" in attacker_ip:
                        rule_text = "ip6tables -I INPUT -s " + attacker_ip + \
                                    " -j DROP"
                    else:
                        rule_text = "iptables -I INPUT -s " + attacker_ip + \
                                    " -j DROP"
                    subprocess.check_output(rule_text, shell=True)
                    print(attacker_ip + " has been successfully blocked.")
                elif firewall_package == "ufw":
                    rule_text = "ufw prepend deny from " + attacker_ip
                    if "Rule added" in str(subprocess.check_output(rule_text,
                                                                shell=True)):
                        print(attacker_ip + " has been successfully blocked.")
                else:
                    pass
        except subprocess.CalledProcessError:
            print("Unable to add firewall rule. Flytrap needs to be run as "
                  "root.")


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
        logger.critical("flytrap: " + attacker_ip + " took the bait!")


    def menu(no_firewalls=False):
        """
        Interactive menu for users calling the program directly without
        arguments. Gathers input and passes it to tcp_listener()
        :param no_firewalls: bool - If the system could not find a supported
        firewall running, this is used by the menu to force the application
        into passive mode.
        """
        print("-" * 80)
        print("Flytrap v1.0.0 \"Sawtooth\"")
        print("-" * 80)
        print("This software provides ABSOLUTELY NO WARRANTY. Use at your "
              "own risk.")
        print("-" * 80)
        print("Press Enter to use default values, or type Q at any time to "
              "quit.")
        print("-" * 80)
        try:
            while True:
                local_ip = input("Enter the local IP address (excluding IPv6 "
                                 "link-local addresses) you'd like to use ["
                                 "Default - " + get_ip() + "]: ")
                if local_ip == "":
                    local_ip = get_ip()
                    break
                elif local_ip.casefold() == "q" or local_ip.casefold() == \
                        "quit":
                    print("Exiting.")
                    quit()
                elif verify_ip_address(local_ip) is True:
                    break
                else:
                    print("Please enter a valid IP address.")
        except KeyboardInterrupt:
            print("\nQuitting.")
            quit()

        try:
            while True:
                try:
                    port = input("Enter the TCP port to listen on [Default - "
                                 "9000]: ")
                    if port == "":
                        port = 9000
                        break
                    elif port.casefold() == "q" or port.casefold() == "quit":
                        print("Exiting.")
                        quit()
                    elif int(port) not in range(0, 65536):
                        print("Please enter a valid port number. Valid ports "
                              "are 0 - 65535")
                    else:
                        port = int(port)
                        break
                except ValueError:
                    print("Please enter a valid port number. Valid ports are "
                          "0 - 65535")
        except KeyboardInterrupt:
            print("\nQuitting.")
            quit()

        try:
            if no_firewalls is True:
                mode = "passive"
            else:
                while True:
                    mode = input("Run in active or passive mode [Default - "
                                 "active]: ")
                    if mode == "":
                        mode = "active"
                        break
                    elif mode.casefold() == "q" or mode.casefold() == "quit":
                        print("Exiting.")
                        quit()
                    elif mode.casefold() == "active" or mode.casefold() == \
                            "passive":
                        mode = mode.casefold()
                        break
                    else:
                        print("Please enter either active or passive.")
        except KeyboardInterrupt:
            print("\nQuitting.")
            quit()

        try:
            while True:
                syslog_server = input("Enter the IP address of your syslog "
                                      "server [Default - 127.0.0.1]: ")
                if syslog_server == "":
                    syslog_server = "127.0.0.1"
                    break
                elif syslog_server.casefold() == "q" or syslog_server.casefold\
                            () == "quit":
                    print("Exiting.")
                    quit()
                elif verify_ip_address(syslog_server) is True:
                    break
                else:
                    print("Please enter a valid IP address.")
        except KeyboardInterrupt:
            print("\nQuitting.")
            quit()

        try:
            while True:
                try:
                    syslog_port = input("Enter the syslog port to use [Default"
                                        " - 514]: ")
                    if syslog_port == "":
                        syslog_port = 514
                        break
                    elif syslog_port.casefold() == "q" or syslog_port.\
                            casefold() == "quit":
                        print("Exiting.")
                        quit()
                    elif int(syslog_port) not in range(0, 65536):
                        print("Please enter a valid port number. Valid ports "
                              "are 0 - 65535")
                    else:
                        syslog_port = int(syslog_port)
                        break
                except ValueError:
                    print("Please enter a valid port number. Valid ports are "
                          "0 - 65535")

        except KeyboardInterrupt:
            print("\nQuitting.")
            quit()

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
                print("WARNING: No supported firewalls running. Flytrap will "
                      "only run in passive mode.")
                no_firewalls = True
                menu(no_firewalls)
        else:
            raise OSError("Operating system is not supported. Use either "
                          "Windows or Linux.")


else:
    print("Can't call functions externally.")

main()
