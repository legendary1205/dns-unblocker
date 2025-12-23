#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

[[ $EUID -ne 0 ]] && echo -e "[${red}Error${plain}] Please run this script as root user!" && exit 1

disable_selinux(){
    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

check_sys(){
    local checkType=$1
    local value=$2

    local release=''
    local systemPackage=''

    if [[ -f /etc/redhat-release ]]; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian|raspbian" /etc/issue; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /etc/issue; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian|raspbian" /proc/version; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /proc/version; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /proc/version; then
        release="centos"
        systemPackage="yum"
    fi

    if [[ "${checkType}" == "sysRelease" ]]; then
        if [ "${value}" == "${release}" ]; then
            return 0
        else
            return 1
        fi
    elif [[ "${checkType}" == "packageManager" ]]; then
        if [ "${value}" == "${systemPackage}" ]; then
            return 0
        else
            return 1
        fi
    fi
}

getversion(){
    if [[ -s /etc/redhat-release ]]; then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else
        grep -oE  "[0-9.]+" /etc/issue
    fi
}

centosversion(){
    if check_sys sysRelease centos; then
        local code=$1
        local version="$(getversion)"
        local main_ver=${version%%.*}
        if [ "$main_ver" == "$code" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

get_ip(){
    local IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
    echo ${IP}
}

check_ip(){
    local checkip=$1
    local valid_check=$(echo $checkip|awk -F. '$1<=255&&$2<=255&&$3<=255&&$4<=255{print "yes"}')
    if echo $checkip|grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" >/dev/null; then
        if [ ${valid_check:-no} == "yes" ]; then
            return 0
        else
            echo -e "[${red}Error${plain}] IP $checkip is not valid!"
            return 1
        fi
    else
        echo -e "[${red}Error${plain}] IP format error!"
        return 1
    fi
}

download(){
    local filename=${1}
    echo -e "[${green}Info${plain}] ${filename} downloading configuration now..."
    wget --no-check-certificate -q -t3 -T60 -O ${1} ${2}
    if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] Download ${filename} failed."
        exit 1
    fi
}

error_detect_depends(){
    local command=$1
    local depend=`echo "${command}" | awk '{print $4}'`
    echo -e "[${green}Info${plain}] Starting to install package ${depend}"
    ${command} > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] Failed to install ${red}${depend}${plain}"
        exit 1
    fi
}

config_firewall(){
    if centosversion 6; then
        /etc/init.d/iptables status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            for port in ${ports}; do
                iptables -L -n | grep -i ${port} > /dev/null 2>&1
                if [ $? -ne 0 ]; then
                    iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
                    if [ ${port} == "53" ]; then
                        iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
                    fi
                else
                    echo -e "[${green}Info${plain}] Port ${green}${port}${plain} already enabled."
                fi
            done
            /etc/init.d/iptables save
            /etc/init.d/iptables restart
        else
            echo -e "[${yellow}Warning${plain}] iptables not running or not installed, please enable port ${ports} manually if necessary."
        fi
    else
        systemctl status firewalld > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            default_zone=$(firewall-cmd --get-default-zone)
            for port in ${ports}; do
                firewall-cmd --permanent --zone=${default_zone} --add-port=${port}/tcp
                if [ ${port} == "53" ]; then
                    firewall-cmd --permanent --zone=${default_zone} --add-port=${port}/udp
                fi
                firewall-cmd --reload
            done
        else
            echo -e "[${yellow}Warning${plain}] firewalld not running or not installed, please enable port ${ports} manually if necessary."
        fi
    fi
}

install_check(){
    if check_sys packageManager yum || check_sys packageManager apt; then
        if centosversion 5; then
            return 1
        fi
        return 0
    else
        return 1
    fi
}

install_dependencies(){
    echo "Installing dependency software..."
    if check_sys packageManager yum; then
        echo -e "[${green}Info${plain}] Checking the EPEL repository..."
        if [ ! -f /etc/yum.repos.d/epel.repo ]; then
            yum install -y epel-release > /dev/null 2>&1
        fi
        [ ! -f /etc/yum.repos.d/epel.repo ] && echo -e "[${red}Error${plain}] Install EPEL repository failed, please check it." && exit 1
        [ ! "$(command -v yum-config-manager)" ] && yum install -y yum-utils > /dev/null 2>&1
        [ x"$(yum repolist epel | grep -w epel | awk '{print $NF}')" != x"enabled" ] && yum-config-manager --enable epel > /dev/null 2>&1
        echo -e "[${green}Info${plain}] Checking the EPEL repository complete..."
            yum_depends=(
                autoconf automake curl gettext-devel libev-devel pcre-devel perl pkgconfig rpm-build udns-devel
            )
        for depend in ${yum_depends[@]}; do
            error_detect_depends "yum -y install ${depend}"
        done
        if centosversion 6; then
            error_detect_depends "yum -y groupinstall development"
            error_detect_depends "yum -y install centos-release-scl"
            error_detect_depends "yum -y install devtoolset-6-gcc-c++"
        else
            yum config-manager --set-enabled powertools
            yum groups list development | grep Installed > /dev/null 2>&1
            if [[ $? -eq 0 ]]; then
                yum groups mark remove development -y > /dev/null 2>&1
            fi
            error_detect_depends "yum -y groupinstall development"
        fi
    elif check_sys packageManager apt; then
        apt_depends=(
            autotools-dev cdbs debhelper dh-autoreconf dpkg-dev gettext libev-dev libpcre3-dev libudns-dev pkg-config fakeroot devscripts autoconf
        )
        apt-get -y update
        for depend in ${apt_depends[@]}; do
            error_detect_depends "apt-get -y install ${depend}"
        done
        error_detect_depends "apt-get -y install build-essential"
    fi
}

download_files(){
    if [ "${fastmode}" == "0" ]; then
        echo -e "Do you want to download the latest configuration file? (y/n)"
        echo -e "${yellow}The default configuration file is suitable for most users.${plain}"
        read -e -p "(Default: n):" isdownload
        [[ -z ${isdownload} ]] && isdownload="n"
        case "${isdownload}" in
            [yY][eE][sS]|[yY])
            echo -e "[${green}Info${plain}] You chose: Yes"
            isdownload="y"
            ;;
            *)
            echo -e "[${green}Info${plain}] You chose: No"
            isdownload="n"
        esac
    else
        isdownload="y"
    fi
    
    if [ "${isdownload}" == "y" ]; then
        download /etc/dnsmasq.d/custom_netflix.conf https://raw.githubusercontent.com/myxuchangbin/dnsmasq_sniproxy_install/master/dnsmasq.conf
        download /etc/sniproxy.conf https://raw.githubusercontent.com/myxuchangbin/dnsmasq_sniproxy_install/master/sniproxy.conf
        download /etc/init.d/sniproxy https://raw.githubusercontent.com/myxuchangbin/dnsmasq_sniproxy_install/master/sniproxy.default
        download /lib/systemd/system/sniproxy.service https://raw.githubusercontent.com/myxuchangbin/dnsmasq_sniproxy_install/master/sniproxy.service
        download /tmp/proxy-domains.txt https://raw.githubusercontent.com/myxuchangbin/dnsmasq_sniproxy_install/master/proxy-domains.txt
    else
        cat > /etc/dnsmasq.d/custom_netflix.conf<<-EOF
# Netflix
server=/netflix.com/${publicip}
server=/netflix.net/${publicip}
server=/nflximg.net/${publicip}
server=/nflximg.com/${publicip}
server=/nflxvideo.net/${publicip}
server=/nflxso.net/${publicip}
server=/nflxext.com/${publicip}
EOF

        cat > /etc/sniproxy.conf<<-EOF
user daemon
pidfile /var/run/sniproxy.pid

error_log {
    filename /var/log/sniproxy/sniproxy.log
    priority notice
}

listen 80 {
    proto http
    table http_hosts
    access_log {
        filename /var/log/sniproxy/http_access.log
        priority notice
    }
}

listen 443 {
    proto tls
    table https_hosts
    access_log {
        filename /var/log/sniproxy/https_access.log
        priority notice
    }
}

table http_hosts {
    .* *:80
}

table https_hosts {
    .* *:443
}
EOF

        cat > /etc/init.d/sniproxy<<-EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          sniproxy
# Required-Start:    \$network \$local_fs \$remote_fs
# Required-Stop::    \$remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: SOCKSv5 proxy server
# Description:       SOCKS v5 and SOCKS v4 proxy server
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/local/bin/sniproxy
NAME=sniproxy
DESC=sniproxy
DAEMON_ARGS="-c /etc/sniproxy.conf"

test -x \$DAEMON || exit 0

set -e

case "\$1" in
  start)
    echo -n "Starting \$DESC: "
    \$DAEMON \$DAEMON_ARGS
    echo "\$NAME."
    ;;
  stop)
    echo -n "Stopping \$DESC: "
    killall \$NAME
    echo "\$NAME."
    ;;
  restart)
    echo -n "Restarting \$DESC: "
    killall \$NAME
    sleep 1
    \$DAEMON \$DAEMON_ARGS
    echo "\$NAME."
    ;;
  *)
    echo "Usage: \$SCRIPTNAME {start|stop|restart}" >&2
    exit 1
    ;;
esac

exit 0
EOF

        cat > /lib/systemd/system/sniproxy.service<<-EOF
[Unit]
Description=SNI Proxy
After=network.target

[Service]
Type=forking
PIDFile=/var/run/sniproxy.pid
ExecStart=/usr/local/bin/sniproxy -c /etc/sniproxy.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

        cat > /tmp/proxy-domains.txt<<-EOF
netflix.com
netflix.net
nflximg.net
nflximg.com
nflxvideo.net
nflxso.net
nflxext.com
EOF
    fi
    
    sed -i "s/server_ip/${publicip}/" /etc/dnsmasq.d/custom_netflix.conf
}

build_sniproxy(){
    bit=`uname -m`
    cd /tmp
    if [ -e sniproxy-0.6.1 ]; then
        rm -rf sniproxy-0.6.1
    fi
    download /tmp/sniproxy-0.6.1.tar.gz https://github.com/dlundquist/sniproxy/archive/refs/tags/0.6.1.tar.gz
    tar -zxf sniproxy-0.6.1.tar.gz
    cd sniproxy-0.6.1
    if check_sys packageManager yum; then
        ./autogen.sh && ./configure && make dist
        if centosversion 6; then
            scl enable devtoolset-6 'rpmbuild --define "_sourcedir `pwd`" --define "_topdir /tmp/sniproxy/rpmbuild" --define "debug_package %{nil}" -ba redhat/sniproxy.spec'
        else
            sed -i "s/\%configure CFLAGS\=\"-I\/usr\/include\/libev\"/\%configure CFLAGS\=\"-fPIC -I\/usr\/include\/libev\"/" redhat/sniproxy.spec
            rpmbuild --define "_sourcedir `pwd`" --define "_topdir /tmp/sniproxy/rpmbuild" --define "debug_package %{nil}" -ba redhat/sniproxy.spec
        fi
        yum install -y /tmp/sniproxy/rpmbuild/RPMS/x86_64/sniproxy-*.rpm
    elif check_sys packageManager apt; then
        ./autogen.sh && dpkg-buildpackage
        dpkg -i /tmp/sniproxy_*.deb
    fi
    rm -rf /tmp/sniproxy-0.6.1/
}

install_dnsmasq(){
    echo -e "[${green}Info${plain}] Starting install Dnsmasq..."
    if check_sys packageManager yum; then
        yum install -y dnsmasq
    elif check_sys packageManager apt; then
        apt-get install -y dnsmasq
    fi
    
    if [ ! -d /etc/dnsmasq.d ]; then
        mkdir /etc/dnsmasq.d
    fi
    
    download_files
    
    cat /tmp/proxy-domains.txt | while read line
    do
        echo "server=/${line}/${publicip}" >> /etc/dnsmasq.d/custom_netflix.conf
    done
    
    if check_sys packageManager yum; then
        if centosversion 6; then
            chkconfig dnsmasq on
            service dnsmasq start
        else
            systemctl enable dnsmasq
            systemctl start dnsmasq
        fi
    elif check_sys packageManager apt; then
        systemctl enable dnsmasq
        systemctl start dnsmasq
    fi
    
    echo -e "[${green}Info${plain}] Dnsmasq install complete..."
}

install_sniproxy(){
    echo -e "[${green}Info${plain}] Starting install SNI Proxy..."
    
    install_dependencies
    build_sniproxy
    
    mkdir -p /var/log/sniproxy
    chmod +x /etc/init.d/sniproxy
    
    if check_sys packageManager yum; then
        if centosversion 6; then
            chkconfig sniproxy on
            service sniproxy start
        else
            systemctl enable sniproxy
            systemctl start sniproxy
        fi
    elif check_sys packageManager apt; then
        systemctl enable sniproxy
        systemctl start sniproxy
    fi
    
    echo -e "[${green}Info${plain}] SNI Proxy install complete..."
}

ready_install(){
    echo "Checking your system..."
    if ! install_check; then
        echo -e "[${red}Error${plain}] Your OS is not supported to run it!"
        echo -e "Please change to CentOS 6+/Debian 8+/Ubuntu 16+ and try again."
        exit 1
    fi
    if check_sys packageManager yum; then
        yum makecache
        error_detect_depends "yum -y install net-tools"
        error_detect_depends "yum -y install wget"
    elif check_sys packageManager apt; then
        apt update
        error_detect_depends "apt-get -y install net-tools"
        error_detect_depends "apt-get -y install wget"
    fi
    disable_selinux
    if check_sys packageManager yum; then
        config_firewall
    fi
    echo -e "[${green}Info${plain}] System check complete..."
}

hello(){
    echo ""
    echo -e "${yellow}========================================${plain}"
    echo -e "${yellow}    Rapido Server - DNS Proxy Setup${plain}"
    echo -e "${yellow}    Dnsmasq + SNI Proxy Installer${plain}"
    echo -e "${yellow}========================================${plain}"
    echo -e "${yellow}Supported: CentOS 6+, Debian 8+, Ubuntu 16+${plain}"
    echo ""
}

help(){
    hello
    echo "Usage: bash $0 [-h] [-i] [-f] [-id] [-fd] [-is] [-fs] [-u] [-ud] [-us]"
    echo ""
    echo "  -h , --help                Show help information"
    echo "  -i , --install             Install Dnsmasq + SNI Proxy"
    echo "  -f , --fastinstall         Fast install Dnsmasq + SNI Proxy"
    echo "  -id, --installdnsmasq      Install Dnsmasq only"
    echo "  -fd, --fastinstalldnsmasq  Fast install Dnsmasq only"
    echo "  -is, --installsniproxy     Install SNI Proxy only"
    echo "  -fs, --fastinstallsniproxy Fast install SNI Proxy only"
    echo "  -u , --uninstall           Uninstall Dnsmasq + SNI Proxy"
    echo "  -ud, --undnsmasq           Uninstall Dnsmasq"
    echo "  -us, --unsniproxy          Uninstall SNI Proxy"
    echo ""
}

install_all(){
    ports="53 80 443"
    publicip=$(get_ip)
    hello
    ready_install
    install_dnsmasq
    install_sniproxy
    echo ""
    echo -e "${yellow}========================================${plain}"
    echo -e "${green}Rapido Server${plain}"
    echo -e "${yellow}========================================${plain}"
    echo -e "${green}Dnsmasq + SNI Proxy installation complete!${plain}"
    echo ""
    echo -e "${yellow}Change your DNS to $(get_ip) to access Netflix content.${plain}"
    echo ""
}

only_dnsmasq(){
    ports="53"
    hello
    ready_install
    inputipcount=1
    echo -e "Enter SNIProxy server IP address:"
    read -e -p "(Leave empty for auto-detect public IP): " inputip
    while true; do
        if [ "${inputipcount}" == 3 ]; then
            echo -e "[${red}Error${plain}] Too many incorrect attempts, please restart the script."
            exit 1
        fi
        if [ -z ${inputip} ]; then
            publicip=$(get_ip)
            break
        else
            check_ip ${inputip}
            if [ $? -eq 0 ]; then
                publicip=${inputip}
                break
            else
                echo -e "Please re-enter SNIProxy server IP address:"
                read -e -p "(Leave empty for auto-detect public IP): " inputip
            fi
        fi
        inputipcount=`expr ${inputipcount} + 1`
    done
    install_dnsmasq
    echo ""
    echo -e "${yellow}========================================${plain}"
    echo -e "${green}Rapido Server${plain}"
    echo -e "${yellow}========================================${plain}"
    echo -e "${green}Dnsmasq installation complete!${plain}"
    echo ""
    echo -e "${yellow}Change your DNS to $(get_ip) to access Netflix content.${plain}"
    echo ""
}

only_sniproxy(){
    ports="80 443"
    hello
    ready_install
    publicip=$(get_ip)
    install_sniproxy
    echo ""
    echo -e "${yellow}========================================${plain}"
    echo -e "${green}Rapido Server${plain}"
    echo -e "${yellow}========================================${plain}"
    echo -e "${green}SNI Proxy installation complete!${plain}"
    echo ""
    echo -e "${yellow}Point Netflix domains to $(get_ip) to access content.${plain}"
    echo ""
}

undnsmasq(){
    echo -e "[${green}Info${plain}] Stopping dnsmasq service..."
    if check_sys packageManager yum; then
        if centosversion 6; then
            chkconfig dnsmasq off > /dev/null 2>&1
            service dnsmasq stop || echo -e "[${red}Error${plain}] Failed to stop dnsmasq."
        else
            systemctl disable dnsmasq > /dev/null 2>&1
            systemctl stop dnsmasq || echo -e "[${red}Error${plain}] Failed to stop dnsmasq."
        fi
    elif check_sys packageManager apt; then
        systemctl disable dnsmasq > /dev/null 2>&1
        systemctl stop dnsmasq || echo -e "[${red}Error${plain}] Failed to stop dnsmasq."
    fi
    echo -e "[${green}Info${plain}] Uninstalling dnsmasq..."
    if check_sys packageManager yum; then
        yum remove dnsmasq -y > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] Failed to uninstall ${red}dnsmasq${plain}"
        fi
    elif check_sys packageManager apt; then
        apt-get remove dnsmasq -y > /dev/null 2>&1
        apt-get remove dnsmasq-base -y > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] Failed to uninstall ${red}dnsmasq${plain}"
        fi
    fi
    rm -rf /etc/dnsmasq.d/custom_netflix.conf
    echo -e "[${green}Info${plain}] Dnsmasq uninstall complete..."
}

unsniproxy(){
    echo -e "[${green}Info${plain}] Stopping sniproxy service..."
    if check_sys packageManager yum; then
        if centosversion 6; then
            chkconfig sniproxy off > /dev/null 2>&1
            service sniproxy stop || echo -e "[${red}Error${plain}] Failed to stop sniproxy."
        else
            systemctl disable sniproxy > /dev/null 2>&1
            systemctl stop sniproxy || echo -e "[${red}Error${plain}] Failed to stop sniproxy."
        fi
    elif check_sys packageManager apt; then
        systemctl disable sniproxy > /dev/null 2>&1
        systemctl stop sniproxy || echo -e "[${red}Error${plain}] Failed to stop sniproxy."
    fi
    echo -e "[${green}Info${plain}] Uninstalling sniproxy..."
    if check_sys packageManager yum; then
        yum remove sniproxy -y > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] Failed to uninstall ${red}sniproxy${plain}"
        fi
    elif check_sys packageManager apt; then
        apt-get remove sniproxy -y > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] Failed to uninstall ${red}sniproxy${plain}"
        fi
    fi
    rm -rf /etc/sniproxy.conf
    echo -e "[${green}Info${plain}] SNI Proxy uninstall complete..."
}

confirm(){
    echo -e "${yellow}Continue? (n:cancel/y:continue)${plain}"
    read -e -p "(Default: cancel): " selection
    [ -z "${selection}" ] && selection="n"
    if [ ${selection} != "y" ]; then
        exit 0
    fi
}

if [[ $# = 1 ]];then
    key="$1"
    case $key in
        -i|--install)
        fastmode=0
        install_all
        ;;
        -f|--fastinstall)
        fastmode=1
        install_all
        ;;
        -id|--installdnsmasq)
        fastmode=0
        only_dnsmasq
        ;;
        -fd|--fastinstalldnsmasq)
        fastmode=1
        only_dnsmasq
        ;;
        -is|--installsniproxy)
        fastmode=0
        only_sniproxy
        ;;
        -fs|--fastinstallsniproxy)
        fastmode=1
        only_sniproxy
        ;;
        -u|--uninstall)
        hello
        echo -e "${yellow}Uninstalling Dnsmasq and SNI Proxy...${plain}"
        confirm
        undnsmasq
        unsniproxy
        ;;
        -ud|--undnsmasq)
        hello
        echo -e "${yellow}Uninstalling Dnsmasq...${plain}"
        confirm
        undnsmasq
        ;;
        -us|--unsniproxy)
        hello
        echo -e "${yellow}Uninstalling SNI Proxy...${plain}"
        confirm
        unsniproxy
        ;;
        -h|--help|*)
        help
        ;;
    esac
else
    help
fi
