#!/bin/bash

# Check if the script is being run as root
if [ "$EUID" -ne 0 ]; then
   echo "Please run as root"
   exit 1
fi

# Install necessary packages
if ! apt-get update && apt-get -y install openvpn easy-rsa openssl; then
  echo "Failed to install packages. Aborting."
  exit 1
fi

# Prompt user if they want to create client certificates
while true; do
  read -p "Do you want to create client certificates? (yes or no): " CREATE_CLIENT_CERTS
  case $CREATE_CLIENT_CERTS in
    [Yy][Ee][Ss]|[Yy])
      CREATE_CLIENT_CERTS=true
      break
      ;;
    [Nn][Oo]|[Nn])
      CREATE_CLIENT_CERTS=false
      break
      ;;
    *)
      echo "Please enter yes or no."
      ;;
  esac
done

if $CREATE_CLIENT_CERTS; then
  echo "Generating client certificates..."
  echo ""

  # Prompt the user for encryption and certificate options
  PS3="Select an encryption algorithm: "
  options=("AES-256-GCM" "ChaCha20-Poly1305" "AES-256-CBC" "AES-128-GCM" "AES-128-CBC")
  select ENCRYPTION in "${options[@]}"
  do
    case $ENCRYPTION in
      AES-256-GCM|ChaCha20-Poly1305|AES-256-CBC|AES-128-GCM|AES-128-CBC)
        break
        ;;
      *)
        echo "Invalid option. Please select a valid encryption algorithm."
        ;;
    esac
  done

  echo ""

  PS3="Select a certificate profile: "
  options=("low" "intermediate" "high" "custom")
  select CERTIFICATE_PROFILE in "${options[@]}"
  do
    case $CERTIFICATE_PROFILE in
      low|intermediate|high|custom)
        break
        ;;
      *)
        echo "Invalid option. Please select a valid certificate profile."
        ;;
    esac
  done

  echo ""

  echo ""
echo "Configuring VPN subnets..."
PS3="Select a VPN subnet: "
options=("10.8.0.0/24: This is the default subnet range used by OpenVPN, a popular open-source VPN solution. It allows for up to 256 IP addresses, and is often used for small to medium-sized networks." 
          "172.16.0.0/12: This is a private IP address range that is commonly used for local networks and VPNs. It allows for up to 1,048,576 IP addresses, and is often used for larger networks."
          "192.168.0.0/16: This is another private IP address range that is commonly used for local networks and VPNs. It allows for up to 65,536 IP addresses, and is often used for small to medium-sized networks.")
select VPN_SUBNET in "${options[@]}"
do
  case $VPN_SUBNET in
    "10.8.0.0/24: This is the default subnet range used by OpenVPN, a popular open-source VPN solution. It allows for up to 256 IP addresses, and is often used for small to medium-sized networks."|"172.16.0.0/12: This is a private IP address range that is commonly used for local networks and VPNs. It allows for up to 1,048,576 IP addresses, and is often used for larger networks."|"192.168.0.0/16: This is another private IP address range that is commonly used for local networks and VPNs. It allows for up to 65,536 IP addresses, and is often used for small to medium-sized networks.")
      break
      ;;
    *)
      echo "Invalid option. Please select a valid VPN subnet."
      ;;
  esac
done

echo ""
echo "Setting up the OpenVPN server..."
mkdir -p /etc/openvpn/server
cp /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz /etc/openvpn/server/
gunzip /etc/openvpn/server/server.conf.gz

sed -i "s|^;tls-auth ta.key 0|tls-auth ta.key 0|" /etc/openvpn/server/server.conf
sed -i "s|^;cipher AES-256-GCM|cipher $ENCRYPTION|" /etc/openvpn/server/server.conf
sed -i "s|^;user nobody|user nobody\n      group nogroup|" /etc/openvpn/server/server.conf
sed -i "s|^dh dh2048.pem|dh dh.pem|" /etc/openvpn/server/server.conf
sed -i "s|^tls-version-min 1.2|tls-version-min $TLS_VERSION|" /etc/openvpn/server/server.conf
sed -i "s|^cert server.crt|cert $SERVER_CERT|" /etc/openvpn/server/server.conf
sed -i "s|^key server.key|key $SERVER_KEY|" /etc/openvpn/server/server.conf
sed -i "s|^;log /var/log/openvpn.log|log /var/log/openvpn.log|" /etc/openvpn/server/server.conf
sed -i "s|^;push \"redirect-gateway def1 bypass-dhcp\"|push \"redirect-gateway def1 bypass-dhcp\"\npush \"dhcp-option DNS 8.8.8.8\"\npush \"dhcp-option DNS 8.8.4.4\"|" /etc/openvpn/server/server.conf
sed -i "s|^server 10.8.0.0 255.255.255.0|server $VPN_SUBNET|" /etc/openvpn/server/server.conf
sed -i "s|^;client-config-dir ccd|client-config-dir /etc


  if [[ $CERTIFICATE_PROFILE == "custom" ]]; then
    while true; do
      read -p "Enter custom cipher suite (e.g. TLS_CHACHA20_POLY1305_SHA256): " CUSTOM_CIPHER_SUITE
      if [ -n "$CUSTOM_CIPHER_SUITE" ]; then
        break
      else
        echo "Invalid cipher suite. Please enter a valid cipher suite."
      fi
    done
  fi

  echo ""
  echo "Setting up the easy-rsa directory..."
  make-cadir ./easy-rsa
  cd ./easy-rsa

  echo ""
  echo "Configuring the easy-rsa variables..."
  echo "set_var EASYRSA_KEY_SIZE 4096" >> vars
  echo "set_var EASYRSA_ALGO ec" >> vars
  echo "set_var EASYRSA_CURVE secp521r1" >> vars
  echo "set_var EASYRSA_DIGEST sha512" >> vars

  echo ""
  echo "Generating a client key pair and certificate..."
  ./easyrsa gen-req client nopass
  ./easyrsa sign-req client client

  echo ""
  echo "Copying the client key pair and certificate to the current directory..."
  cp pki/ca.crt ../client.crt
  cp pki/issued/client.crt ../client.crt
  cp pki/private/client.key ../client

# Prompt the user for TLS version
while true; do
  read -p "Select a TLS version (1.2 or 1.3): " TLS_VERSION
  case $TLS_VERSION in
    1.2|1.3)
      break
      ;;
    *)
      echo "Invalid TLS version. Please enter 1.2 or 1.3."
      ;;
  esac
done

# Prompt the user for encryption and certificate options
while true; do
  read -p "Select an encryption algorithm (AES-256-GCM, ChaCha20-Poly1305, AES-256-CBC, AES-128-GCM, or AES-128-CBC): " ENCRYPTION
  case $ENCRYPTION in
    AES-256-GCM|ChaCha20-Poly1305|AES-256-CBC|AES-128-GCM|AES-128-CBC)
      break
      ;;
    *)
      echo "Invalid encryption algorithm. Please enter AES-256-GCM, ChaCha20-Poly1305, AES-256-CBC, AES-128-GCM, or AES-128-CBC."
      ;;
  esac
done

while true; do
  read -p "Select a certificate profile (low, intermediate, high, custom): " CERTIFICATE_PROFILE
  case $CERTIFICATE_PROFILE in
    low|intermediate|high|custom)
      break
      ;;
    *)
      echo "Invalid certificate profile. Please enter low, intermediate, high, or custom."
      ;;
  esac
done

if [[ $CERTIFICATE_PROFILE == "custom" ]]; then
  while true; do
    read -p "Enter custom cipher suite (e.g. TLS_CHACHA20_POLY1305_SHA256): " CUSTOM_CIPHER_SUITE
    if [ -n "$CUSTOM_CIPHER_SUITE" ]; then
      break
    else
      echo "Invalid cipher suite. Please enter a valid cipher suite."
    fi
  done
fi

# Set up the easy-rsa directory
make-cadir /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa

# Configure the easy-rsa variables
echo "set_var EASYRSA_KEY_SIZE 4096" >> vars
echo "set_var EASYRSA_ALGO ec" >> vars
echo "set_var EASYRSA_CURVE secp521r1" >> vars
echo "set_var EASYRSA_DIGEST sha512" >> vars

# Generate a CA certificate
./easyrsa init-pki
./easyrsa build-ca

# Generate a server key pair and certificate
./easyrsa gen-req server nopass
./easyrsa sign-req server server

# Generate a Diffie-Hellman (DH) key exchange file
openssl dhparam -out /etc/openvpn/dh.pem 4096

# Generate a certificate revocation list (CRL)
./easyrsa gen-crl

# Copy the server key pair and certificate to the OpenVPN directory
cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/
cp /etc/openvpn/easy-rsa/pki/private/server.key /etc/openvpn/
cp /etc/openvpn/easy-rsa/pki/issued/server.crt /etc/openvpn/
cp /etc/openvpn/dh.pem /etc/openvpn/
cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/

# Configure the OpenVPN server
cat << EOF > /etc/openvpn/server.conf
port 1194
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
keepalive 10 120
cipher $ENCRYPTION
auth SHA512
tls-version-min $TLS_VERSION
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
EOF

# Add the certificate profile options
if [[ $CERTIFICATE_PROFILE == "intermediate" ]]; then
  echo "tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384" >> /etc/openvpn/server.conf
elif [[ $CERTIFICATE_PROFILE == "high" ]]; then
  echo "tls-ciphersuites TLS_AES_256_GCM_SHA384" >> /etc/openvpn/server.conf
  echo "tls-cert-profile $CERTIFICATE_PROFILE" >> /etc/openvpn/server.conf
fi

# Restart the OpenVPN service
systemctl restart openvpn

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/#net.ipv4.ip_forward/net.ipv4.ip_forward/g' /etc/sysctl.conf

# Prompt the user for firewall rules
while true; do
  read -p "Enable firewall rules (y/n): " FIREWALL_RULES
  case $FIREWALL_RULES in
    y|Y)
      FIREWALL_ENABLED=true
      break
      ;;
    n|N)
      FIREWALL_ENABLED=false
      break
      ;;
    *)
      echo "Invalid option. Please enter y or n."
      ;;
  esac
done

# Configure firewall rules if enabled
if [ "$FIREWALL_ENABLED" = true ]; then
  # Prompt the user for firewall options
  while true; do
    read -p "Select a firewall profile (basic or advanced): " FIREWALL_PROFILE
    case $FIREWALL_PROFILE in
      basic|advanced)
        break
        ;;
      *)
        echo "Invalid firewall profile. Please enter basic or advanced."
        ;;
    esac
  done

  # Configure the firewall rules
  if [ "$FIREWALL_PROFILE" = "basic" ]; then
    # Basic firewall rules
    iptables -N LOGGING
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -A INPUT -p udp --dport 1194 -j ACCEPT
    iptables -A INPUT -p icmp -j ACCEPT
    iptables -A INPUT -j LOGGING
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -j LOGGING
    iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "iptables-dropped: " --log-level 4
    iptables -A LOGGING -j DROP
  elif [ "$FIREWALL_PROFILE" = "advanced" ]; then
    # Advanced firewall rules
    iptables -N LOGGING
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -A INPUT -p udp --dport 1194 -j ACCEPT
    iptables -A INPUT -p icmp -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT # allow SSH
    iptables -A INPUT -j LOGGING
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -j LOGGING
    iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "iptables-dropped: " --log-level 4
    iptables -A LOGGING -j DROP
  fi

  # Save firewall rules
  iptables-save > /etc/iptables/rules.v4

  # Enable firewall on boot
  systemctl enable netfilter-persistent
fi

echo "OpenVPN server setup complete!"
