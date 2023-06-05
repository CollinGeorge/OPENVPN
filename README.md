# OpenVPN Server Setup Script


**Usage**

Clone the repository or download the script openvpn_setup.sh to your Linux system.
Open a terminal and navigate to the directory containing the script.
Ensure that you have root privileges by running the script as root. Use the following command:

<pre>
sudo bash openvpn_setup.sh
</pre>

Follow the prompts and provide the required information as requested by the script.
Once the setup is complete, you will have an OpenVPN server running on your system.


**Encryption and Security**

This script focuses on providing a secure setup for your OpenVPN server. Here are some key features related to encryption and security:

**Encryption Algorithms**

During the setup process, you will be prompted to select an encryption algorithm for securing the VPN connections. The available options include:

AES-256-GCM
ChaCha20-Poly1305
AES-256-CBC
AES-128-GCM
AES-128-CBC

Choose an encryption algorithm that meets your security requirements.

**Certificate Profiles**

The script allows you to select a certificate profile that determines the level of security for your OpenVPN server. The available options include:

Low: Basic security settings.
Intermediate: Enhanced security with TLS-DHE-RSA-WITH-AES-256-GCM-SHA384 cipher suite.
High: High-level security with TLS_AES_256_GCM_SHA384 cipher suite and custom certificate profile.
Custom: Allows you to enter a custom cipher suite for advanced security configurations.
Select the appropriate certificate profile based on your security needs.

**Firewall Rules**

The script provides an option to enable firewall rules for additional network security. You can choose between two firewall profiles:

Basic: Provides essential firewall rules allowing OpenVPN traffic and basic network services.
Advanced: Offers more comprehensive firewall rules, including SSH access in addition to OpenVPN traffic and basic network services.
Select the firewall profile that suits your security requirements. The firewall rules are implemented using iptables and saved for persistence.

Please note that while this script aims to provide a secure setup, it's essential to review the generated configuration and consider additional security measures based on your specific use case and environment.

**License**

This script is released under the MIT License. Feel free to modify and distribute it according to your needs. However, please note that this script comes with no warranties, and the author is not liable for any misuse or damages caused by its usage.
