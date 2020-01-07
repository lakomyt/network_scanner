#include <tins/tins.h>
#include <iostream>
#include <regex>
#include <string>
#include <sstream>
using namespace Tins;

bool match_reg(std::regex const &pattern, std::string const &ip_address){
	std::smatch match;
	if (std::regex_search(ip_address, match, pattern)){
		return true;
	}
	std::cout << std::endl << "Wpisz poprawną wartość." << std::endl << std::endl;
	return false;
}

int netmask_to_prefix(std::string netmask_string){
	int netmask_tab[4]{0,0,0,0};
	int c = 0;
	for (int octet=0;octet<=3;octet++){
		do{
			netmask_tab[octet] = netmask_tab[octet]*10+(netmask_string[c]-'0');
			c++;
		} while(netmask_string[c] and netmask_string[c] != '.');
		c++;
	}
	int prefix=0;
	for (int octet=0; octet<=3; octet++){
		int i = netmask_tab[octet];
		while (i != 0){
			if (i % 2 == 1){
				prefix++;
			}
			i = i / 2;
		}
	}
	return prefix;
}

std::pair<std::string, std::string> calc(){
	std::regex ip_pattern("\\d{1,3}\\.\\d{1,3}.\\d{1,3}");
	std::string ip_string;
	do{
		std::cout << std::endl << "Podaj adres ip(v4): ";
		std::cin >> ip_string;
	} while(!match_reg(ip_pattern, ip_string));
	std::string netmask_string;
	do{
		std::cout << "Podaj maskę podsieci: ";
		std::cin >> netmask_string;
	} while(!match_reg(ip_pattern, netmask_string));

	int ip_tab[4]{0,0,0,0};
	int netmask_tab[4]{0,0,0,0};
	int c = 0;
	for (int octet=0;octet<=3;octet++){
		do{

			ip_tab[octet] = ip_tab[octet]*10+(ip_string[c]-'0');

			c++;
		} while(ip_string[c] and ip_string[c] != '.');
		c++;
	}
	c = 0;
	for (int octet=0;octet<=3;octet++){
		do{
			netmask_tab[octet] = netmask_tab[octet]*10+(netmask_string[c]-'0');
			c++;
		} while(netmask_string[c] and netmask_string[c] != '.');
		c++;
	}

	int network_ip_tab[4];
	for (int octet=0;octet<=3;octet++){
		network_ip_tab[octet] = ip_tab[octet] & netmask_tab[octet];
	}
	int broadcast_ip_tab[4];
	for (int octet=0;octet<=3;octet++){
		broadcast_ip_tab[octet] = ip_tab[octet] | (255-netmask_tab[octet]);
	}
	std::stringstream network_ip_string;
	std::stringstream broadcast_ip_string;
	network_ip_string << network_ip_tab[0] << '.' << network_ip_tab[1] << '.' << network_ip_tab[2] << '.' << network_ip_tab[3] << std::endl;
	broadcast_ip_string << broadcast_ip_tab[0] << '.' << broadcast_ip_tab[1] << '.' << broadcast_ip_tab[2] << '.' << broadcast_ip_tab[3] << std::endl;

	return std::make_pair(network_ip_string.str(), broadcast_ip_string.str());
}

void subnet_scan(){
    NetworkInterface iface = NetworkInterface::default_interface();
	NetworkInterface::Info iface_addresses = iface.addresses();
	std::string netmask_string = std::to_string(iface_addresses.netmask);
	IPv4Range scan_range = IPv4Address(iface_addresses.ip_addr) / netmask_to_prefix(netmask_string);
	for (const auto &addr : scan_range){
		if (addr == iface_addresses.ip_addr){
			continue;
		}
		PacketSender sender;
		EthernetII icmp_request = EthernetII("ff:ff:ff:ff:ff:ff",iface_addresses.hw_addr) / IP(addr,iface_addresses.ip_addr) / ICMP();
		std::unique_ptr<PDU> response(sender.send_recv(icmp_request, iface));
		if (response){
			std::cout << "Adres " << addr << " aktywny, ";

			EthernetII arp_request = ARP::make_arp_request(addr, iface_addresses.ip_addr, iface_addresses.hw_addr);
			std::unique_ptr<PDU> response(sender.send_recv(arp_request, iface));
			if (response) {
				const ARP &arp = response->rfind_pdu<ARP>();
				std::cout << "MAC: " << arp.sender_hw_addr() << std::endl;
			}
			std::cout << std::endl;
		}
	}
}


void dns_resolver(){
	std::string domain_name;
	std::cout << "Podaj nazwę domenową: ";
	std::cin >> domain_name;
	std::cout << std::endl << Utils::resolve_domain(domain_name) << std::endl << std::endl;
}

void dev_scan(){
	std::string addr;
	std::regex ip_pattern("\\d{1,3}\\.\\d{1,3}.\\d{1,3}");
	int ports[7] = {22,23,53,80,443,445,3389};
	do{
		std::cout << "Podaj adres ip: ";
		std::cin >> addr;
	} while (!match_reg(ip_pattern, addr));

	NetworkInterface iface = NetworkInterface::default_interface();
	NetworkInterface::Info iface_addresses = iface.addresses();
	PacketSender sender;

	EthernetII ping_req = EthernetII("ff:ff:ff:ff:ff:ff",iface_addresses.hw_addr) / IP(addr,iface_addresses.ip_addr) / ICMP();
	std::unique_ptr<PDU> response(sender.send_recv(ping_req, iface));
	if (response){
		std::cout << std::endl << addr << ", otwarte porty:" << std::endl;
		for (int port_number=0;port_number<7;port_number++){
			IP port_request = IP(addr) / TCP(ports[port_number],25566);
			try {
				port_request.rfind_pdu<TCP>().set_flag(TCP::SYN, 1);
				std::unique_ptr<PDU> response(sender.send_recv(port_request));
				if (response){
					TCP &tcp = response->rfind_pdu<TCP>();
					if (!tcp.get_flag(TCP::RST)){
						std::cout << "Port " << ports[port_number] << std::endl;
					}
				}
			}
			catch (Tins::pdu_not_found) {
				std::cout << "error" << ports[port_number] << std::endl;
				continue;
			}
		}
	}
	std::cout << std::endl;
}