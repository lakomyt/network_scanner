#include <tins/tins.h>
#include <iostream>
#include <regex>
using namespace Tins;

bool match_ip(std::regex const &pattern, std::string const &ip_address){
	std::smatch match;
	if (std::regex_search(ip_address, match, pattern)){
		return true;
	}
	std::cout << std::endl << "Wpisz poprawną wartość" << std::endl << std::endl;
	return false;
}

int main(){
	std::regex ip_pattern("\\d{1,3}(\\.\\d{1,3}){3}");
	std::string ip_string;
	do{
		std::cout << "Podaj adres ip(v4): ";
		std::cin >> ip_string;
	} while (!match_ip(ip_pattern, ip_string));
	std::string netmask_string;
	do{
		std::cout << std::endl << "Podaj maskę podsieci: ";
		std::cin >> netmask_string;
	} while (!match_ip(ip_pattern, netmask_string));


}