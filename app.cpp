#include "nazwa.h"
using namespace Tins;

void clear_screen(){
	#ifdef _WIN32
	system("cls");
	#else
	system("clear");
	#endif
}

int main(){
	clear_screen();
	int c = 1;
	while (c != 0){
		std::cout << "0. Wyjdź" << std::endl;
		std::cout << "1. Oblicz adres sieci oraz rozgłoszeniowy." << std::endl;
		std::cout << "2. Wyświetl aktywne urządzenia w sieci." << std::endl;
		std::cout << "3. Rozwiąż nazwę domenową." << std::endl;
		std::cout << "4. Przeskanuj porty urządzenia." << std::endl;
		std::cout << "Podaj numer: ";
		std::cin >> c;
		switch (c){
			case 0:{
				clear_screen();
				break;
			}
			case 1:{
				clear_screen();
				std::pair<std::string, std::string> addresses = calc();
				std::cout << std::endl << "Adres IP sieci: " << addresses.first;
				std::cout << "Adres IP rozgłoszeniowy: " << addresses.second << std::endl << std::endl;
				break;
			}
			case 2:{
				clear_screen();
				subnet_scan();
				break;
			}
			case 3:{
				clear_screen();
				dns_resolver();
				break;
			}
			case 4:{
				clear_screen();
				dev_scan();
				break;
			}
			default:{
				clear_screen();
				std::cout << "Nie ma takiego menu.";
				break;
			}
		}
	}
	return 0;
}
