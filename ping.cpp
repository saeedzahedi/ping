//
// ping.cpp : implements a connectivity check with ping function
// ~~~~~~~~
//

//#define BOOST_ASIO_ENABLE_HANDLER_TRACKING

#include "ping.hpp"

// bool ping(hex_ip4_address, count, timer_millisecond)

int main()
{
	if (ping(0x5B626262, 5, 100))
		std::cout << "\n Ping Successful.\n";
	else
		std::cout << "\n check network\n";
}
