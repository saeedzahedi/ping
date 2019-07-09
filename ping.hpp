//
// ping.hpp : implements a connectivity check with ping function
// bool ping(hex_ip4_address, count, timer_millisecond)
//

#ifndef PING_HPP
#define PING_HPP

#include <boost/asio.hpp>
#include <boost/asio/ip/address_v4.hpp>		//used by IP4 header
#include <boost/bind.hpp>
#include <iostream>

// Packet header for IPv4.
//
// The wire format of an IPv4 header is:
// 
// 0               8               16                             31
// +-------+-------+---------------+------------------------------+      ---
// |       |       |               |                              |       ^
// |version|header |    type of    |    total length in bytes     |       |
// |  (4)  | length|    service    |                              |       |
// +-------+-------+---------------+-+-+-+------------------------+       |
// |                               | | | |                        |       |
// |        identification         |0|D|M|    fragment offset     |       |
// |                               | |F|F|                        |       |
// +---------------+---------------+-+-+-+------------------------+       |
// |               |               |                              |       |
// | time to live  |   protocol    |       header checksum        |   20 bytes
// |               |               |                              |       |
// +---------------+---------------+------------------------------+       |
// |                                                              |       |
// |                      source IPv4 address                     |       |
// |                                                              |       |
// +--------------------------------------------------------------+       |
// |                                                              |       |
// |                   destination IPv4 address                   |       |
// |                                                              |       v
// +--------------------------------------------------------------+      ---
// |                                                              |       ^
// |                                                              |       |
// /                        options (if any)                      /    0 - 40
// /                                                              /     bytes
// |                                                              |       |
// |                                                              |       v
// +--------------------------------------------------------------+      ---

class ipv4_header
{
private:
	unsigned char rep_[60];

	unsigned short decode(int a, int b) const { return (rep_[a] << 8) + rep_[b]; }

public:
	ipv4_header() { std::fill(rep_, rep_ + sizeof(rep_), 0); }
	unsigned char version() const { return (rep_[0] >> 4) & 0xF; }
	unsigned short header_length() const { return (rep_[0] & 0xF) * 4; }
	unsigned char type_of_service() const { return rep_[1]; }
	unsigned short total_length() const { return decode(2, 3); }
	unsigned short identification() const { return decode(4, 5); }
	bool dont_fragment() const { return (rep_[6] & 0x40) != 0; }
	bool more_fragments() const { return (rep_[6] & 0x20) != 0; }
	unsigned short fragment_offset() const { return decode(6, 7) & 0x1FFF; }
	unsigned int time_to_live() const { return rep_[8]; }
	unsigned char protocol() const { return rep_[9]; }
	unsigned short header_checksum() const { return decode(10, 11); }

	boost::asio::ip::address_v4 source_address() const
	{
		boost::asio::ip::address_v4::bytes_type bytes = { { rep_[12], rep_[13], rep_[14], rep_[15] } };
		return boost::asio::ip::address_v4(bytes);
	}

	boost::asio::ip::address_v4 destination_address() const
	{
		boost::asio::ip::address_v4::bytes_type bytes = { { rep_[16], rep_[17], rep_[18], rep_[19] } };
		return boost::asio::ip::address_v4(bytes);
	}

	friend std::istream& operator>>(std::istream& is, ipv4_header& header)
	{
		is.read(reinterpret_cast<char*>(header.rep_), 20);
		if (header.version() != 4)
			is.setstate(std::ios::failbit);
		std::streamsize options_length = header.header_length() - 20;
		if (options_length < 0 || options_length > 40)
			is.setstate(std::ios::failbit);
		else
			is.read(reinterpret_cast<char*>(header.rep_) + 20, options_length);
		return is;
	}
};

// ICMP header for both IPv4 and IPv6.
//
// The wire format of an ICMP header is:
// 
// 0               8               16                             31
// +---------------+---------------+------------------------------+      ---
// |               |               |                              |       ^
// |     type      |     code      |          checksum            |       |
// |               |               |                              |       |
// +---------------+---------------+------------------------------+    8 bytes
// |                               |                              |       |
// |          identifier           |       sequence number        |       |
// |                               |                              |       v
// +-------------------------------+------------------------------+      ---

class icmp_header
{
private:
	unsigned char rep_[8];

	unsigned short decode(int a, int b) const { return (rep_[a] << 8) + rep_[b]; }

	void encode(int a, int b, unsigned short n)
	{
		rep_[a] = static_cast<unsigned char>(n >> 8);
		rep_[b] = static_cast<unsigned char>(n & 0xFF);
	}

public:
	enum {
		echo_reply = 0, destination_unreachable = 3, source_quench = 4,
		redirect = 5, echo_request = 8, time_exceeded = 11, parameter_problem = 12,
		timestamp_request = 13, timestamp_reply = 14, info_request = 15,
		info_reply = 16, address_request = 17, address_reply = 18
	};

	icmp_header() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

	unsigned char type() const { return rep_[0]; }
	unsigned char code() const { return rep_[1]; }
	unsigned short checksum() const { return decode(2, 3); }
	unsigned short identifier() const { return decode(4, 5); }
	unsigned short sequence_number() const { return decode(6, 7); }

	void type(unsigned char n) { rep_[0] = n; }
	void code(unsigned char n) { rep_[1] = n; }
	void checksum(unsigned short n) { encode(2, 3, n); }
	void identifier(unsigned short n) { encode(4, 5, n); }
	void sequence_number(unsigned short n) { encode(6, 7, n); }

	friend std::istream& operator>>(std::istream& is, icmp_header& header)
	{
		return is.read(reinterpret_cast<char*>(header.rep_), 8);
	}

	friend std::ostream& operator<<(std::ostream& os, const icmp_header& header)
	{
		return os.write(reinterpret_cast<const char*>(header.rep_), 8);
	}
};

template <typename Iterator>
void compute_checksum(icmp_header& header, Iterator body_begin, Iterator body_end)
{
	unsigned int sum = (header.type() << 8) + header.code() + header.identifier() + header.sequence_number();

	Iterator body_iter = body_begin;
	while (body_iter != body_end)
	{
		sum += (static_cast<unsigned char>(*body_iter++) << 8);
		if (body_iter != body_end)
			sum += static_cast<unsigned char>(*body_iter++);
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	header.checksum(static_cast<unsigned short>(~sum));
}

//
// pinger class
//

using boost::asio::ip::icmp;
using boost::asio::steady_timer;
namespace chrono = boost::asio::chrono;

class pinger
{
private:
	icmp::socket socket_;
	steady_timer timer_;
	chrono::steady_clock::time_point time_sent_;
	boost::asio::streambuf reply_buffer_;

	static unsigned short get_identifier()
	{
#if defined(BOOST_ASIO_WINDOWS)
		return static_cast<unsigned short>(::GetCurrentProcessId());
#else
		return static_cast<unsigned short>(::getpid());
#endif
	}

public:
	icmp::endpoint destination_;
	std::size_t num_replies_;
	uint8_t sequence_number_;
	uint8_t count_;
	uint16_t timer_interval_;

	pinger(boost::asio::io_context& ping_io_context) : socket_(ping_io_context, icmp::v4()), timer_(ping_io_context)
	{
		num_replies_ = 0;
		sequence_number_ = 0;
	};

	void start_send()
	{
		if (sequence_number_ >= count_)
			return;

		std::string body("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");

		// Create an ICMP header for an echo request.
		icmp_header echo_request;
		echo_request.type(icmp_header::echo_request);
		echo_request.code(0);
		echo_request.identifier(get_identifier());
		echo_request.sequence_number(++sequence_number_);
		compute_checksum(echo_request, body.begin(), body.end());

		// Encode the request packet.
		boost::asio::streambuf request_buffer;
		std::ostream os(&request_buffer);
		os << echo_request << body;

		// Send the request.
		time_sent_ = steady_timer::clock_type::now();
		socket_.send_to(request_buffer.data(), destination_);

		timer_.expires_at(time_sent_ + chrono::milliseconds(timer_interval_));
		timer_.async_wait([this](const boost::system::error_code& error)
			{
				//handle_timeout lambda
				if (sequence_number_ >= count_)
				{
					socket_.close();
					return;
				}

				timer_.expires_at(time_sent_ + chrono::milliseconds(timer_interval_));
				timer_.async_wait(boost::bind(&pinger::start_send, this));
			});
	}

	void start_receive()
	{
		// Discard any data already in the buffer.
		reply_buffer_.consume(reply_buffer_.size());

		// Wait for a reply. We prepare the buffer to receive up to 1KB.
		socket_.async_receive(reply_buffer_.prepare(1024), [this](const boost::system::error_code& error, std::size_t bytes_transferred)
			{
				//handle_receive lambda

				// The actual number of bytes received is committed to the buffer so that we can extract it using a std::istream object.
				reply_buffer_.commit(bytes_transferred);

				// Decode the reply packet.
				std::istream is(&reply_buffer_);
				ipv4_header ipv4_hdr;
				icmp_header icmp_hdr;
				is >> ipv4_hdr >> icmp_hdr;

				// We can receive all ICMP packets received by the host, so we need to
				// filter out only the echo replies that match the our identifier and expected sequence number.
				if (is && icmp_hdr.type() == icmp_header::echo_reply
					&& icmp_hdr.identifier() == get_identifier()
					&& icmp_hdr.sequence_number() == sequence_number_)
				{
					++num_replies_;
					// Print out some information about the reply packet.
	//				chrono::steady_clock::time_point now = chrono::steady_clock::now();
	//				chrono::steady_clock::duration elapsed = now - time_sent_;

	//				std::cout << "\n reply received in " << chrono::duration_cast<chrono::milliseconds>(elapsed).count() << " msec\n\n";
				}

				if (sequence_number_ < count_)
					start_receive();
			});
	}

};

bool ping(uint32_t address, uint8_t count, uint16_t timer_milliseconds)
{
	boost::asio::io_context ping_io_context;

	pinger p(ping_io_context);
	p.destination_.address(boost::asio::ip::address_v4(address));
	p.count_ = (count < 2 ? 2 : count);
	p.timer_interval_ = timer_milliseconds;

	try
	{
		p.start_send();
		p.start_receive();

		ping_io_context.run();
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << std::endl;
	}

	return (((uint8_t)p.num_replies_ > p.count_ / 2) ? true : false);
}

#endif // PIBG_HPP
