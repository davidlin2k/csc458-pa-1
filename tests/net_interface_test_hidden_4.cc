#include "arp_message.hh"
#include "ethernet_header.hh"
#include "ipv4_datagram.hh"
#include "network_interface_test_harness.hh"

#include <cstdlib>
#include <iostream>
#include <random>
#include <map>

using namespace std;

EthernetAddress random_private_ethernet_address()
{
  EthernetAddress addr;
  for ( auto& byte : addr ) {
    byte = random_device()(); // use a random local Ethernet address
  }
  addr.at( 0 ) |= 0x02; // "10" in last two binary digits marks a private Ethernet address
  addr.at( 0 ) &= 0xfe;

  return addr;
}

InternetDatagram make_datagram( const string& src_ip, const string& dst_ip ) // NOLINT(*-swappable-*)
{
  InternetDatagram dgram;
  dgram.header.src = Address( src_ip, 0 ).ipv4_numeric();
  dgram.header.dst = Address( dst_ip, 0 ).ipv4_numeric();
  dgram.payload.emplace_back( "hello" );
  dgram.header.len = static_cast<uint64_t>( dgram.header.hlen ) * 4 + dgram.payload.size();
  dgram.header.compute_checksum();
  return dgram;
}

ARPMessage make_arp( const uint16_t opcode,
                     const EthernetAddress sender_ethernet_address,
                     const string& sender_ip_address,
                     const EthernetAddress target_ethernet_address,
                     const string& target_ip_address )
{
  ARPMessage arp;
  arp.opcode = opcode;
  arp.sender_ethernet_address = sender_ethernet_address;
  arp.sender_ip_address = Address( sender_ip_address, 0 ).ipv4_numeric();
  arp.target_ethernet_address = target_ethernet_address;
  arp.target_ip_address = Address( target_ip_address, 0 ).ipv4_numeric();
  return arp;
}

EthernetFrame make_frame( const EthernetAddress& src,
                          const EthernetAddress& dst,
                          const uint16_t type,
                          vector<Buffer> payload )
{
  EthernetFrame frame;
  frame.header.src = src;
  frame.header.dst = dst;
  frame.header.type = type;
  frame.payload = std::move( payload );
  return frame;
}

std::string address_plus_number(Address& base_addr, int inc) {
    Address base_addr_inc = Address::from_ipv4_numeric(base_addr.ipv4_numeric() + inc); 
    std::string addr_port_str = base_addr_inc.to_string(); 
    size_t pos = addr_port_str.find(":");

    if (pos != std::string::npos) {
        std::string result = addr_port_str.substr(0, pos);
        return result; 
    } 

    return "";
}


int main()
{
  const int host_count = 10; 
  const int datagram_count = 10; 

  try {
    {
      std::cout << "\n=== Starting Hidden Test #4 ===" << std::endl;

      const EthernetAddress local_eth = random_private_ethernet_address();
      NetworkInterfaceTestHarness test { "Hidden Test #4", local_eth, Address( "4.3.2.1", 0 ) };

      
      Address base_dst = Address("13.12.11.10", 0); 
      Address base_next_hop = Address("192.168.0.1", 0); 
      
      std::map<int, EthernetAddress> remote_eth; 
      std::map<int, std::string> dst_string;  
      std::map<int, std::string> next_hop_string; 

      for (int i = 0; i < host_count; i ++) {
          std::string this_dst_string = address_plus_number(base_dst, i); 
          std::string this_next_hop_string = address_plus_number(base_next_hop, i); 
          const EthernetAddress this_remote_eth = random_private_ethernet_address();

          remote_eth[i] = this_remote_eth; 
          dst_string[i] = this_dst_string; 
          next_hop_string[i] = this_next_hop_string; 
      } 

      
      std::cout << "\n=== Phase 1: Initial ARP Requests ===" << std::endl;
      for (int i = 0; i < host_count; i++) {
        std::cout << "\nProcessing Host " << i << ":" << std::endl;
        const auto datagram = make_datagram("4.3.2.1", dst_string[i]);

        test.execute( SendDatagram { datagram, Address( next_hop_string[i], 0 ) } );
        std::cout << "- Sent datagram, expecting ARP request broadcast" << std::endl;
        
        test.execute( ExpectFrame { make_frame(
          local_eth,
          ETHERNET_BROADCAST,
          EthernetHeader::TYPE_ARP,
          serialize( make_arp( ARPMessage::OPCODE_REQUEST, local_eth, "4.3.2.1", {}, next_hop_string[i] ) ) ) } );

        test.execute( Tick { 400 } );

        if (i % 2 == 0) {
          std::cout << "- Queueing " << datagram_count << " additional datagrams to even-numbered Host " << i << std::endl;
          for (int j = 0; j < datagram_count; j ++) {
            test.execute( SendDatagram { datagram, Address( next_hop_string[i], 0 ) } );
            test.execute( ExpectNoFrame {} );
          }
        }
      }

      std::cout << "\n=== Phase 2: Waiting Period (2000ms passed) ===" << std::endl;
      std::cout << "NOTE: ARP requests for hosts 0-2 have expired" << std::endl;
      test.execute( Tick { 2000 } );

      std::cout << "\n=== Phase 3: Processing ARP Replies (Hosts 3-9 only) ===" << std::endl;
      for (int i = 0; i < host_count; i++) {
        if (i >= 3) {
          std::cout << "\nProcessing ARP reply from Host " << i << std::endl;
          test.execute( ReceiveFrame {
            make_frame(
              remote_eth[i],
              local_eth,
              EthernetHeader::TYPE_ARP, // NOLINTNEXTLINE(*-suspicious-*)
              serialize( make_arp( ARPMessage::OPCODE_REPLY, remote_eth[i], next_hop_string[i], local_eth, "4.3.2.1" ) ) ),
            {} } );
          std::cout << "- Received ARP reply with MAC address" << std::endl;

          int expected_frames = 1; 
          
          if (i % 2 == 0) {
            expected_frames += datagram_count; 
          }
          std::cout << "- Expecting " << expected_frames << " IPv4 frames to be sent" << std::endl;

          const auto datagram = make_datagram("4.3.2.1", dst_string[i]);
    
          for (int j = 0; j < expected_frames; j++) {
            test.execute( ExpectFrame {
              make_frame( local_eth, remote_eth[i], EthernetHeader::TYPE_IPv4, serialize( datagram ) )
            });
          }
        }
        test.execute( ExpectNoFrame {} );
      }

      std::cout << "\n=== Phase 4: Second Round of Communication ===" << std::endl;
      std::cout << "NOTE: Hosts 0-2 had no replies, ARP requests expired since 5000ms has passed" << std::endl;
      std::cout << "NOTE: Hosts 3-9 have valid MAC mappings in cache" << std::endl;
      // one more round.
      // Hosts 0-2 (no ARP replies received) has timed out:
      //   - Original ARP requests have expired
      //   - Pending frames should have expired
      // For Hosts 3-9 (ARP replies received)
      //   - MAC addresses should be cached
      //   - Frames should be sent immediately without ARP requests
      for (int i = 0; i < host_count; i ++) {
          const auto datagram = make_datagram("4.3.2.1", dst_string[i]);

          test.execute( SendDatagram { datagram, Address( next_hop_string[i], 0 ) } );

          if (i < 3) {
            std::cout << "Host " << i << " (no ARP reply received): Sending new ARP request" << std::endl;
            test.execute( ExpectFrame { make_frame(
              local_eth,
              ETHERNET_BROADCAST,
              EthernetHeader::TYPE_ARP,
              serialize( make_arp( ARPMessage::OPCODE_REQUEST, local_eth, "4.3.2.1", {}, next_hop_string[i] ) ) ) } );
          } else {
            std::cout << "Host " << i << " (ARP cached): Sending IPv4 frame directly" << std::endl;
            test.execute( ExpectFrame {
              make_frame( local_eth, remote_eth[i], EthernetHeader::TYPE_IPv4, serialize( datagram ) )
            });
          }
      }

      std::cout << "\n=== Phase 5: Testing ARP Request Handling ===" << std::endl;
      // now let's ask the interface some stuff 
      for (int i = 0; i < host_count; i++) {
          std::cout << "\nReceiving ARP request from Host " << i << std::endl;
          test.execute( ReceiveFrame {
            make_frame(
              remote_eth[i],
              ETHERNET_BROADCAST,
              EthernetHeader::TYPE_ARP, // NOLINTNEXTLINE(*-suspicious-*)
              serialize( make_arp( ARPMessage::OPCODE_REQUEST, remote_eth[i], next_hop_string[i], {}, "4.3.2.1" ) ) ),
            {} } );

          if (i < 3) {
            // The first three destinations, have one datagram waiting to be sent. 

            // now two packets should be sent. the datagram that was waiting, and ARP response. 
            // The ordering of the two packets might vary from one implementation to another. 
            // Therefore we are not checking the content of the frames here. sending two frame
            // would be enough to pass the test.
            std::cout << "Host " << i << " (has pending datagram): Expecting two frames (order not checked)" << std::endl;

            test.execute( ExpectFrame {{}}); 
            test.execute( ExpectFrame {{}});

            // only two packets should be sent.  
            test.execute( ExpectNoFrame {} );
          } else {
            std::cout << "Host " << i << ": Sending normal ARP reply only" << std::endl;
            
            // the rest will reply normally. 
            test.execute( ExpectFrame { make_frame(
              local_eth,
              remote_eth[i],
              EthernetHeader::TYPE_ARP,
              serialize( make_arp( ARPMessage::OPCODE_REPLY, local_eth, "4.3.2.1", remote_eth[i], next_hop_string[i] ) ) ) } );

            test.execute( ExpectNoFrame {} );
          }
          
      }
      
      std::cout << "\n=== Test #4 Completed Successfully ===" << std::endl;
    }
  } catch ( const exception& e ) {
    cerr << e.what() << endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
