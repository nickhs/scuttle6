extern crate nix;
extern crate pnet_packet;

use nix::sys::socket::*;
use nix::Error;
use nix::sys::select::*;
use std::os::unix::io::RawFd;
use pnet_packet::icmpv6::*;
use pnet_packet::ipv6::*;
use pnet_packet::ip::IpNextHeaderProtocol;
use std::net::Ipv6Addr;
use pnet_packet::Packet;
use std::thread;
use std::time;
use nix::sys::uio::IoVec;

const MAX_PACKET_SIZE: usize = 65535;
const SOME_CRAP: [u8; 40] = [1; 40];

fn main() -> Result<(), Error> {
    let mut sockets = vec![];
    let icmp_socket = socket(AddressFamily::Inet6, SockType::Raw, SockFlag::empty(), SockProtocol::Icmpv6)?;
    setsockopt(icmp_socket, sockopt::RecvPktInfo, &true)?;
    sockets.push(icmp_socket);

    println!("we running...");
    loop {
        let sockets = sockets.clone();
        let mut fd_set = create_fd_set(&sockets);
        println!("waiting for a packet...");
        select(None, Some(&mut fd_set), None, None, None)?;
        for fd in parse_fd_set(sockets, fd_set).into_iter() {
            let mut buf = [0; MAX_PACKET_SIZE];
            let (read_size, sock_addr) = recvfrom(fd, &mut buf)?;

            let ip_packet = Ipv6Packet::new(&buf[0..read_size]);
            println!("Read IPv6 packet {:?}", ip_packet);

            let icmp_packet = Icmpv6Packet::new(&buf[0..read_size]);
            if icmp_packet.is_none() {
                continue;
            }

            let icmp_packet = icmp_packet.unwrap();

            println!("Read ICMP {:?} from {:?}: {:?}", icmp_packet, sock_addr, icmp_packet.payload());

            if icmp_packet.get_icmpv6_type() != Icmpv6Types::EchoRequest {
                continue;
            }

            continue;

            let resp_packet = create_reply(convert(&(sock_addr.clone())), &icmp_packet);
            println!("reps packet is {:?}", resp_packet);
            // sendto(fd, &resp_packet, &dest, MsgFlags::empty())?;
            // wat(fd, &resp_packet, &sock_addr)?;
            repro(icmp_socket, &sock_addr, &icmp_packet)?;
        }
    }
}

fn wat(fd: i32, resp_packet: &[u8], dest: &SockAddr) -> Result<(), Error> {
    sendto(fd, &resp_packet, &dest, MsgFlags::empty())?;
    return Ok(());
}

fn repro(sock: RawFd, dest: &SockAddr, prev_packet: &Icmpv6Packet) -> Result<(), Error> {
    // let dest = SockAddr::new_inet(InetAddr::new(IpAddr::new_v4(127, 0, 0, 1), 8000));
    /*
    let dest = SockAddr::new_inet(InetAddr::new(IpAddr::new_v6(u16::from_str_radix("2605", 16).unwrap(),
                                                               u16::from_str_radix("2700", 16).unwrap(),
                                                               u16::from_str_radix("0", 16).unwrap(),
                                                               u16::from_str_radix("3", 16).unwrap(),
                                                               u16::from_str_radix("a800", 16).unwrap(),
                                                               u16::from_str_radix("ff", 16).unwrap(),
                                                               u16::from_str_radix("fe76", 16).unwrap(),
                                                               u16::from_str_radix("d28", 16).unwrap()), 0));
    */

    let source = Ipv6Addr::new(123, 123, 123, 123, 123, 123, 123, 1);
    let resp_packet = create_icmp_reply(&convert(&dest), &source, prev_packet);
    println!("resp packet is {:?}", resp_packet);
    // sendto(sock, &resp_packet, &dest, MsgFlags::empty())?;
    sendmsg(sock, &vec![IoVec::from_slice(&resp_packet)], &vec![], MsgFlags::empty(), Some(&dest))?;
    return Ok(());
}

fn create_fd_set(sockets: &Vec<RawFd>) -> FdSet {
    let mut fd_set = FdSet::new();
    for socket in sockets.into_iter() {
        fd_set.insert(*socket);
    }

    fd_set
}

fn parse_fd_set(sockets: Vec<RawFd>, mut fd_set: FdSet) -> Vec<RawFd> {
    sockets.into_iter().filter(|x| fd_set.contains(*x)).collect()
}

fn create_icmp_reply(target: &Ipv6Addr, source: &Ipv6Addr, prev_packet: &Icmpv6Packet) -> Vec<u8> {
    let mut icmp_buf = [0u8; MAX_PACKET_SIZE - 40]; // 40 comes from the IPv6 header size
    let mut icmp = MutableIcmpv6Packet::new(&mut icmp_buf).unwrap();
    icmp.set_icmpv6_type(Icmpv6Types::EchoReply);
    icmp.set_icmpv6_code(Icmpv6Code::new(0));
    let payload = prev_packet.payload().clone(); // FIXME(nickhs): check size
    icmp.set_payload(payload);
    let icmp_packet_size = payload.len() + MutableIcmpv6Packet::minimum_packet_size();

    // calculate the checksum
    let just_bloody_copy_it = Icmpv6Packet::owned(icmp.packet().clone().to_vec()).unwrap();
    icmp.set_checksum(checksum(&just_bloody_copy_it, &source, &target));

    Vec::from(&icmp.packet()[0..icmp_packet_size])
}

fn create_reply(target: Ipv6Addr, prev_packet: &Icmpv6Packet) -> Vec<u8> {
    let mut buf = [0u8; MAX_PACKET_SIZE];
    let mut ipv6_header = MutableIpv6Packet::new(&mut buf).unwrap();
    let source = Ipv6Addr::new(123, 123, 123, 123, 123, 123, 123, 1);

    ipv6_header.set_source(source);
    ipv6_header.set_destination(target);

    let icmp = create_icmp_reply(&target, &source, prev_packet);
    let icmp_packet_size = icmp.len();
    ipv6_header.set_payload_length(icmp_packet_size as u16); // FIXME(nickhs): is this safe
    ipv6_header.set_payload(&icmp);

    ipv6_header.set_version(6 as u8);
    ipv6_header.set_next_header(IpNextHeaderProtocol(1)); // ICMP
    ipv6_header.set_hop_limit(33);

    let packet_size = MutableIpv6Packet::minimum_packet_size() + icmp_packet_size;
    println!("Returning {:?} / {:?}", ipv6_header, icmp);
    return Vec::from(&ipv6_header.packet()[0..packet_size]);
}

fn convert(sock_addr: &SockAddr) -> Ipv6Addr {
    match sock_addr {
        SockAddr::Inet(InetAddr::V6(x)) => Ipv6Addr::from(x.sin6_addr.s6_addr),
        SockAddr::Inet(_) => panic!("Don't know how to handle type"),
        SockAddr::Unix(_) => panic!("Don't know how to handle type"),
        SockAddr::Link(_) => panic!("Don't know how to handle type"),
        SockAddr::Netlink(_) => panic!("Don't know how to handle type"),
    }
}
