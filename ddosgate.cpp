#include <pcap.h>
#include <iostream>
#include <unordered_map>
#include <signal.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fstream>
#include <ctime>
#include <curl/curl.h>
#include <sstream>
#include <cstdio>

#define THRESHOLD 1000 // nombre de paquets par seconde

std::unordered_map<std::string, int> packet_counts;
bool running = true;
bool silent_mode = false;
std::ofstream logfile;

const std::string TELEGRAM_TOKEN = getenv("TELEGRAM_TOKEN");
const std::string TELEGRAM_CHAT_ID = getenv("TELEGRAM_CHAT_ID");

void signal_handler(int signal) {
    running = false;
}

void log_action(const std::string& message) {
    std::time_t now = std::time(nullptr);
    char timestamp[100];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    logfile << "[" << timestamp << "] " << message << std::endl;
    if (!silent_mode) {
        std::cout << message << std::endl;
    }
}

bool is_ip_blocked(const std::string& ip) {
    std::string command = "iptables -L INPUT -v -n | grep " + ip;
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) return false;
    char buffer[128];
    std::string result = "";
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    pclose(pipe);
    return !result.empty();
}

void send_telegram_message(const std::string& message) {
    CURL *curl;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        std::string url = "https://api.telegram.org/bot" + TELEGRAM_TOKEN + "/sendMessage?chat_id=" + TELEGRAM_CHAT_ID + "&text=" + curl_easy_escape(curl, message.c_str(), message.length());
        struct curl_slist *headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L); // Vérifier le certificat SSL du pair
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L); // Vérifier le certificat SSL de l'hôte

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cerr << "Échec de l'envoi du message à Telegram : " << curl_easy_strerror(res) << std::endl;
        }
        
        curl_slist_free_all(headers); // Libérer la liste des en-têtes
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
}

void block_ip(const std::string& ip) {
    if (!is_ip_blocked(ip)) {
        std::string command = "iptables -A INPUT -s " + ip + " -j DROP";
        system(command.c_str());
        std::string log_message = "Blocage de l'IP : " + ip;
        log_action(log_message);
        send_telegram_message(log_message);
    } else {
        log_action("IP déjà bloquée : " + ip);
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct ip *ip_header = (struct ip *)(packet + 14); // 14 est la taille de l'en-tête Ethernet
    std::string src_ip = inet_ntoa(ip_header->ip_src);
    packet_counts[src_ip]++;
}

void monitor_traffic(pcap_t *handle, int duration) {
    while (running) {
        packet_counts.clear();
        pcap_dispatch(handle, 0, packet_handler, nullptr);
        sleep(duration);
        
        for (const auto& entry : packet_counts) {
            if (entry.second > THRESHOLD) {
                std::string alert_message = "[ALERT] Attaque DDoS possible depuis " + entry.first + " : " + std::to_string(entry.second) + " paquets/seconde";
                log_action(alert_message);
                send_telegram_message(alert_message);
                block_ip(entry.first);
            }
        }
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);

    if (argc > 1 && std::string(argv[1]) == "--silent") {
        silent_mode = true;
    }

    logfile.open("ddos_protection.log", std::ios::app);
    if (!logfile.is_open()) {
        std::cerr << "Impossible d'ouvrir le fichier de log." << std::endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
        std::cerr << "Impossible d'ouvrir le périphérique : " << errbuf << std::endl;
        logfile.close();
        return 1;
    }

    log_action("Surveillance du trafic...");

    monitor_traffic(handle, 1);

    pcap_close(handle);
    logfile.close();

    return 0;
}