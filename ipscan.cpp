#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <map>
#include <vector>
#include <mutex>
#include <chrono>
#include <string>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <getopt.h>
using namespace std;

const map<int, string> PORTS = {
    {21,   "FTP"},
    {22,   "SSH"},
    {23,   "TELNET"},
    {25,   "SMTP"},
    {53,   "DNS"},
    {80,   "HTTP"},
    {110,  "POP3"},
    {111,  "RPCBIND"},
    {139,  "NETBIOS"},
    {161,  "SNMP"},
    {143,  "IMAP"},
    {389,  "LDAP"},
    {443,  "HTTPS"},
    {445,  "SMB"},
    {587, "SMPT"},
    {636,  "LDAPS"},
    {993, "IMAP"},
    {1433, "MSSQL"},
    {2049, "NFS"},
    {2222, "SSHALT"},
    {2375, "DOCKER"},
    {2376, "DOCKERTLS"},
    {3000, "NODEJS"},
    {3306, "MYSQL"},
    {3389, "RDP"},
    {5000, "FLASK"},
    {5432, "POSTGRESQL"},
    {5900, "VNC"},
    {5985, "WINRMHTTP"},
    {5986, "WINRMHTTPS"},
    {6379, "REDIS"},
    {6443, "KUBERNETES"},
    {8000, "DEVSERVERS"},
    {8080, "TOMCAT / PROXIES"},
    {9000, "PORTAINER"},
    {27017,"MONGODB"}
};

string getService(int port){
    auto it = PORTS.find(port);
    // condition ? value_if_true : value_if_false
    return it != PORTS.end() ? it->second : "Unkown";
}

string get_mac_address(const string &ip){
    ifstream arp("/proc/net/arp");
    string line;
    // skip header
    getline(arp, line);
    while(getline(arp, line)){
        istringstream iss(line);
        string ip_addr, hw_type, flags, mac, mask, device;

        if(!(iss >> ip_addr >> hw_type >> flags >> mac >> mask >> device))
            continue;

        if(ip_addr == ip){
            return mac;
        }
    }
    return "No MAC address found\n";
}

// Mutex for thread-safe output
mutex mtx;

// Function to scan a single port
void scan_port(const string &ip, int port){
    // AF_INET -> IPv4 protocol | SOCK_STREAM -> TCP socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if(serverSocket < 0){
        lock_guard<mutex> lock(mtx);
        cerr << "Socket creation failed for port " << port << endl;
        return;
    }
    // defining target network address
    sockaddr_in target{};
    target.sin_family = AF_INET; 
    target.sin_port = htons(port); // htons() converts port to network byte order
    if (inet_pton(AF_INET, ip.c_str(), &target.sin_addr) <= 0){
        lock_guard<mutex> lock(mtx);
        cerr << "Error: Invalid IP address\n";
        close(serverSocket);
        return;
    };

    // trying to connect
    // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
    int result = connect(serverSocket, (struct sockaddr*)&target, sizeof(target));
    if(result == 0){
        lock_guard<mutex> lock(mtx);
        cout << "[OPEN] Port " << port << "["<< getService(port)<< "] is open\n";
    }

    close(serverSocket);
}

// function to scan a range of ports 
void scan_ports(const string &ip, const vector<int> &ports){
    vector<thread> threads;
    for(int port : ports){
        threads.push_back(thread(scan_port, ip, port));
        // limit number of activate threads to avoid overload
        if(threads.size() >= 100){
            for(auto &t : threads) t.join();
            // remove old threads after every batch
            threads.clear();
        }
    }
    // join remaining threads
    for(auto &t : threads) t.join();
}

int main(int argc, char* argv[]){
    if(argc < 2){
        cerr << "Usage: ./ipscan <target_ip> [ports...] for help use -h\n";
        return 1;
    }
    string target_ip = argv[1];
    cout << "Target IP:\t" << target_ip << endl;
    vector<int> ports_to_scan;
    
    vector<int> common_ports = {
        21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389,
        8080, 8000, 8008, 8888, 3000, 5000,
        5900, 5985, 5986,
        3306, 5432, 6379, 27017, 1433,
        2049, 111, 389, 636,
        2375, 2376, 6443, 9000
    };

    if(argc > 2){
        for(int i = 2; i < argc; i++){
            // stoi(): string -> digit
            int port = stoi(argv[i]);
            if(port > 0 && port <= 65535){
                ports_to_scan.push_back(port);
            }
            else{
                cerr << "Invalid port number! exiting...";
                return 1;
            }
        }
    }
    else{
        // no ports provided -> use common_ports
        ports_to_scan = common_ports;
    }

    cout << "======= C++ Port Scanner =======\n";
    cout << "Enter target IP: ";

    auto start_time = chrono::high_resolution_clock::now();
    cout << "Scanning "<< ports_to_scan.size() << " ports on " << target_ip << endl;
    scan_ports(target_ip, ports_to_scan);
    system(("ping -c 1 " + target_ip + " > /dev/null 2>&1").c_str());
    this_thread::sleep_for(chrono::milliseconds(300));
    cout << "MAC:" << get_mac_address(target_ip);
    auto end_time = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
    cout << "Scanning completed in " << duration.count() << " seconds.\n";

    return 0;
}