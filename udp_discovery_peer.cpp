#include "udp_discovery_peer.hpp"

#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <vector>

#include "udp_discovery_protocol.hpp"

// sockets
#if defined(_WIN32)
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET SocketType;
typedef int AddressLenType;
const SocketType kInvalidSocket = INVALID_SOCKET;
#else
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
typedef int SocketType;
typedef socklen_t AddressLenType;
const SocketType kInvalidSocket = -1;
#endif

// time
#if defined(__APPLE__)
#include <mach/mach_time.h>
#include <stdint.h>
#endif
#if !defined(_WIN32)
#include <sys/time.h>
#endif
#include <time.h>

// threads
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <pthread.h>
#include <stdlib.h>
#endif

#if defined(_WIN32)
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#endif

#if !defined(_WIN32)
#include <ifaddrs.h>
#include <net/if.h>
#endif


static void InitSockets() {
#if defined(_WIN32)
  WSADATA wsa_data;
  WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif
}

static void SetSocketTimeout(SocketType sock, int param, int timeout_ms) {
#if defined(_WIN32)
  setsockopt(sock, SOL_SOCKET, param, (const char*)&timeout_ms,
             sizeof(timeout_ms));
#else
  struct timeval timeout;
  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = 1000 * (timeout_ms % 1000);
  setsockopt(sock, SOL_SOCKET, param, (const char*)&timeout, sizeof(timeout));
#endif
}

static void CloseSocket(SocketType sock) {
#if defined(_WIN32)
  closesocket(sock);
#else
  close(sock);
#endif
}

static bool IsRightTime(long last, long now, long timeout, long& sleep_out) {
  if (last == 0) {
    sleep_out = timeout;
    return true;
  }

  long elapsed = now - last;

  if (elapsed >= timeout) {
    sleep_out = timeout;
    return true;
  }

  sleep_out = timeout - elapsed;
  return false;
}

static uint32_t MakeRandomId() {
  srand((unsigned int)time(0));
  return (uint32_t)rand();
}

namespace udpdiscovery {
namespace impl {
    struct InterfaceInfo {
        uint32_t ip;         // Host byte order
        uint32_t netmask;    // Host byte order
        uint32_t broadcast;  // Host byte order
        std::string name;

        bool operator==(const InterfaceInfo& other) const {
            return ip == other.ip && netmask == other.netmask;
        }

    };
    std::vector<InterfaceInfo> GetPhysicalInterfaces() {
        std::vector<InterfaceInfo> interfaces;

#if defined(_WIN32)
        ULONG bufLen = 15000;
        PIP_ADAPTER_ADDRESSES adapters =
            (PIP_ADAPTER_ADDRESSES)malloc(bufLen);

        ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST |
            GAA_FLAG_SKIP_DNS_SERVER;

        ULONG result = GetAdaptersAddresses(AF_INET, flags, NULL, adapters, &bufLen);
        if (result == ERROR_BUFFER_OVERFLOW) {
            free(adapters);
            adapters = (PIP_ADAPTER_ADDRESSES)malloc(bufLen);
            result = GetAdaptersAddresses(AF_INET, flags, NULL, adapters, &bufLen);
        }

        if (result == NO_ERROR && adapters) {
            for (auto adapter = adapters; adapter; adapter = adapter->Next) {
                if (adapter->OperStatus != IfOperStatusUp) continue;
                if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

                std::wstring desc(adapter->Description);
                if (desc.find(L"VirtualBox") != std::wstring::npos) continue;
                if (desc.find(L"VMware") != std::wstring::npos) continue;
                if (desc.find(L"Hyper-V") != std::wstring::npos) continue;
                if (desc.find(L"Virtual") != std::wstring::npos) continue;
                if (desc.find(L"TAP-") != std::wstring::npos) continue;
                if (desc.find(L"VPN") != std::wstring::npos) continue;
                if (desc.find(L"Loopback") != std::wstring::npos) continue;

                for (auto ua = adapter->FirstUnicastAddress; ua; ua = ua->Next) {
                    if (ua->Address.lpSockaddr->sa_family != AF_INET) continue;

                    sockaddr_in* sa = (sockaddr_in*)ua->Address.lpSockaddr;
                    uint32_t ip = ntohl(sa->sin_addr.s_addr);

                    // Skip loopback and link-local
                    if ((ip >> 24) == 127) continue;
                    if ((ip >> 16) == 0xA9FE) continue;

                    InterfaceInfo info;
                    info.ip = ip;

                    if (ua->OnLinkPrefixLength > 0 && ua->OnLinkPrefixLength <= 32) {
                        info.netmask = 0xFFFFFFFF << (32 - ua->OnLinkPrefixLength);
                    }
                    else {
                        info.netmask = 0xFFFFFF00;
                    }

                    info.broadcast = (ip & info.netmask) | ~info.netmask;

                    char name[256] = { 0 };
                    WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1,
                        name, sizeof(name) - 1, NULL, NULL);
                    info.name = name;

                    interfaces.push_back(info);
                }
            }
        }

        if (adapters) {
            free(adapters);
        }

#else  // POSIX
        struct ifaddrs* ifaddr = nullptr;

        if (getifaddrs(&ifaddr) == 0 && ifaddr) {
            for (auto ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
                if (!ifa->ifa_addr) continue;
                if (ifa->ifa_addr->sa_family != AF_INET) continue;
                if (ifa->ifa_flags & IFF_LOOPBACK) continue;
                if (!(ifa->ifa_flags & IFF_UP)) continue;
                if (!(ifa->ifa_flags & IFF_RUNNING)) continue;

                std::string name(ifa->ifa_name);
                if (name.find("vbox") != std::string::npos) continue;
                if (name.find("vmnet") != std::string::npos) continue;
                if (name.find("docker") != std::string::npos) continue;
                if (name.find("virbr") != std::string::npos) continue;
                if (name.find("br-") != std::string::npos) continue;
                if (name.find("veth") != std::string::npos) continue;
                if (name.find("tun") != std::string::npos) continue;
                if (name.find("tap") != std::string::npos) continue;
                if (name.find("lo") == 0) continue;

                sockaddr_in* sa = (sockaddr_in*)ifa->ifa_addr;
                uint32_t ip = ntohl(sa->sin_addr.s_addr);

                // Skip loopback and link-local
                if ((ip >> 24) == 127) continue;
                if ((ip >> 16) == 0xA9FE) continue;

                InterfaceInfo info;
                info.ip = ip;
                info.name = name;

                if (ifa->ifa_netmask) {
                    sockaddr_in* nm = (sockaddr_in*)ifa->ifa_netmask;
                    info.netmask = ntohl(nm->sin_addr.s_addr);
                }
                else {
                    info.netmask = 0xFFFFFF00;
                }

                if (ifa->ifa_broadaddr && (ifa->ifa_flags & IFF_BROADCAST)) {
                    sockaddr_in* ba = (sockaddr_in*)ifa->ifa_broadaddr;
                    info.broadcast = ntohl(ba->sin_addr.s_addr);
                }
                else {
                    info.broadcast = (ip & info.netmask) | ~info.netmask;
                }

                interfaces.push_back(info);
            }
            freeifaddrs(ifaddr);
        }
#endif

        return interfaces;
    }


long NowTime() {
#if defined(_WIN32)
  LARGE_INTEGER freq;
  if (!QueryPerformanceFrequency(&freq)) {
    return 0;
  }
  LARGE_INTEGER cur;
  QueryPerformanceCounter(&cur);
  return (long)(cur.QuadPart * 1000 / freq.QuadPart);
#elif defined(__APPLE__)
  mach_timebase_info_data_t time_info;
  mach_timebase_info(&time_info);

  uint64_t cur = mach_absolute_time();
  return (long)((cur / (time_info.denom * 1000000)) * time_info.numer);
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
#endif

  return 0;
}

void SleepFor(long time_ms) {
#if defined(_WIN32)
  Sleep((DWORD)time_ms);
#else
  usleep((useconds_t)(time_ms * 1000));
#endif
}

class MinimalisticMutex {
 public:
  MinimalisticMutex() {
#if defined(_WIN32)
    InitializeCriticalSection(&critical_section_);
#else
    pthread_mutex_init(&mutex_, 0);
#endif
  }

  ~MinimalisticMutex() {
#if defined(_WIN32)
    DeleteCriticalSection(&critical_section_);
#else
    pthread_mutex_destroy(&mutex_);
#endif
  }

  void Lock() {
#if defined(_WIN32)
    EnterCriticalSection(&critical_section_);
#else
    pthread_mutex_lock(&mutex_);
#endif
  }

  void Unlock() {
#if defined(_WIN32)
    LeaveCriticalSection(&critical_section_);
#else
    pthread_mutex_unlock(&mutex_);
#endif
  }

 private:
#if defined(_WIN32)
  CRITICAL_SECTION critical_section_;
#else
  pthread_mutex_t mutex_;
#endif
};

class MinimalisticThread : public MinimalisticThreadInterface {
 public:
#if defined(_WIN32)
  MinimalisticThread(LPTHREAD_START_ROUTINE f, void* env) : detached_(false) {
    thread_ = CreateThread(NULL, 0, f, env, 0, NULL);
  }
#else
  MinimalisticThread(void* (*f)(void*), void* env) : detached_(false) {
    pthread_create(&thread_, 0, f, env);
  }
#endif

  ~MinimalisticThread() { detach(); }

  void Detach() { detach(); }

  void Join() {
    if (detached_) return;

#if defined(_WIN32)
    WaitForSingleObject(thread_, INFINITE);
    CloseHandle(thread_);
#else
    pthread_join(thread_, 0);
#endif
    detached_ = true;
  }

 private:
  void detach() {
    if (detached_) return;

#if defined(_WIN32)
    CloseHandle(thread_);
#else
    pthread_detach(thread_);
#endif
    detached_ = true;
  }

  bool detached_;
#if defined(_WIN32)
  HANDLE thread_;
#else
  pthread_t thread_;
#endif
};

class PeerEnv : public PeerEnvInterface {
 public:
  PeerEnv()
      : binding_sock_(kInvalidSocket),
        sock_(kInvalidSocket),
        packet_index_(0),
        ref_count_(0),
        exit_(false) {}

  ~PeerEnv() {
    if (binding_sock_ != kInvalidSocket) {
      CloseSocket(binding_sock_);
    }

    if (sock_ != kInvalidSocket) {
      CloseSocket(sock_);
    }

  }

  NetworkState GetNetworkState() override {
      lock_.Lock();
      NetworkState state = network_state_;
      lock_.Unlock();
      return state;
  }

  bool Start(const PeerParameters& parameters, const std::string& user_data) {
    parameters_ = parameters;
    user_data_ = user_data;

    if (!parameters_.can_use_broadcast() && !parameters_.can_use_multicast()) {
      std::cerr
          << "udpdiscovery::Peer can't use broadcast and can't use multicast."
          << std::endl;
      return false;
    }

    if (!parameters_.can_discover() && !parameters_.can_be_discovered()) {
      std::cerr << "udpdiscovery::Peer can't discover and can't be discovered."
                << std::endl;
      return false;
    }

    InitSockets();

    peer_id_ = MakeRandomId();

    // Initial interface discovery and socket setup
    if (!InitializeNetworking()) {
        std::cerr << "udpdiscovery::Peer initial network setup failed, "
            << "will retry automatically." << std::endl;
        // Don't return false - we'll retry in the thread
    }

    return true;
  }

  void SetUserData(const std::string& user_data) {
    lock_.Lock();
    user_data_ = user_data;
    lock_.Unlock();
  }

  std::list<DiscoveredPeer> ListDiscovered() {
    std::list<DiscoveredPeer> result;

    lock_.Lock();
    result = discovered_peers_;
    lock_.Unlock();
 
    return result;
  }

  void Exit() {
    lock_.Lock();
    exit_ = true;
    lock_.Unlock();
  }

  void SendingThreadFunc() {
    lock_.Lock();
    ++ref_count_;
    lock_.Unlock();

    long last_send_time_ms = 0;
    long last_delete_idle_ms = 0;

    while (true) {
      lock_.Lock();
      if (exit_) {
        for (int protocol_version =
                 parameters_.min_supported_protocol_version();
             protocol_version <= parameters_.max_supported_protocol_version();
             ++protocol_version) {
          send(/* under_lock= */ true, (ProtocolVersion)protocol_version,
               kPacketIAmOutOfHere);
        }

        decreaseRefCountAndMaybeDestroySelfAndUnlock();
        return;
      }
      lock_.Unlock();

      long cur_time_ms = NowTime();
      long to_sleep_ms = 0;

      // Periodic interface check (every 5 seconds or on failure)
      bool should_check_interfaces = false;
      if (cur_time_ms - last_interface_check_ms_ >= kInterfaceCheckIntervalMs) {
          should_check_interfaces = true;
      }

      lock_.Lock();
      if (consecutive_send_failures_ >= kMaxConsecutiveFailures) {
          should_check_interfaces = true;
      }
      if (!sockets_valid_) {
          should_check_interfaces = true;
      }
      lock_.Unlock();

      if (should_check_interfaces) {
          CheckAndReinitializeNetwork();
          last_interface_check_ms_ = cur_time_ms;
      }

      if (parameters_.can_be_discovered()) {
        if (IsRightTime(last_send_time_ms, cur_time_ms,
                        parameters_.send_timeout_ms(), to_sleep_ms)) {
          for (int protocol_version =
                   parameters_.min_supported_protocol_version();
               protocol_version <= parameters_.max_supported_protocol_version();
               ++protocol_version) {
            send(/* under_lock= */ false, (ProtocolVersion)protocol_version,
                 kPacketIAmHere);
          }
          last_send_time_ms = cur_time_ms;
        }
      }

      if (parameters_.can_discover()) {
        long to_sleep_until_next_delete_idle = 0;
        if (IsRightTime(last_delete_idle_ms, cur_time_ms,
                        parameters_.discovered_peer_ttl_ms(),
                        to_sleep_until_next_delete_idle)) {
          deleteIdle(cur_time_ms);
          last_delete_idle_ms = cur_time_ms;
        }

        if (to_sleep_ms > to_sleep_until_next_delete_idle) {
          to_sleep_ms = to_sleep_until_next_delete_idle;
        }
      }

      SleepFor(to_sleep_ms);
    }
  }

  void ReceivingThreadFunc() {
    lock_.Lock();
    ++ref_count_;
    lock_.Unlock();

    while (true) {
     
  
      lock_.Lock();
      SocketType current_sock = binding_sock_;
      bool valid = sockets_valid_;
      lock_.Unlock();

      if (!valid || current_sock == kInvalidSocket) {
          SleepFor(kNetworkRetryIntervalMs);
          continue;
      }

      sockaddr_in from_addr;
      AddressLenType addr_length = sizeof(sockaddr_in);
      std::string buffer;
      buffer.resize(kMaxPacketSize);

      int length = (int)recvfrom(binding_sock_, &buffer[0], buffer.size(), 0,
                                 (struct sockaddr*)&from_addr, &addr_length);

     
      lock_.Lock();
      if (exit_) {
          decreaseRefCountAndMaybeDestroySelfAndUnlock();
          return;
      }
      lock_.Unlock();
      if (length < 0) {
#if defined(_WIN32)
          int err = WSAGetLastError();
          if (err != WSAETIMEDOUT && err != WSAEWOULDBLOCK) {
              HandleReceiveError(err);
          }
#else
          if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
              HandleReceiveError(errno);
          }
#endif
          continue;
      }
      else if (length == 0) {
          continue;
      }

      IpPort from;
      from.set_port(ntohs(from_addr.sin_port));
      from.set_ip(ntohl(from_addr.sin_addr.s_addr));

      buffer.resize(length);
      processReceivedBuffer(NowTime(), from, buffer);
    }
  }

 private:
    static const long kInterfaceCheckIntervalMs = 5000;
    static const long kNetworkRetryIntervalMs = 1000;
    static const int kMaxConsecutiveFailures = 3;

    void CloseAllSockets() {
        if (binding_sock_ != kInvalidSocket) {
            // Leave multicast groups before closing
            if (parameters_.can_use_multicast()) {
                for (const auto& iface : interfaces_) {
                    struct ip_mreq mreq;
                    mreq.imr_multiaddr.s_addr =
                        htonl(parameters_.multicast_group_address());
                    mreq.imr_interface.s_addr = htonl(iface.ip);
                    setsockopt(binding_sock_, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                        (const char*)&mreq, sizeof(mreq));
                }
            }
            CloseSocket(binding_sock_);
            binding_sock_ = kInvalidSocket;
        }

        if (sock_ != kInvalidSocket) {
            CloseSocket(sock_);
            sock_ = kInvalidSocket;
        }
    }

    bool InitializeNetworking() {
        lock_.Lock();

        // Close existing sockets
        CloseAllSockets();
        sockets_valid_ = false;
        consecutive_send_failures_ = 0;

        lock_.Unlock();

        // Get current interfaces
        std::vector<InterfaceInfo> new_interfaces = GetPhysicalInterfaces();

        if (new_interfaces.empty()) {
            std::cerr << "udpdiscovery: No suitable network interfaces found."
                << std::endl;
            lock_.Lock();
            network_state_ = NetworkState::kNoInterfaces;
            lock_.Unlock();
            return false;
        }

        // Log interface changes
        for (const auto& iface : new_interfaces) {
            std::cerr << "udpdiscovery: Using interface " << iface.name
                << " (" << FormatIp(iface.ip) << ")" << std::endl;
        }

        // Create sending socket
        SocketType new_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (new_sock == kInvalidSocket) {
            std::cerr << "udpdiscovery: Can't create socket." << std::endl;
            lock_.Lock();
            network_state_ = NetworkState::kSocketError;
            lock_.Unlock();
            return false;
        }

        // Set socket options
        {
            int value = 1;
            setsockopt(new_sock, SOL_SOCKET, SO_BROADCAST,
                (const char*)&value, sizeof(value));
        }

        if (parameters_.can_use_multicast()) {
            unsigned char ttl = 1;
            setsockopt(new_sock, IPPROTO_IP, IP_MULTICAST_TTL,
                (const char*)&ttl, sizeof(ttl));

            unsigned char loop = parameters_.discover_self() ? 1 : 0;
            setsockopt(new_sock, IPPROTO_IP, IP_MULTICAST_LOOP,
                (const char*)&loop, sizeof(loop));

            if (!new_interfaces.empty()) {
                struct in_addr mcast_if;
                mcast_if.s_addr = htonl(new_interfaces[0].ip);
                setsockopt(new_sock, IPPROTO_IP, IP_MULTICAST_IF,
                    (const char*)&mcast_if, sizeof(mcast_if));
            }
        }

        // Create receiving socket if needed
        SocketType new_binding_sock = kInvalidSocket;
        if (parameters_.can_discover()) {
            new_binding_sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (new_binding_sock == kInvalidSocket) {
                std::cerr << "udpdiscovery: Can't create binding socket."
                    << std::endl;
                CloseSocket(new_sock);
                lock_.Lock();
                network_state_ = NetworkState::kSocketError;
                lock_.Unlock();
                return false;
            }

            {
                int reuse_addr = 1;
                setsockopt(new_binding_sock, SOL_SOCKET, SO_REUSEADDR,
                    (const char*)&reuse_addr, sizeof(reuse_addr));
#ifdef SO_REUSEPORT
                int reuse_port = 1;
                setsockopt(new_binding_sock, SOL_SOCKET, SO_REUSEPORT,
                    (const char*)&reuse_port, sizeof(reuse_port));
#endif
            }

            // Join multicast on all interfaces
            if (parameters_.can_use_multicast()) {
                for (const auto& iface : new_interfaces) {
                    struct ip_mreq mreq;
                    mreq.imr_multiaddr.s_addr =
                        htonl(parameters_.multicast_group_address());
                    mreq.imr_interface.s_addr = htonl(iface.ip);

                    if (setsockopt(new_binding_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                        (const char*)&mreq, sizeof(mreq)) < 0) {
                        std::cerr << "udpdiscovery: Failed to join multicast on "
                            << iface.name << std::endl;
                    }
                    else {
                        std::cerr << "udpdiscovery: Joined multicast on "
                            << iface.name << std::endl;
                    }
                }
            }

            sockaddr_in addr;
            memset(&addr, 0, sizeof(sockaddr_in));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(parameters_.port());
            addr.sin_addr.s_addr = htonl(INADDR_ANY);

            if (bind(new_binding_sock, (struct sockaddr*)&addr,
                sizeof(sockaddr_in)) < 0) {
                std::cerr << "udpdiscovery: Can't bind socket." << std::endl;
                CloseSocket(new_binding_sock);
                CloseSocket(new_sock);
                lock_.Lock();
                network_state_ = NetworkState::kSocketError;
                lock_.Unlock();
                return false;
            }

            SetSocketTimeout(new_binding_sock, SO_RCVTIMEO, 1000);
        }

        // Atomically update sockets and interfaces
        lock_.Lock();
        sock_ = new_sock;
        binding_sock_ = new_binding_sock;
        interfaces_ = new_interfaces;
        sockets_valid_ = true;
        network_state_ = NetworkState::kOk;
        consecutive_send_failures_ = 0;
        lock_.Unlock();

        std::cerr << "udpdiscovery: Network initialized successfully with "
            << new_interfaces.size() << " interface(s)." << std::endl;

        return true;
    }

    void CheckAndReinitializeNetwork() {
        std::vector<InterfaceInfo> current_interfaces = GetPhysicalInterfaces();

        bool interfaces_changed = false;

        lock_.Lock();

        // Check if interfaces changed
        if (current_interfaces.size() != interfaces_.size()) {
            interfaces_changed = true;
        }
        else {
            for (size_t i = 0; i < current_interfaces.size(); ++i) {
                bool found = false;
                for (size_t j = 0; j < interfaces_.size(); ++j) {
                    if (current_interfaces[i] == interfaces_[j]) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    interfaces_changed = true;
                    break;
                }
            }
        }

        bool need_reinit = interfaces_changed ||
            !sockets_valid_ ||
            (consecutive_send_failures_ >= kMaxConsecutiveFailures);

        if (interfaces_changed) {
            network_state_ = NetworkState::kInterfacesChanged;
        }

        lock_.Unlock();

        if (need_reinit) {
            if (interfaces_changed) {
                std::cerr << "udpdiscovery: Network interfaces changed, "
                    << "reinitializing..." << std::endl;
            }
            else {
                std::cerr << "udpdiscovery: Network error detected, "
                    << "reinitializing..." << std::endl;
            }
            InitializeNetworking();
        }
    }

    void HandleReceiveError(int error_code) {
        std::cerr << "udpdiscovery: Receive error " << error_code << std::endl;

        lock_.Lock();
        // Mark sockets as potentially invalid
        // The sending thread will handle reinitialization
        network_state_ = NetworkState::kSocketError;
        lock_.Unlock();
    }

    void HandleSendError() {
        lock_.Lock();
        ++consecutive_send_failures_;
        if (consecutive_send_failures_ >= kMaxConsecutiveFailures) {
            network_state_ = NetworkState::kSocketError;
            std::cerr << "udpdiscovery: Multiple send failures, "
                << "will reinitialize network." << std::endl;
        }
        lock_.Unlock();
    }

    void ResetSendFailures() {
        lock_.Lock();
        consecutive_send_failures_ = 0;
        lock_.Unlock();
    }

    static std::string FormatIp(uint32_t ip) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
            (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF, ip & 0xFF);
        return buf;
    }

  void decreaseRefCountAndMaybeDestroySelfAndUnlock() {
    --ref_count_;
    int cur_ref_count = ref_count_;

    // This method is performed when the mutex is locked.
    lock_.Unlock();

    if (cur_ref_count <= 0) {
      if (cur_ref_count < 0) {
        // Shouldn't be there.
        std::cerr << "Strangly ref count is less than 0." << std::endl;
      }

      delete this;
    }
  }

  void processReceivedBuffer(long cur_time_ms, const IpPort& from,
                             const std::string& buffer) {
    Packet packet;

    ProtocolVersion packet_version = packet.Parse(buffer);
    bool is_supported_packet_version =
        (packet_version >= parameters_.min_supported_protocol_version() &&
         packet_version <= parameters_.max_supported_protocol_version());

    if (packet_version != kProtocolVersionUnknown &&
        is_supported_packet_version) {
      bool accept_packet = false;
      if (parameters_.application_id() == packet.application_id()) {
        if (!parameters_.discover_self()) {
          if (packet.peer_id() != peer_id_) {
            accept_packet = true;
          }
        } else {
          accept_packet = true;
        }
      }

      if (accept_packet) {
        lock_.Lock();

        std::list<DiscoveredPeer>::iterator find_it = discovered_peers_.end();
        for (std::list<DiscoveredPeer>::iterator it = discovered_peers_.begin();
             it != discovered_peers_.end(); ++it) {
          if (Same(parameters_.same_peer_mode(), (*it).ip_port(), from)) {
            find_it = it;
            break;
          }
        }

        if (packet.packet_type() == kPacketIAmHere) {
          if (find_it == discovered_peers_.end()) {
            discovered_peers_.push_back(DiscoveredPeer());
            discovered_peers_.back().set_ip_port(from);
            discovered_peers_.back().SetUserData(packet.user_data(),
                                                 packet.snapshot_index());
            discovered_peers_.back().set_last_updated(cur_time_ms);
          } else {
            bool update_user_data =
                ((*find_it).last_received_packet() < packet.snapshot_index());
            if (update_user_data) {
              (*find_it).SetUserData(packet.user_data(),
                                     packet.snapshot_index());
            }
            (*find_it).set_last_updated(cur_time_ms);
          }
        } else if (packet.packet_type() == kPacketIAmOutOfHere) {
          if (find_it != discovered_peers_.end()) {
            discovered_peers_.erase(find_it);
          }
        }

        lock_.Unlock();
      }
    }
  }

  void deleteIdle(long cur_time_ms) {
    lock_.Lock();

    std::vector<std::list<DiscoveredPeer>::iterator> to_delete;
    for (std::list<DiscoveredPeer>::iterator it = discovered_peers_.begin();
         it != discovered_peers_.end(); ++it) {
      if (cur_time_ms - (*it).last_updated() >
          parameters_.discovered_peer_ttl_ms())
        to_delete.push_back(it);
    }

    for (size_t i = 0; i < to_delete.size(); ++i)
      discovered_peers_.erase(to_delete[i]);

    lock_.Unlock();
  }

  // Internal send without lock management (caller must handle locking)
  bool sendInternal(ProtocolVersion protocol_version, PacketType packet_type) {
      // Assumes lock_ is held or not needed
      std::string user_data = user_data_;

      Packet packet;
      packet.set_packet_type(packet_type);
      packet.set_application_id(parameters_.application_id());
      packet.set_peer_id(peer_id_);
      packet.set_snapshot_index(packet_index_);
      packet.SwapUserData(user_data);

      ++packet_index_;

      std::string packet_data;
      if (!packet.Serialize(protocol_version, packet_data)) {
          return false;
      }

      bool any_success = false;

      if (parameters_.can_use_broadcast()) {
          for (const auto& iface : interfaces_) {
              sockaddr_in addr;
              memset(&addr, 0, sizeof(sockaddr_in));
              addr.sin_family = AF_INET;
              addr.sin_port = htons(parameters_.port());
              addr.sin_addr.s_addr = htonl(iface.broadcast);

              int result = sendto(sock_, packet_data.data(), packet_data.size(), 0,
                  (struct sockaddr*)&addr, sizeof(sockaddr_in));
              if (result > 0) {
                  any_success = true;
              }
          }
      }

      if (parameters_.can_use_multicast()) {
          for (const auto& iface : interfaces_) {
              struct in_addr mcast_if;
              mcast_if.s_addr = htonl(iface.ip);
              setsockopt(sock_, IPPROTO_IP, IP_MULTICAST_IF,
                  (const char*)&mcast_if, sizeof(mcast_if));

              sockaddr_in addr;
              memset(&addr, 0, sizeof(sockaddr_in));
              addr.sin_family = AF_INET;
              addr.sin_port = htons(parameters_.port());
              addr.sin_addr.s_addr = htonl(parameters_.multicast_group_address());

              int result = sendto(sock_, packet_data.data(), packet_data.size(), 0,
                  (struct sockaddr*)&addr, sizeof(sockaddr_in));
              if (result > 0) {
                  any_success = true;
              }
          }
      }

      return any_success;
  }

  void send(bool under_lock, ProtocolVersion protocol_version,
      PacketType packet_type) {
      if (!under_lock) {
          lock_.Lock();
      }
      std::string user_data = user_data_;
      if (!under_lock) {
          lock_.Unlock();
      }

      Packet packet;
      packet.set_packet_type(packet_type);
      packet.set_application_id(parameters_.application_id());
      packet.set_peer_id(peer_id_);
      packet.set_snapshot_index(packet_index_);
      packet.SwapUserData(user_data);

      ++packet_index_;

      std::string packet_data;
      if (!packet.Serialize(protocol_version, packet_data)) {
          return;
      }

      bool any_success = false;
      int total_attempts = 0;
      int failed_attempts = 0;

      // Send via broadcast on each interface's broadcast address
      if (parameters_.can_use_broadcast()) {
          for (const auto& iface : interfaces_) {
              sockaddr_in addr;
              memset(&addr, 0, sizeof(sockaddr_in));
              addr.sin_family = AF_INET;
              addr.sin_port = htons(parameters_.port());
              addr.sin_addr.s_addr = htonl(iface.broadcast);

              // Bind send to specific interface for this packet
              struct in_addr local_if;
              local_if.s_addr = htonl(iface.ip);
              setsockopt(sock_, IPPROTO_IP, IP_MULTICAST_IF,
                  (const char*)&local_if, sizeof(local_if));

              int result = sendto(sock_, packet_data.data(), packet_data.size(), 0,
                  (struct sockaddr*)&addr, sizeof(sockaddr_in));

              if (result > 0) any_success = true;
              else ++failed_attempts;
          }
      }

      // Send via multicast on each interface
      if (parameters_.can_use_multicast()) {
          for (const auto& iface : interfaces_) {
              // Set outgoing interface for this multicast packet
              struct in_addr mcast_if;
              mcast_if.s_addr = htonl(iface.ip);
              setsockopt(sock_, IPPROTO_IP, IP_MULTICAST_IF,
                  (const char*)&mcast_if, sizeof(mcast_if));

              sockaddr_in addr;
              memset(&addr, 0, sizeof(sockaddr_in));
              addr.sin_family = AF_INET;
              addr.sin_port = htons(parameters_.port());
              addr.sin_addr.s_addr = htonl(parameters_.multicast_group_address());

              int result = sendto(sock_, packet_data.data(), packet_data.size(), 0,
                  (struct sockaddr*)&addr, sizeof(sockaddr_in));
              if (result > 0) any_success = true;
              else ++failed_attempts;
          }
      }

      if (any_success) {
          ResetSendFailures();
      }
      else if (total_attempts > 0) {
          HandleSendError();
      }
  }

 private:
  PeerParameters parameters_;
  uint32_t peer_id_;
  SocketType binding_sock_;
  SocketType sock_;
  uint64_t packet_index_;

  MinimalisticMutex lock_;
  int ref_count_;
  bool exit_;
  std::string user_data_;
  std::list<DiscoveredPeer> discovered_peers_;

  // Network resilience members
  std::vector<InterfaceInfo> interfaces_;
  NetworkState network_state_;
  long last_interface_check_ms_;
  int consecutive_send_failures_;
  bool sockets_valid_;
};

#if defined(_WIN32)
DWORD WINAPI SendingThreadFunc(void* env_typeless) {
  PeerEnv* env = (PeerEnv*)env_typeless;
  env->SendingThreadFunc();

  return 0;
}
#else
void* SendingThreadFunc(void* env_typeless) {
  PeerEnv* env = (PeerEnv*)env_typeless;
  env->SendingThreadFunc();

  return 0;
}
#endif

#if defined(_WIN32)
DWORD WINAPI ReceivingThreadFunc(void* env_typeless) {
  PeerEnv* env = (PeerEnv*)env_typeless;
  env->ReceivingThreadFunc();

  return 0;
}
#else
void* ReceivingThreadFunc(void* env_typeless) {
  PeerEnv* env = (PeerEnv*)env_typeless;
  env->ReceivingThreadFunc();

  return 0;
}
#endif
};  // namespace impl

Peer::Peer() : env_(0), sending_thread_(0), receiving_thread_(0) {}

Peer::~Peer() { Stop(false); }

bool Peer::Start(const PeerParameters& parameters,
                 const std::string& user_data) {
  Stop(false);

  impl::PeerEnv* env = new impl::PeerEnv();
  if (!env->Start(parameters, user_data)) {
    delete env;
    env = 0;

    return false;
  }

  env_ = env;

  sending_thread_ = new impl::MinimalisticThread(impl::SendingThreadFunc, env_);

  if (parameters.can_discover()) {
    receiving_thread_ =
        new impl::MinimalisticThread(impl::ReceivingThreadFunc, env_);
  }

  return true;
}

void Peer::SetUserData(const std::string& user_data) {
  if (env_) {
    env_->SetUserData(user_data);
  }
}

std::list<DiscoveredPeer> Peer::ListDiscovered() const {
  std::list<DiscoveredPeer> result;
  if (env_) {
    result = env_->ListDiscovered();
  }
  return result;
}

void Peer::Stop() { Stop(/* wait_for_threads= */ false); }

void Peer::StopAndWaitForThreads() { Stop(/* wait_for_threads= */ true); }


NetworkState Peer::GetNetworkState() const {
    if (env_) {
        return env_->GetNetworkState();
    }
    return NetworkState::kNoInterfaces;
}

bool Peer::IsNetworkHealthy() const {
    return GetNetworkState() == NetworkState::kOk;
}


void Peer::Stop(bool wait_for_threads) {
  if (!env_) {
    return;
  }

  env_->Exit();

  // Threads live longer than the object itself. So env will be deleted in one
  // of the threads.
  env_ = 0;

  if (wait_for_threads) {
    if (sending_thread_) {
      sending_thread_->Join();
    }

    if (receiving_thread_) {
      receiving_thread_->Join();
    }
  } else {
    if (sending_thread_) {
      sending_thread_->Detach();
    }

    if (receiving_thread_) {
      receiving_thread_->Detach();
    }
  }

  delete sending_thread_;
  sending_thread_ = 0;
  delete receiving_thread_;
  receiving_thread_ = 0;
}

bool Same(PeerParameters::SamePeerMode mode, const IpPort& lhv,
          const IpPort& rhv) {
  switch (mode) {
    case PeerParameters::kSamePeerIp:
      return lhv.ip() == rhv.ip();

    case PeerParameters::kSamePeerIpAndPort:
      return (lhv.ip() == rhv.ip()) && (lhv.port() == rhv.port());
  }

  return false;
}

bool Same(PeerParameters::SamePeerMode mode,
          const std::list<DiscoveredPeer>& lhv,
          const std::list<DiscoveredPeer>& rhv) {
  for (std::list<DiscoveredPeer>::const_iterator lhv_it = lhv.begin();
       lhv_it != lhv.end(); ++lhv_it) {
    std::list<DiscoveredPeer>::const_iterator in_rhv = rhv.end();
    for (std::list<DiscoveredPeer>::const_iterator rhv_it = rhv.begin();
         rhv_it != rhv.end(); ++rhv_it) {
      if (Same(mode, (*lhv_it).ip_port(), (*rhv_it).ip_port())) {
        in_rhv = rhv_it;
        break;
      }
    }

    if (in_rhv == rhv.end()) {
      return false;
    }
  }

  for (std::list<DiscoveredPeer>::const_iterator rhv_it = rhv.begin();
       rhv_it != rhv.end(); ++rhv_it) {
    std::list<DiscoveredPeer>::const_iterator in_lhv = lhv.end();
    for (std::list<DiscoveredPeer>::const_iterator lhv_it = lhv.begin();
         lhv_it != lhv.end(); ++lhv_it) {
      if (Same(mode, (*rhv_it).ip_port(), (*lhv_it).ip_port())) {
        in_lhv = lhv_it;
        break;
      }
    }

    if (in_lhv == lhv.end()) {
      return false;
    }
  }

  return true;
}
};  // namespace udpdiscovery
