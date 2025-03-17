#include "modules/response/response_module.hpp"
#include "modules/logging/logging_module.hpp"
#include "modules/routing/routing_module.hpp"
#include "modules/monitoring/file_monitoring.hpp"
#include "modules/monitoring/process_monitoring.hpp"
#include "modules/monitoring/network_monitoring.hpp"
#include "modules/monitoring/syslog_monitoring.hpp"
#include "modules/detection/detection_module.hpp"
#include "modules/event_management/event_manager.hpp"

#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>
#include <vector>
#include <memory>
#include <map>
#include <string>
#include <mutex>
#include <condition_variable>

// İşletim sistemi tespiti
#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
    #define IS_WINDOWS 1
#elif defined(__APPLE__)
    #include <CoreFoundation/CoreFoundation.h>
    #include <ServiceManagement/ServiceManagement.h>
    #define IS_MAC 1
#else
    #include <sys/types.h>
    #include <unistd.h>
    #define IS_LINUX 1
#endif

// Global değişkenler
std::atomic<bool> running(true);
std::mutex monitoring_mutex;
std::condition_variable monitoring_cv;

// Monitoring modül durumları
struct MonitoringStatus {
    std::thread thread;
    std::atomic<bool> running{false};
    std::atomic<bool> stopped{false};
    std::chrono::system_clock::time_point last_check;
    std::string name;
};

// Sinyal yakalama fonksiyonu
void signalHandler(int signum) {
    std::cout << "Sinyal " << signum << " alındı. Kapatılıyor..." << std::endl;
    running = false;
    monitoring_cv.notify_all();
}

// Monitoring işlemi başlatma fonksiyonu
template<typename MonitoringClass>
void startMonitoring(
    MonitoringStatus& status,
    std::shared_ptr<MonitoringClass> module,
    std::shared_ptr<security_agent::logging::LoggingModule> logging_module
) {
    status.running = true;
    status.stopped = false;
    status.last_check = std::chrono::system_clock::now();
    
    try {
        // Başlatma log mesajı
        if (logging_module) {
            logging_module->log(
                security_agent::logging::LogLevel::INFO,
                status.name,
                "startMonitoring",
                status.name + " modülü başlatılıyor",
                __FILE__,
                __FUNCTION__,
                std::to_string(__LINE__),
                std::nullopt
            );
        }
        
        // Monitoring işlemini başlat
        module->monitor();
        
    } catch (const std::exception& e) {
        if (logging_module) {
            logging_module->log(
                security_agent::logging::LogLevel::ERROR,
                status.name,
                "startMonitoring",
                status.name + " modülü başlatılırken hata: " + e.what(),
                __FILE__,
                __FUNCTION__,
                std::to_string(__LINE__),
                std::nullopt
            );
        }
    }
    
    // Tamamlandı
    status.stopped = true;
    status.running = false;
    monitoring_cv.notify_all();
}

// İşletim sistemine göre servis oluşturma
bool installService(const std::string& service_name, const std::string& display_name, const std::string& description, const std::string& executable_path) {
#if defined(IS_WINDOWS)
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (schSCManager == NULL) {
        std::cerr << "OpenSCManager failed: " << GetLastError() << std::endl;
        return false;
    }
    
    SC_HANDLE schService = CreateService(
        schSCManager,
        service_name.c_str(),
        display_name.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        executable_path.c_str(),
        NULL, NULL, NULL, NULL, NULL);
    
    if (schService == NULL) {
        std::cerr << "CreateService failed: " << GetLastError() << std::endl;
        CloseServiceHandle(schSCManager);
        return false;
    }
    
    SERVICE_DESCRIPTION sd;
    sd.lpDescription = const_cast<LPSTR>(description.c_str());
    ChangeServiceConfig2(schService, SERVICE_CONFIG_DESCRIPTION, &sd);
    
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return true;
    
#elif defined(IS_MAC)
    // Mac OS için launchd plist oluştur
    std::string plist_path = "/Library/LaunchDaemons/" + service_name + ".plist";
    std::ofstream plist_file(plist_path);
    
    if (!plist_file.is_open()) {
        std::cerr << "Launchd plist dosyası oluşturulamadı: " << plist_path << std::endl;
        return false;
    }
    
    plist_file << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    plist_file << "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n";
    plist_file << "<plist version=\"1.0\">\n";
    plist_file << "<dict>\n";
    plist_file << "    <key>Label</key>\n";
    plist_file << "    <string>" << service_name << "</string>\n";
    plist_file << "    <key>ProgramArguments</key>\n";
    plist_file << "    <array>\n";
    plist_file << "        <string>" << executable_path << "</string>\n";
    plist_file << "        <string>/etc/security_agent/config.yaml</string>\n";
    plist_file << "    </array>\n";
    plist_file << "    <key>RunAtLoad</key>\n";
    plist_file << "    <true/>\n";
    plist_file << "    <key>KeepAlive</key>\n";
    plist_file << "    <true/>\n";
    plist_file << "    <key>StandardErrorPath</key>\n";
    plist_file << "    <string>/var/log/" << service_name << ".err</string>\n";
    plist_file << "    <key>StandardOutPath</key>\n";
    plist_file << "    <string>/var/log/" << service_name << ".log</string>\n";
    plist_file << "</dict>\n";
    plist_file << "</plist>\n";
    
    plist_file.close();
    
    // Launchd servisi yükle
    std::string cmd = "launchctl load " + plist_path;
    int result = system(cmd.c_str());
    
    if (result != 0) {
        std::cerr << "Launchctl load başarısız: " << result << std::endl;
        return false;
    }
    
    return true;
    
#elif defined(IS_LINUX)
    // Linux için systemd servis dosyası oluştur
    std::string service_path = "/etc/systemd/system/" + service_name + ".service";
    std::ofstream service_file(service_path);
    
    if (!service_file.is_open()) {
        std::cerr << "Systemd servis dosyası oluşturulamadı: " << service_path << std::endl;
        return false;
    }
    
    service_file << "[Unit]\n";
    service_file << "Description=" << description << "\n";
    service_file << "After=network.target\n\n";
    
    service_file << "[Service]\n";
    service_file << "Type=simple\n";
    service_file << "ExecStart=" << executable_path << " /etc/security_agent/config.yaml\n";
    service_file << "Restart=always\n";
    service_file << "RestartSec=15\n\n";
    
    service_file << "[Install]\n";
    service_file << "WantedBy=multi-user.target\n";
    
    service_file.close();
    
    // Systemd servisini etkinleştir
    std::string cmd1 = "systemctl daemon-reload";
    std::string cmd2 = "systemctl enable " + service_name;
    std::string cmd3 = "systemctl start " + service_name;
    
    system(cmd1.c_str());
    int result = system(cmd2.c_str());
    
    if (result != 0) {
        std::cerr << "Systemctl enable başarısız: " << result << std::endl;
        return false;
    }
    
    result = system(cmd3.c_str());
    if (result != 0) {
        std::cerr << "Systemctl start başarısız: " << result << std::endl;
        return false;
    }
    
    return true;
#endif

    return false;
}

// Windows servis işleyicileri
#ifdef IS_WINDOWS
SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;

void WINAPI ServiceControlHandler(DWORD controlCode) {
    switch (controlCode) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            serviceStatus.dwWaitHint = 30000; // 30 saniye
            SetServiceStatus(serviceStatusHandle, &serviceStatus);
            
            // Servis durdurma sinyali gönder
            running = false;
            monitoring_cv.notify_all();
            break;
            
        case SERVICE_CONTROL_INTERROGATE:
            // Durum raporla
            SetServiceStatus(serviceStatusHandle, &serviceStatus);
            break;
            
        default:
            break;
    }
}

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    serviceStatus.dwCurrentState = SERVICE_START_PENDING;
    serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    serviceStatus.dwWin32ExitCode = 0;
    serviceStatus.dwServiceSpecificExitCode = 0;
    serviceStatus.dwCheckPoint = 0;
    serviceStatus.dwWaitHint = 0;
    
    serviceStatusHandle = RegisterServiceCtrlHandler("SecurityAgent", ServiceControlHandler);
    
    if (serviceStatusHandle == (SERVICE_STATUS_HANDLE)0) {
        return;
    }
    
    serviceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);
    
    // Ana fonksiyonu çağır (aşağıdaki main fonksiyonu içeriği)
    std::string config_path = "C:\\Program Files\\SecurityAgent\\config.yaml";
    main_service(config_path);
    
    serviceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);
}
#endif

// Ana servis fonksiyonu
int main_service(const std::string& config_path) {
    try {
        // Modülleri başlat
        auto logging_module = std::make_shared<security_agent::logging::LoggingModule>(config_path);
        
        // Başlangıç log mesajı
        logging_module->log(
            security_agent::logging::LogLevel::INFO,
            "Main",
            "main_service",
            "Security Agent başlatılıyor",
            __FILE__,
            __FUNCTION__,
            std::to_string(__LINE__),
            std::nullopt
        );
        
        // Event manager
        auto event_manager = std::make_shared<security_agent::event_management::EventManager>(
            "localhost", 5672, "guest", "guest", "/", false
        );
        
        // Routing modülü
        auto routing_module = std::make_shared<security_agent::routing::RoutingModule>(config_path);
        
        // Detection modülü
        auto detection_module = std::make_shared<security_agent::detection::DetectionModule>(
            config_path, event_manager, logging_module
        );
        
        // Monitoring modülleri
        auto file_monitoring = std::make_shared<security_agent::monitoring::FileMonitoring>(
            config_path, event_manager, logging_module, routing_module, detection_module
        );
        
        auto process_monitoring = std::make_shared<security_agent::monitoring::ProcessMonitoring>(
            config_path, event_manager, logging_module, routing_module, detection_module
        );
        
        auto network_monitoring = std::make_shared<security_agent::monitoring::NetworkMonitoring>(
            config_path, event_manager, logging_module, routing_module, detection_module
        );
        
        auto syslog_monitoring = std::make_shared<security_agent::monitoring::SyslogMonitoring>(
            config_path, event_manager, logging_module, routing_module, detection_module
        );
        
        // Response modülü
        auto response_module = std::make_shared<security_agent::response::ResponseModule>(config_path);
        
        // Monitoring durumları
        std::map<std::string, MonitoringStatus> monitoring_statuses;
        
        // File monitoring durumu
        monitoring_statuses["FileMonitoring"].name = "FileMonitoring";
        
        // Process monitoring durumu
        monitoring_statuses["ProcessMonitoring"].name = "ProcessMonitoring";
        
        // Network monitoring durumu
        monitoring_statuses["NetworkMonitoring"].name = "NetworkMonitoring";
        
        // Syslog monitoring durumu
        monitoring_statuses["SyslogMonitoring"].name = "SyslogMonitoring";
        
        // Response modülünü başlat
        response_module->start();
        logging_module->log(
            security_agent::logging::LogLevel::INFO,
            "Main",
            "main_service",
            "Response modülü başlatıldı",
            __FILE__,
            __FUNCTION__,
            std::to_string(__LINE__),
            std::nullopt
        );
        
        std::cout << "Security Agent başlatıldı. Çıkmak için Ctrl+C tuşlarına basın." << std::endl;
        
        // Monitoring thread'leri başlat
        monitoring_statuses["FileMonitoring"].thread = std::thread(
            startMonitoring<security_agent::monitoring::FileMonitoring>,
            std::ref(monitoring_statuses["FileMonitoring"]),
            file_monitoring,
            logging_module
        );
        
        monitoring_statuses["ProcessMonitoring"].thread = std::thread(
            startMonitoring<security_agent::monitoring::ProcessMonitoring>,
            std::ref(monitoring_statuses["ProcessMonitoring"]),
            process_monitoring,
            logging_module
        );
        
        monitoring_statuses["NetworkMonitoring"].thread = std::thread(
            startMonitoring<security_agent::monitoring::NetworkMonitoring>,
            std::ref(monitoring_statuses["NetworkMonitoring"]),
            network_monitoring,
            logging_module
        );
        
        monitoring_statuses["SyslogMonitoring"].thread = std::thread(
            startMonitoring<security_agent::monitoring::SyslogMonitoring>,
            std::ref(monitoring_statuses["SyslogMonitoring"]),
            syslog_monitoring,
            logging_module
        );
        
        // Ana döngü - monitoring durumlarını kontrol et
        int counter = 0;
        while (running) {
            // 5 saniyelik uyku
            {
                std::unique_lock<std::mutex> lock(monitoring_mutex);
                monitoring_cv.wait_for(lock, std::chrono::seconds(5), [&]{ return !running; });
                
                if (!running) {
                    break;
                }
            }
            
            // Her monitoring işlemini kontrol et
            for (auto& [name, status] : monitoring_statuses) {
                // Eğer monitoring thread durmuşsa, yeniden başlat
                if (status.stopped) {
                    logging_module->log(
                        security_agent::logging::LogLevel::WARNING,
                        "Main",
                        "main_service",
                        name + " durdu, 15 saniye sonra yeniden başlatılacak",
                        __FILE__,
                        __FUNCTION__,
                        std::to_string(__LINE__),
                        std::nullopt
                    );
                    
                    // 15 saniye bekle
                    std::this_thread::sleep_for(std::chrono::seconds(15));
                    
                    // Önceki thread'i bekle
                    if (status.thread.joinable()) {
                        status.thread.join();
                    }
                    
                    // Monitoring tipine göre yeniden başlat
                    if (name == "FileMonitoring") {
                        status.thread = std::thread(
                            startMonitoring<security_agent::monitoring::FileMonitoring>,
                            std::ref(status),
                            file_monitoring,
                            logging_module
                        );
                    } else if (name == "ProcessMonitoring") {
                        status.thread = std::thread(
                            startMonitoring<security_agent::monitoring::ProcessMonitoring>,
                            std::ref(status),
                            process_monitoring,
                            logging_module
                        );
                    } else if (name == "NetworkMonitoring") {
                        status.thread = std::thread(
                            startMonitoring<security_agent::monitoring::NetworkMonitoring>,
                            std::ref(status),
                            network_monitoring,
                            logging_module
                        );
                    } else if (name == "SyslogMonitoring") {
                        status.thread = std::thread(
                            startMonitoring<security_agent::monitoring::SyslogMonitoring>,
                            std::ref(status),
                            syslog_monitoring,
                            logging_module
                        );
                    }
                }
            }
            
            counter++;
            
            // Periyodik log mesajı
            logging_module->log(
                security_agent::logging::LogLevel::INFO,
                "Main",
                "main_service",
                "Security Agent çalışıyor - " + std::to_string(counter) + ". kontrol",
                __FILE__,
                __FUNCTION__,
                std::to_string(__LINE__),
                std::nullopt
            );
        }
        
        // Kapanış log mesajı
        logging_module->log(
            security_agent::logging::LogLevel::INFO,
            "Main",
            "main_service",
            "Security Agent kapatılıyor",
            __FILE__,
            __FUNCTION__,
            std::to_string(__LINE__),
            std::nullopt
        );
        
        // Response modülünü durdur
        response_module->stop();
        
        // Thread'lerin kapanmasını bekle
        for (auto& [name, status] : monitoring_statuses) {
            if (status.thread.joinable()) {
                status.thread.join();
            }
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Hata: " << e.what() << std::endl;
        return 1;
    }
}

// Ana fonksiyon
int main(int argc, char** argv) {
    // Sinyal işleyicilerini ayarla
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Komut satırı argümanlarını kontrol et
    if (argc < 2) {
        std::cerr << "Kullanım: " << argv[0] << " <config_file> [--install-service]" << std::endl;
        return 1;
    }
    
    std::string config_path = argv[1];
    
    // Servis kurulumu kontrol et
    if (argc > 2 && std::string(argv[2]) == "--install-service") {
        std::string executable_path(argv[0]);
        return installService("SecurityAgent", "Security Agent Service", 
                            "Güvenlik izleme ve tepki servisi", executable_path) ? 0 : 1;
    }

#ifdef IS_WINDOWS
    // Windows'ta servis olarak çalıştır
    if (argc > 2 && std::string(argv[2]) == "--service") {
        SERVICE_TABLE_ENTRY serviceTable[] = {
            {"SecurityAgent", (LPSERVICE_MAIN_FUNCTION)ServiceMain},
            {NULL, NULL}
        };
        
        if (!StartServiceCtrlDispatcher(serviceTable)) {
            DWORD error = GetLastError();
            if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
                // Servis olarak çalışmıyor, normal uygulamaya devam et
                return main_service(config_path);
            } else {
                std::cerr << "Service dispatcher failed: " << error << std::endl;
                return 1;
            }
        }
        return 0;
    } else {
        // Normal uygulama olarak çalıştır
        return main_service(config_path);
    }
#else
    // Mac ve Linux için direkt servis fonksiyonunu çağır
    return main_service(config_path);
#endif
} 