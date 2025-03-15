# Security Agent

Bu proje, sistem güvenliğini izlemek ve potansiyel tehditleri tespit etmek için tasarlanmış kapsamlı bir C++ güvenlik ajanıdır.

## Proje Amacı

Security Agent, aşağıdaki güvenlik izleme ve tespit özelliklerini sağlar:

- **Süreç İzleme**: Şüpheli süreçleri tespit eder, yüksek CPU/bellek kullanımını izler
- **Ağ İzleme**: Şüpheli ağ bağlantılarını ve trafiğini izler
- **Dosya İzleme**: Kritik sistem dosyalarındaki değişiklikleri tespit eder
- **Syslog İzleme**: Sistem günlüklerindeki şüpheli etkinlikleri izler
- **Tehdit Tespiti**: Önceden tanımlanmış kurallara göre tehditleri tespit eder
- **Olay Yönetimi**: Güvenlik olaylarını merkezi bir şekilde yönetir
- **Yanıt Mekanizması**: Tespit edilen tehditlere otomatik yanıt verir

## Gereksinimler

- C++17 uyumlu derleyici (GCC 7+, Clang 5+, MSVC 19.14+)
- CMake 3.10+
- OpenSSL
- yaml-cpp
- RabbitMQ C istemcisi
- GTest (testler için)
- CURL

### macOS için Bağımlılıklar

```bash
brew install openssl yaml-cpp rabbitmq-c gtest curl
```

### Ubuntu için Bağımlılıklar

```bash
sudo apt-get install libssl-dev libyaml-cpp-dev librabbitmq-dev libgtest-dev libcurl4-openssl-dev
```

## Kurulum

1. Repoyu klonlayın:

```bash
git clone https://github.com/merlingo/security_agent.git
cd security_agent
```

2. Build dizini oluşturun ve CMake ile projeyi yapılandırın:

```bash
mkdir build && cd build
cmake ..
```

3. Projeyi derleyin:

```bash
make
```

## Yapılandırma

Uygulama, `config.yaml` dosyasından yapılandırma ayarlarını okur. Örnek bir yapılandırma dosyası proje içinde bulunmaktadır. Aşağıdaki bileşenler için yapılandırma ayarları mevcuttur:

- Logging Modülü
- Routing Modülü
- Monitoring Modülü (Syslog, Network, Process, File)
- Detection Modülü
- Response Modülü

## Çalıştırma

Uygulamayı çalıştırmak için:

```bash
./security_agent ../config.yaml
```

Uygulama, yapılandırma dosyasında belirtilen ayarlara göre çalışacak ve logları `logs/security_agent.log` dosyasına yazacaktır.

## Testler

Testleri çalıştırmak için:

```bash
ctest
```

veya belirli bir testi çalıştırmak için:

```bash
./logging_module_test
./routing_module_test
./syslog_monitoring_test
```

## Proje Yapısı

```
security_agent/
├── include/                  # Header dosyaları
│   └── modules/              # Modül header dosyaları
│       ├── behavior/         # Davranış analizi modülü
│       ├── config/           # Yapılandırma modülü
│       ├── detection/        # Tehdit tespit modülü
│       ├── event_management/ # Olay yönetimi modülü
│       ├── logging/          # Günlük modülü
│       ├── monitoring/       # İzleme modülleri
│       ├── response/         # Yanıt modülü
│       └── routing/          # Yönlendirme modülü
├── src/                      # Kaynak dosyaları
│   ├── main.cpp              # Ana uygulama
│   └── modules/              # Modül implementasyonları
├── tests/                    # Test dosyaları
├── config/                   # Yapılandırma dosyaları
│   ├── detection_rules.json  # Tehdit tespit kuralları
│   └── suspicious_processes.json # Şüpheli süreç listesi
├── logs/                     # Log dosyaları
├── CMakeLists.txt            # CMake yapılandırması
└── config.yaml               # Ana yapılandırma dosyası
```

## Katkıda Bulunma

1. Repoyu fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add some amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Daha fazla bilgi için `LICENSE` dosyasına bakın.
