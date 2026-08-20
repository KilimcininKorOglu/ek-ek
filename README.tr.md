# ek-ek

[English](README.md) | **Türkçe**

`ek-ek`, yük dağıtımı ve yüksek erişilebilirliği tek bir Rust binary'sinde birleştiren bir load balancer'dır. Bugün bu iş iki ayrı yazılımla, HAProxy ve Keepalived ile yapılır. İkisi ayrı metin dosyalarıyla yapılandırılır, birbirlerinin durumundan haberdar değildir ve doğru kurulumu protokol seviyesinde bilgi ister. `ek-ek` aynı işi tek bir yapılandırma modeli, tek bir web arayüzü ve node başına tek bir servis ile yapar.

## Kimin için

Orta ölçekli kurumlarda çalışan bir veya iki kişilik IT ekipleri. Hedef, VRRP priority değeri veya HAProxy backend sözdizimi bilmeden çalışan ve yedekli bir load balancer kurabilmektir.

## Durum

Geliştirme aşamasında. Henüz kullanılabilir bir sürüm yayımlanmadı.

## Mimari

Her node aynı binary'yi çalıştırır. Merkezi bir yönetim sunucusu yoktur, node'lar birbirine peer olarak bağlanır.

Binary iki process çalıştırır:

| Process            | Sorumluluk                                                                                   |
|--------------------|----------------------------------------------------------------------------------------------|
| `ek-ek node-agent` | Yapılandırma deposu, cluster üyeliği, VRRP durum makinesi, VIP yönetimi, web arayüzü ve API. |
| `ek-ek data-plane` | Trafiğin kendisi. HTTP, TCP, UDP proxy'si, TLS sonlandırma, health check.                    |

İki process ayrıdır çünkü yeni bir dinleme portu eklendiğinde `data-plane` process'i yerine yenisi konur. VRRP aynı process içinde çalışsaydı bu değişim VIP'in kısa süre iki node'da birden görünmesine yol açardı.

Yapılandırma Raft ile replike edilir. Raft'ın quorum kaybetmesi trafiği etkilemez: bu durumda yapılandırma değiştirilemez, ancak var olan yapılandırma çalışmaya devam eder. VIP sahipliği hiçbir zaman Raft liderliğinden türetilmez.

### Kullanılan bileşenler

- [pingora](https://github.com/cloudflare/pingora), HTTP data plane.
- [rustls](https://github.com/rustls/rustls), TLS.
- [openraft](https://github.com/databendlabs/openraft), yapılandırma replikasyonu.
- SQLite, durum makinesi deposu.

## Desteklenen platformlar

Yalnızca Linux. Hedef dağıtımlar Debian, Ubuntu ve RHEL ailesi.

## Lisans

Çift lisans:

- [AGPL-3.0](LICENSE). Varsayılan lisans, ücretsiz. Yalnızca İngilizce metin bağlayıcıdır.
- [Ticari lisans](LICENSE-COMMERCIAL.tr.md). Kapalı kaynak kullanım için.

## Katkı

CLA süreci kurulana kadar dış katkı kabul edilmez. Çift lisans modeli telif hakkının tek elde toplanmasını gerektirir ve imzasız birleştirilen bir katkı bu modeli geri dönülmez biçimde bozar.
