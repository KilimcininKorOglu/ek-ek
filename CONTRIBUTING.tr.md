# ek-ek'e katkı

English: [CONTRIBUTING.md](CONTRIBUTING.md)

## Kod yazmadan önce

Hiçbir şey. Depoyu fork'layın, pull request açın. İmzalanacak bir sözleşme ve
commit'e eklenecek bir imza satırı yok.

Katkılar, projenin geri kalanıyla aynı lisansla, [AGPL-3.0-or-later](LICENSE)
ile gelir. Pull request açarak çalışmanızı bu lisansla sunmuş olursunuz.

## Projeyi ayağa kaldırma

```bash
make dev-env     # .env ve docker-data dizinlerini olustur
make dev-up      # uc node'lu kumeyi baslat
make dev-verify  # urunun dayandigi on kosullari kanitla
```

Tüm hedefleri `make help` listeler.

## Pull request açmadan önce

```bash
make ci          # bicim, clippy, lisans, sir, katman, birim testleri
make dev-test    # docker kumesine karsi entegrasyon testleri
```

İkisi de geçmeli. Kalite kapıları için CI yalnızca `make ci` hedefini çağırır,
yani yerelde geçiyorsa orada da geçer.

## Kodun uyması gerekenler

- Kod, kod yorumları ve log mesajları İngilizce yazılır.
- Rust: testler dışında `.unwrap()` veya `.expect()` kullanılmaz. `Result`
  döndürülür ve `?` kullanılır. Workspace lint'leri bunu zorlar.
- SQL parametreli yazılır. Sorgu asla string birleştirme ile kurulmaz.
- Web arayüzü `alert()`, `confirm()` veya `prompt()` çağırmaz. Diyaloglar
  SweetAlert2 ile yapılır. Tarayıcı tarafı durum çerezde tutulur, asla
  `localStorage` veya `sessionStorage` içinde değil. `make ci` içindeki bir
  script bunların hepsini denetler.
- Her Rust kaynak dosyası [LICENSE-HEADER.txt](LICENSE-HEADER.txt) içindeki iki
  satırlık başlığı taşır.
- Crate bağımlılık yönü sabittir ve denetlenir. `ek-ek-config` hiçbir workspace
  crate'ine bağımlı değildir; `ek-ek-dataplane` ile `ek-ek-vrrp` birbirini
  tanımaz; `ek-ek-itest` hiçbir workspace crate'ine bağımlı olamaz.

## Commit'ler

Bir commit, bir mantıksal değişiklik. Mesajı kendi başına anlaşılacak şekilde
yazın: atıfta bulunabileceği planlama belgeleri bu depoda değil.

Asla sır commit etmeyin. `.env`, özel anahtarlar ve sertifikalar depo dışında
kalır. `make ci` içinde desen tabanlı bir tarama koşar, ama bu bir güvenlik ağı,
garanti değil.

## Güvenlik açığı bildirimi

Herkese açık bir issue açmayın. Bu depoda GitHub Private Vulnerability Reporting
kullanın veya `security@keremgok.tr` adresine yazın.

Desteklenen sürümleri, yanıt süresini ve PGP anahtarını içeren tam politika
ilerideki `SECURITY.md` ile gelecek. O zamana kadar çalışan kanallar bu ikisi.

## Hata bildirimi ve özellik önerisi

Küçük bir düzeltmeden büyük her şey için önce issue açın. Ne gözlemlediğinizi,
ne beklediğinizi ve ortamı yazın: dağıtım, kernel, ek-ek'in nasıl kurulduğu ve
kümede kaç node olduğu.
