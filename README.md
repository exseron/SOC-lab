# SOC / LAB — SIEM Simülatörü

Tarayıcıda çalışan, tamamen yerel bir **SOC analisti eğitim laboratuvarı**. 11 saldırı kategorisinde 55 sentetik alarmı incelersin: ilişkili logları (WAF, EDR, DNS, Cloud Audit, DLP…) okur, inceleme sorularını yanıtlar, notunu yazar ve alarmı sınıflandırırsın. Sonra kendi analizini örnek analizle karşılaştırırsın.

- **Kurulum yok:** Yalnızca Python 3.9+ standart kütüphanesi.
- **Tek dosya:** `SOC_Lab.py` arayüzün tamamını içinde taşır; tek başına kopyalanıp çalıştırılabilir.
- **Yerel ve izole:** Sunucu yalnızca `127.0.0.1` üzerinde dinler, dışarıya istek atmaz. Tüm veriler sentetiktir (RFC 5737 belgeleme IP'leri, `.test` alan adları).

## Çalıştırma

```bash
# Windows
py SOC_Lab.py

# macOS / Linux
python3 SOC_Lab.py
```

Tarayıcı otomatik açılır (açılmazsa terminaldeki adrese git). Durdurmak için `Ctrl+C`.

| Seçenek | Açıklama |
| --- | --- |
| `--port 8788` | Belirli bir port kullan. Verilmezse 8787 denenir, doluysa sıradaki boş port seçilir. `--port 0` rastgele boş port. |
| `--no-browser` | Tarayıcıyı otomatik açma. |
| `--verbose` | Her HTTP isteğini terminale yazdır. |
| `--version` | Sürümü göster. |

## Senaryolar

| Kategori | Örnekler |
| --- | --- |
| DDoS | HTTP flood, UDP reflection, SYN flood, meşru kampanya trafiği |
| SQL Injection | Boolean/time-based SQLi, engellenen deneme, yanlış pozitif |
| XSS | Reflected, stored, DOM XSS |
| Web ve API | Path traversal, SSRF, IDOR, command injection, web shell |
| Kimlik ve AD | Password spraying, MFA fatigue, DCSync, Kerberoasting |
| Endpoint ve EDR | Ransomware, LSASS erişimi, persistence, Office → PowerShell |
| Ağ ve DNS | DNS tunneling, beaconing, lateral movement |
| Bulut ve Kubernetes | IAM yetki artışı, S3 indirme, OAuth consent, privileged pod |
| E-posta ve Phishing | Credential phishing, BEC, zararlı ek |
| Veri Sızıntısı ve DLP | Toplu indirme, arşiv yükleme, USB kopyası |
| CI/CD ve Tedarik Zinciri | Pipeline değişikliği, imaj digest değişimi, secret sızıntısı, bağımlılık kurulum script'i |

Birçok senaryoda yanlış pozitif / meşru etkinlik örnekleri de var: amaç yalnızca saldırıyı bulmak değil, kanıta dayalı karar vermek.

## Nasıl kullanılır

1. Soldan bir senaryo seç (veya **Genel Bakış**'ta hepsini gör). Seçim URL'de tutulur, ör. `http://127.0.0.1:8787/#identity`.
2. Kuyruktan bir alarm aç; logları incele, soruları yanıtla, **Analist Notu**'nu yaz.
3. Durumu **İnceleniyor** veya **Kapatıldı** yapıp kaydet (`Ctrl+Enter`).
4. **Örnek Analizi Göster** ile kendi sonucunu karşılaştır.
5. Bitirince üst bardaki **Rapor** ile tüm notlarını Markdown olarak indir.

Kısayollar: `/` aramaya odaklanır, `Ctrl+Enter` kaydeder, `Esc` paneli kapatır (kaydedilmemiş değişiklik varsa onay ister).

İlerleme ve notlar yalnızca tarayıcının `localStorage`'ında tutulur; hiçbir yere gönderilmez. **Sıfırla** hepsini siler.

## Geliştirme

```
SOC_Lab.py          # Çalıştırılan tek dosya: sunucu + gömülü arayüz
web/                # Arayüzün düzenlenebilir kaynakları
  index.html, styles.css, app.js
  data.js           # Senaryo tanımları ve ilk 6 detaylı alarm
  exercises.js      # Diğer senaryolar ve alarmlar (exercise(...) yardımcı fonksiyonu)
tools/build.py      # web/ içeriğini SOC_Lab.py içine gömer
tests/              # Sunucu, build ve veri doğrulama testleri
```

`web/` altında değişiklik yaptıktan sonra:

```bash
python tools/build.py            # SOC_Lab.py içindeki gömülü arşivi yenile
python -m unittest discover -s tests -v
```

`python tools/build.py --check` gömülü içerik `web/` ile aynı değilse hata verir; CI her push'ta bunu ve testleri çalıştırır. Node.js kuruluysa testler ayrıca JS sözdizimini ve `tests/validate_data.mjs` ile alarm verisinin bütünlüğünü (benzersiz ID, geçerli senaryo/önem/durum, saat biçimi) kontrol eder.

### Yeni alarm eklemek

`web/exercises.js` içine bir `exercise(...)` çağrısı ekle:

```js
exercise(156, "network", 52, "Örnek Başlık", "high", "10.44.2.50", "host.lab.test",
  "Alarm açıklaması.",
  [["DNS", {client: "10.44.2.50", query: "example.test"}],
   ["Proxy", {dst: "example.test", bytes_out: 1200}],
   ["EDR", {process: "example.exe"}]],
  "Analiste sorulacak ana soru?",
  "Örnek analiz ve önerilen aksiyon.");
```

Sonra `python tools/build.py` çalıştır.

## Güvenlik notları

- Sunucu yalnızca loopback'e bağlanır ve yalnızca `127.0.0.1:<port>` / `localhost:<port>` Host başlıklarını kabul eder (DNS rebinding koruması).
- Yanıtlar sıkı bir Content-Security-Policy ile gelir: dış script, ağ isteği, form gönderimi ve iframe'e gömülme kapalı.
- Yalnızca sabit bir dosya listesi sunulur; disk üzerindeki hiçbir dosyaya erişilmez.
