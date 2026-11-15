# Değişiklik Günlüğü

## 1.1.0

### Sunucu
- Tüm yanıtlara Content-Security-Policy, X-Frame-Options, Referrer-Policy, COOP/CORP başlıkları.
- DNS rebinding koruması: yerel olmayan Host başlıkları `421` ile reddedilir.
- Varsayılan port doluysa sıradaki boş port otomatik seçilir.
- İstek logları varsayılan olarak sessiz (`--verbose` ile açılır); `--version` eklendi.
- Python 3.9 altı için anlaşılır hata mesajı.
- Çıktı yönlendirildiğinde Türkçe karakterlerin `UnicodeEncodeError` ile çökmesi düzeltildi.

### Arayüz
- Durum filtresi, ilerleme göstergesi, Markdown rapor dışa aktarma, ilerlemeyi sıfırlama.
- Senaryo seçimi URL hash'inde saklanır.
- Kaydedilmemiş notlar için kapatma onayı; `/` ve `Ctrl+Enter` kısayolları.
- Kayıtlara zaman damgası, notlu alarmlarda ✎ işareti, sekmeler arası senkron, canlı UTC saati.
- Grafik ölçeği artık veriden hesaplanıyor (önceden senaryo adına göre sabit kodluydu).
- Tablo alanlarının tamamı HTML-escape ediliyor; arama metni önceden hesaplanıyor.

### Proje
- Arayüz kaynakları `web/` altına ayrıldı; `tools/build.py` bunları `SOC_Lab.py`'ye gömer.
- Sunucu, build ve veri doğrulama testleri; GitHub Actions CI.

## 1.0.0
- İlk sürüm: tek dosyalık yerel SIEM simülatörü, 11 kategoride 55 sentetik alarm.
