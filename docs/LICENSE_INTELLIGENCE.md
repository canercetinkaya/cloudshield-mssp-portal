# CloudShield Lisans Zekâsı ve Güvenlik Değer Gerçekleştirme Modülü
# (License Intelligence & Security Value Realization)

**Sürüm:** 3.2.0  
**Tarih:** 2026-10-09  
**Platform:** CloudShield Security Reporting & Managed Services Visibility Platform  

---

## 1. Modülün Amacı ve Kapsamı

Lisans Zekâsı ve Güvenlik Değer Gerçekleştirme Modülü, bir Microsoft 365 kiracısında yalnızca satın alınan lisans adetlerini sayan geleneksel envanter araçlarından köklü biçimde ayrışır.

Temel hedef: **Satın alınan kurumsal güvenlik ve uyumluluk lisans yatırımlarının, organizasyon genelinde gerçekten operasyonel güvenlik değeri üretip üretmediğini 5 teknik katmanda kanıtlamaktır.**

Modül, spekülatif veya doğrulanmamış "tahmini dolar/TL kazancı" ya da yapay "ROI" iddiaları üretmez. Bunun yerine doğrudan teknik hak sahipliği, kullanıcı atama hijyeni, servis planı etkinliği, güvenlik ilkesi kapsamı ve canlı telemetri kanıtlarını raporlar (**Zero Fake Financial ROI Prensibi**).

---

## 2. 5 Katmanlı Değer Gerçekleştirme Mimarisi

Modül, tenant'taki 15 güvenlik ve uyumluluk iş yükünü 5 ardışık katmanda denetler:

```
[1. Hak Sahipliği (Entitlement)]
       │  (Satın alınmış geçerli SKU havuzu)
       ▼
[2. Kullanıcı Ataması (Assignment)]
       │  (Kullanıcılara doğrudan veya grup bazlı atanmış koltuklar)
       ▼
[3. Servis Planı Etkinliği (Service Plan Active)]
       │  (SKU içindeki teknik yeteneğin provizyon ve etkin durumu)
       ▼
[4. Konfigürasyon ve İlke Kapsamı (Configuration & Policy Coverage)]
       │  (Güvenlik ilkelerinin kullanıcıyı/cihazı hedeflemesi)
       ▼
[5. Gerçek Telemetri ve Kanıt (Evidence & Telemetry)]
          (Canlı olaylar, telemetri sinyalleri, denetim kayıtları)
```

Bu 5 katmandan herhangi birinde bir kopukluk olduğunda, modül durumu 14 kanonik statüden biriyle sınıflandırır ve operasyonel aksiyonu belirler.

---

## 3. Temel Analiz Yetenekleri

1. **Persona Bazlı Lisanslama Sınıflandırması:**
   - *Executive (C-Level, Yönetim Kurulu):* Gelişmiş XDR ve Defender Plan 2 gereksinimi.
   - *Sec / IT Admin:* Entra ID P2, PIM ve güçlü kimlik koruması.
   - *Finance / Sensitive Data:* Otomatik etiketleme, EDM ve Purview E5 Compliance.
   - *HR / PII:* KVKK/GDPR kişisel veri koruma ve DLP kapsamı.
   - *Dev / DevOps, Frontline, Guest, Service Account, Inactive User.*

2. **Mükerrer ve Çakışan Lisans Denetimi (Duplicate/Overlapping Entitlements):**
   - E5 ve E3 paketlerinin aynı kullanıcıya atanması (E5, E3'ü kapsar; E3 atıldır).
   - E5 paketine sahip kullanıcıya bağımsız E5 Security veya E5 Compliance add-on verilmesi.
   - Business Premium ve Business Standard lisanslarının üst üste atanması.
   - Office 365 E3 ile Microsoft 365 E3 çakışmaları.

3. **Eklenti (Add-on) Ön Koşul Doğrulaması:**
   - Microsoft 365 E5 Security, E5 Compliance veya Copilot eklentilerinin geçerli bir temel plan (Base SKU) olmaksızın atanıp atanmadığını denetler.

4. **Atıl ve Boşta Kalan Lisans Optimizasyonu:**
   - Satın alınmış ancak kullanıcılara atanmamış boşta lisansları tespit eder.

5. **Pasif / Ayrılmış Kullanıcı Lisans Riski:**
   - `accountEnabled = False` olan hesaplar üzerinde asılı kalmış lisansları tespit ederek geri kazanım (License Reclaim) sağlar.

6. **KOBİ 300 Koltuk Tavanı Denetimi:**
   - Business Basic, Standard ve Premium toplam tüketiminin 300 kullanıcı sınırını aşıp aşmadığını denetler.

7. **Azure Tüketim Modeli Ayrımı:**
   - Defender for Servers, Containers, Storage, SQL ve CSPM planlarını kullanıcı lisansı gerektirmeyen ayrı bulut kaynak tüketim modeli olarak raporlar.

---

## 4. Güvenlik ve Gizlilik Prensipleri

- **Salt-Okunur Erişim (Zero Write Impact):** Modül kesinlikle Microsoft 365 üzerinde lisans atama, lisans silme veya ilke değiştirme işlemi yapmaz. Yalnızca `Organization.Read.All` ve `User.Read.All` yetkilerini kullanır.
- **k-Anonymity & Maskeleme:** Rapora yansıyan kullanıcı e-posta ve kimlikleri gizlilik ilkelerine göre korunur.
- **Tenant İzolasyonu:** RBAC mimarisiyle her müşteri yalnızca kendi lisans verilerini görebilir.
