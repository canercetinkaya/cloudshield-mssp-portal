# Katkıda Bulunma Kılavuzu (CONTRIBUTING.md)
## CloudShield Security Reporting & Managed Services Visibility Platform

CloudShield projesine katkıda bulunmak istediğiniz için teşekkür ederiz. Bu belge, platform geliştirme standartlarını, kod kalitesi kurallarını ve çekme isteği (Pull Request) süreçlerini açıklar.

---

### 1. Temel Mühendislik İlkeleri

1. **Kod Gerçeğin Tek Kaynağıdır:** Dokümantasyon, şablonlar ve testler yalnızca kodda gerçekten çalışan kabiliyetleri anlatmalıdır. Uygulanmamış hiçbir özellik "tamamlandı" olarak iddia edilemez.
2. **Sıfır Dış Bağımlılık (Standard Library First):** Backend REST API sunucusu (`Portal/api/server.py`) ve yetkilendirme motoru saf Python 3 Standart Kütüphanesi (`urllib`, `http.server`, `sqlite3`, `hashlib`, `secrets`) ile çalışır. Zorunlu olmadıkça harici paket eklenmemelidir.
3. **Sıfır Sentetik Çarpan & Veri Dürüstlüğü:** Kodda veya şablonlarda alarm sayılarını artıran katsayılar veya tahminî müşteri oranları kullanılamaz. Eksik veri açıkça `N/A` olarak sunulmalıdır.
4. **Sıfır Bilet / Sıfır CR:** Mimaride Change Request, Ticket, ServiceNow, Jira veya manuel mühendis saati kavramları bulunmaz. Tüm iyileştirmeler doğrudan tenant telemetrisi ve denetim kütüklerinden türetilmelidir.

---

### 2. Zorunlu Test ve Kalite Kapıları

Herhangi bir Pull Request göndermeden önce yerel ortamınızda aşağıdaki testlerin hatasız geçtiğini doğrulamanız zorunludur:

```bash
# 1. Python Sözdizimi Kontrolü
python -m py_compile Portal/api/server.py Portal/api/report_generator.py Portal/api/rbac_engine.py Portal/api/rbac_handlers.py database/db.py

# 2. Birim ve Güvenlik Testleri (92 Test)
python -m unittest discover tests

# 3. Kapsamlı Platform QA Test Paketi (60 Test)
python tests/test_comprehensive_qa.py

# 4. Kolektör - Rapor Mutabakat Testi (9 Test)
python -m unittest tests/test_collector_to_report_reconciliation.py
```

---

### 3. Dal (Branch) ve Commit Standartları

- **Dal Adlandırma:** `feat/ozellik-adi`, `fix/duzeltme-adi`, `docs/dokuman-adi`
- **Commit Mesajları:** Conventional Commits standardı (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`)
- **Doğrudan Main'e Push:** `main` dalına doğrudan push korumalıdır; değişiklikler Pull Request üzerinden doğrulanarak aktarılmalıdır.
- **Hassas Veri / Secret:** Commit'lere kesinlikle `.env`, yerel veritabanı, API anahtarı veya gerçek müşteri bilgisi dahil edilmemelidir (`.gitignore` kurallarına uyunuz).
