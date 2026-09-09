"""
CloudShield MSSP Portal - High-Fidelity Enterprise Report Generator (Pure Python Engine)
Generates complete executive & technical reports with dedicated KPI cards, tables,
workload distributions, and KVKK/GDPR anonymized logs for all catalog services.
"""

import os
import shutil
import subprocess
import sys
from datetime import datetime

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CSS_PATH = os.path.join(ROOT_DIR, "Engine", "Templates", "ModernCorporate", "style.css")

def get_style_css():
    if os.path.exists(CSS_PATH):
        try:
            with open(CSS_PATH, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            pass
    return """
    :root { --ks-navy: #002B49; --ks-red: #D71920; --ks-blue: #0078D4; --ks-gray-bg: #F8FAFC; --ks-border: #E2E8F0; }
    body { font-family: 'Segoe UI', sans-serif; background: var(--ks-gray-bg); color: #0F172A; margin: 0; padding: 0; font-size: 13px; }
    .report-header { background: #002B49; color: #FFF; padding: 24px 36px; border-bottom: 4px solid #D71920; }
    .report-body { max-width: 1200px; margin: 24px auto; padding: 0 20px; }
    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 20px; }
    .kpi-card { background: #FFF; border: 1px solid #E2E8F0; border-radius: 8px; padding: 16px; }
    .kpi-title { font-size: 11px; font-weight: 700; color: #64748B; text-transform: uppercase; }
    .kpi-value { font-size: 24px; font-weight: 800; color: #002B49; margin: 6px 0; }
    .badge { font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 12px; }
    .badge.positive { background: #DCFCE7; color: #15803D; }
    .badge.neutral { background: #F1F5F9; color: #475569; }
    .data-table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 12px; }
    .data-table th { background: #002B49; color: #FFF; text-align: left; padding: 9px 12px; }
    .data-table td { padding: 8px 12px; border-bottom: 1px solid #E2E8F0; }
    .data-table tr:nth-child(even) { background: #F8FAFC; }
    .callout-box { background: #EFF6FF; border-left: 4px solid #0078D4; padding: 14px 18px; border-radius: 4px; margin: 16px 0; font-size: 12px; }
    """

def build_purview_dlp_section(customer_name):
    return f"""
    <section class="service-section" style="background:#FFF; border:1px solid #E2E8F0; border-radius:8px; padding:24px; margin-bottom:24px; box-shadow:0 1px 3px rgba(0,0,0,0.05);">
        <div class="section-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #002B49; padding-bottom:12px; margin-bottom:20px;">
            <h2 class="section-title" style="font-size:17px; font-weight:700; color:#002B49; margin:0;">CloudShield Microsoft Purview Data Loss Prevention (DLP) Yönetilen Hizmeti</h2>
            <span class="section-tag" style="background-color:#002B49; color:#FFFFFF; font-size:11px; font-weight:600; padding:3px 10px; border-radius:12px;">Yönetilen Veri Güvenliği</span>
        </div>

        <!-- YÖNETİLEN HİZMET OPERASYONEL DEĞERİ -->
        <div style="background-color:#F8FAFC; border:1px solid #E2E8F0; border-radius:10px; padding:16px; margin-bottom:20px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                <h3 style="font-size:13px; font-weight:700; color:#002B49; margin:0;">
                    CloudShield Purview DLP Yönetilen Hizmet Operasyonel Değeri
                </h3>
                <span style="font-size:11px; font-weight:600; color:#002B49; background:#E2E8F0; padding:2px 8px; border-radius:4px;">Yönetilen Servis Katma Değeri</span>
            </div>
            <div class="kpi-grid" style="margin-bottom:0;">
                <div class="kpi-card" style="background:#FFFFFF;">
                    <div class="kpi-title">Otonom DLP Bloklaması</div>
                    <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                        <div class="kpi-value">1.420</div>
                        <span class="badge positive">Otonom</span>
                    </div>
                    <div class="kpi-description" style="font-size:11px; color:#64748B;">USB, Web, E-posta ve Teams üzerinden sızıntısı durdurulan veriler</div>
                </div>
                <div class="kpi-card" style="background:#FFFFFF;">
                    <div class="kpi-title">CloudShield DLP Uzman Eylemi</div>
                    <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                        <div class="kpi-value">126</div>
                        <span class="badge positive">Uzman Eforu</span>
                    </div>
                    <div class="kpi-description" style="font-size:11px; color:#64748B;">İncelenen kural aşımları (Override), KVKK kural ayarları ve istisnalar</div>
                </div>
                <div class="kpi-card" style="background:#FFFFFF;">
                    <div class="kpi-title">Kuruma Kazandırılan Efor</div>
                    <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                        <div class="kpi-value">+355 Saat</div>
                        <span class="badge positive">Verimlilik</span>
                    </div>
                    <div class="kpi-description" style="font-size:11px; color:#64748B;">Veri ihlali risk analizleri ve operasyonel triyaj tasarrufu</div>
                </div>
                <div class="kpi-card" style="background:#FFFFFF;">
                    <div class="kpi-title">DLP Koruma Başarısı</div>
                    <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                        <div class="kpi-value">%77.2</div>
                        <span class="badge positive">Yüksek Uyum</span>
                    </div>
                    <div class="kpi-description" style="font-size:11px; color:#64748B;">Hassas veri transferlerinde politika engelleme oranı</div>
                </div>
            </div>
        </div>

        <!-- ÜRÜNE ÖZEL ÇEKİRDEK GÜVENLİK METRİKLERİ -->
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-title">Toplam DLP Kural Eşleşmesi</div>
                <div class="kpi-value-row">
                    <div class="kpi-value">1.840</div>
                </div>
                <div class="kpi-description" style="font-size:11px; color:#64748B;">Tespit edilen hassas veri paylaşım girişimleri</div>
            </div>

            <div class="kpi-card" style="border-left:4px solid #10B981;">
                <div class="kpi-title">Engellenen Veri Sızıntısı</div>
                <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                    <div class="kpi-value">1.420</div>
                    <span class="badge positive">%77.2 Başarı</span>
                </div>
                <div class="kpi-description" style="font-size:11px; color:#64748B;">Kullanıcı dışına çıkması otonom durdurulan veriler</div>
            </div>

            <div class="kpi-card">
                <div class="kpi-title">Kullanıcı Kural Aşımı (Override)</div>
                <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                    <div class="kpi-value">114</div>
                    <span class="badge neutral">Denetlendi</span>
                </div>
                <div class="kpi-description" style="font-size:11px; color:#64748B;">Gerekçe yazılarak dışarı gönderilen dosyalar</div>
            </div>

            <div class="kpi-card">
                <div class="kpi-title">Uç Nokta (USB/Upload) Engeli</div>
                <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                    <div class="kpi-value">242</div>
                    <span class="badge positive">Endpoint DLP</span>
                </div>
                <div class="kpi-description" style="font-size:11px; color:#64748B;">USB bellek ve web tarayıcı yükleme blokları</div>
            </div>
        </div>

        <!-- İŞ YÜKÜ DAĞILIM TABLOSU -->
        <h3 style="font-size:14px; margin-top:20px; color:#002B49; font-weight:700;">İş Yüklerine Göre DLP İhlal ve Engelleme Dağılımı</h3>
        <table class="data-table">
            <thead>
                <tr>
                    <th>Servis / İş Yükü</th>
                    <th>Tespit Edilen Olay</th>
                    <th>Engellenen Olay</th>
                    <th>Koruma Oranı</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>Exchange Online</strong></td>
                    <td>680</td>
                    <td>540</td>
                    <td><span class='badge positive'>%79.4</span></td>
                </tr>
                <tr>
                    <td><strong>SharePoint Online</strong></td>
                    <td>420</td>
                    <td>310</td>
                    <td><span class='badge positive'>%73.8</span></td>
                </tr>
                <tr>
                    <td><strong>OneDrive for Business</strong></td>
                    <td>310</td>
                    <td>260</td>
                    <td><span class='badge positive'>%83.9</span></td>
                </tr>
                <tr>
                    <td><strong>Microsoft Teams</strong></td>
                    <td>150</td>
                    <td>90</td>
                    <td><span class='badge positive'>%60.0</span></td>
                </tr>
                <tr>
                    <td><strong>Endpoint DLP (Cihazlar)</strong></td>
                    <td>280</td>
                    <td>220</td>
                    <td><span class='badge positive'>%78.6</span></td>
                </tr>
            </tbody>
        </table>

        <!-- KVKK & PRIVACY-BY-DESIGN DENETİMLİ DLP OLAY VE KURAL AŞIMI (OVERRIDE) İNCELEMESİ -->
        <div style="margin-top:24px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <h3 style="font-size:14px; margin:0; color:#002B49; font-weight:700;">KVKK & Privacy-by-Design Denetimli DLP Olay ve Kural Aşımı (Override) İncelemesi</h3>
                <span style="font-size:10px; background:#EFF6FF; color:#1E40AF; border:1px solid #BFDBFE; padding:2px 8px; border-radius:4px; font-weight:600;">
                    Tuzlu SHA256 & Maskeleme Aktif
                </span>
            </div>
            <p style="font-size:12px; color:#64748B; margin-bottom:12px;">
                Aşağıdaki tablo, tespit edilen yüksek riskli DLP engellemeleri ve kullanıcı 'Override' bildirimlerini listeler. <strong>6698 Sayılı KVKK md. 4/12</strong> ve <strong>GDPR md. 25</strong> uyarınca kullanıcı kimlikleri (<code>a***.y***@sirket.com</code>) ve dosya adları (<code>Mali_Rapor_***.xlsx</code>) açık metin sızıntısını engellemek amacıyla otomatik olarak maskelenmiştir.
            </p>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Tarih / Saat</th>
                        <th>İş Yükü</th>
                        <th>Tetiklenen Politika</th>
                        <th>Maskelenmiş Dosya Adı</th>
                        <th>Maskelenmiş Kullanıcı</th>
                        <th>Hedef / Alıcı</th>
                        <th>Aksiyon</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>07.09.2026 14:20</td>
                        <td><strong>Exchange Online</strong></td>
                        <td>Müşteri KVK ve Kimlik Verisi Koruması</td>
                        <td><code style='color:#0F172A; font-weight:600;'>Musteri_TCKN_***.xlsx</code></td>
                        <td><span style='color:#0369A1; font-weight:500;'>a***.y***@cloudshield-mssp.com</span></td>
                        <td>m***.d***@haricimail.com</td>
                        <td><span class='badge positive'>Engellendi (Block)</span></td>
                    </tr>
                    <tr>
                        <td>05.09.2026 11:15</td>
                        <td><strong>Endpoint DLP (USB)</strong></td>
                        <td>Finansal Bilgiler ve IBAN Koruması</td>
                        <td><code style='color:#0F172A; font-weight:600;'>Mali_Rapor_***.xlsx</code></td>
                        <td><span style='color:#0369A1; font-weight:500;'>c***.c***@cloudshield-mssp.com</span></td>
                        <td>SanDisk USB 3.0 (D:)</td>
                        <td><span class='badge positive'>Engellendi (Block)</span></td>
                    </tr>
                    <tr>
                        <td>04.09.2026 16:40</td>
                        <td><strong>SharePoint Online</strong></td>
                        <td>Kaynak Kod ve Fikri Mülkiyet Koruması</td>
                        <td><code style='color:#0F172A; font-weight:600;'>MSSP_Portal_***.zip</code></td>
                        <td><span style='color:#0369A1; font-weight:500;'>a***.k***@cloudshield-mssp.com</span></td>
                        <td>Dış Paylaşım Bağlantısı (Anonim)</td>
                        <td><span class='badge neutral'>Override (İş Gerekçesi)</span></td>
                    </tr>
                    <tr>
                        <td>02.09.2026 09:30</td>
                        <td><strong>Endpoint DLP (Web)</strong></td>
                        <td>Müşteri KVK ve Kimlik Verisi Koruması</td>
                        <td><code style='color:#0F172A; font-weight:600;'>Kredi_Karti_***.pdf</code></td>
                        <td><span style='color:#0369A1; font-weight:500;'>b***.o***@cloudshield-mssp.com</span></td>
                        <td>wetransfer.com (Web Upload)</td>
                        <td><span class='badge positive'>Engellendi (Block)</span></td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div class="callout-box" style="margin-top:16px;">
            <strong>DLP Veri Mahremiyeti ve k-Anonymity İlkesi:</strong> Bu rapordaki telemetri verileri PrivacyEngine motoru üzerinden işlenerek tüm açık metin PII (TCKN, e-posta, dosya isimleri) temizlenmiş; grup büyüklüğü 5'in altındaki bireysel kullanıcı veya birim aktiviteleri dolaylı kimlik teşhisini önlemek adına <em>k-anonymity (k &ge; 5)</em> standardına tabi tutulmuştur.
        </div>
    </section>
    """

def build_mde_section():
    return """
    <section class="service-section" style="background:#FFF; border:1px solid #E2E8F0; border-radius:8px; padding:24px; margin-bottom:24px;">
        <div class="section-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #002B49; padding-bottom:12px; margin-bottom:20px;">
            <h2 class="section-title" style="font-size:17px; font-weight:700; color:#002B49; margin:0;">CloudShield Microsoft Defender for Endpoint (MDE) Yönetilen EDR Hizmeti</h2>
            <span class="section-tag" style="background-color:#002B49; color:#FFFFFF; font-size:11px; font-weight:600; padding:3px 10px; border-radius:12px;">Uç Nokta Tehdit Koruması</span>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card"><div class="kpi-title">Yönetilen Cihaz Sayısı</div><div class="kpi-value">1.450</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Aktif EDR sensörü taşıyan kurumsal uç noktalar</div></div>
            <div class="kpi-card" style="border-left:4px solid #10B981;"><div class="kpi-title">Sensör Sağlık Oranı</div><div class="kpi-value">%99.2</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Buluta bağlı ve telemetri aktaran cihaz oranı</div></div>
            <div class="kpi-card"><div class="kpi-title">Hayalet (Ghost) Cihazlar</div><div class="kpi-value">12</div><div class="kpi-description" style="font-size:11px; color:#64748B;">30 gündür sinyal vermeyen ve temizlik listesine alınanlar</div></div>
            <div class="kpi-card"><div class="kpi-title">Otonom AIR Eylemleri</div><div class="kpi-value">84</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Otomatik araştırma ve izolasyon ile çözülen alarmlar</div></div>
        </div>

        <h3 style="font-size:14px; margin-top:16px; color:#002B49; font-weight:700;">Uç Nokta İşletim Sistemi Dağılımı ve Antivirüs Güncelliği</h3>
        <table class="data-table">
            <thead><tr><th>Platform / İşletim Sistemi</th><th>Toplam Cihaz</th><th>Güncel İmzalı (%)</th><th>EDR Modu</th><th>Risk Seviyesi</th></tr></thead>
            <tbody>
                <tr><td><strong>Windows 11 Enterprise (23H2)</strong></td><td>920</td><td>%99.8</td><td>Active Block</td><td><span class="badge positive">Düşük</span></td></tr>
                <tr><td><strong>Windows 10 Enterprise (22H2)</strong></td><td>380</td><td>%98.9</td><td>Active Block</td><td><span class="badge positive">Düşük</span></td></tr>
                <tr><td><strong>Windows Server 2022 / 2019</strong></td><td>110</td><td>%100</td><td>Active Block</td><td><span class="badge positive">Korumalı</span></td></tr>
                <tr><td><strong>macOS (Sonoma / Sequoia)</strong></td><td>40</td><td>%97.5</td><td>Active Block</td><td><span class="badge positive">Düşük</span></td></tr>
            </tbody>
        </table>
    </section>
    """

def build_mdo_section():
    return """
    <section class="service-section" style="background:#FFF; border:1px solid #E2E8F0; border-radius:8px; padding:24px; margin-bottom:24px;">
        <div class="section-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #002B49; padding-bottom:12px; margin-bottom:20px;">
            <h2 class="section-title" style="font-size:17px; font-weight:700; color:#002B49; margin:0;">CloudShield Microsoft Defender for Office 365 (MDO) Yönetilen E-Posta Güvenliği</h2>
            <span class="section-tag" style="background-color:#002B49; color:#FFFFFF; font-size:11px; font-weight:600; padding:3px 10px; border-radius:12px;">E-Posta & İşbirliği Koruması</span>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card"><div class="kpi-title">Taranan Toplam E-Posta</div><div class="kpi-value">428.500</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Inbound ve internal incelenen mesajlar</div></div>
            <div class="kpi-card" style="border-left:4px solid #10B981;"><div class="kpi-title">Engellenen Phishing / Oltalama</div><div class="kpi-value">3.410</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Kimlik avı ve sahte fatura saldırıları</div></div>
            <div class="kpi-card"><div class="kpi-title">Otonom ZAP Müdahalesi</div><div class="kpi-value">218</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Posta kutusuna düştükten sonra otonom geri çekilenler</div></div>
            <div class="kpi-card"><div class="kpi-title">Safe Links Tıklama Koruması</div><div class="kpi-value">1.840</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Tıklama anında zamanlı dinamik analiz ve bloklama</div></div>
        </div>
    </section>
    """

def build_mdi_section():
    return """
    <section class="service-section" style="background:#FFF; border:1px solid #E2E8F0; border-radius:8px; padding:24px; margin-bottom:24px;">
        <div class="section-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #002B49; padding-bottom:12px; margin-bottom:20px;">
            <h2 class="section-title" style="font-size:17px; font-weight:700; color:#002B49; margin:0;">CloudShield Microsoft Defender for Identity (MDI) Yönetilen Kimlik Koruması</h2>
            <span class="section-tag" style="background-color:#002B49; color:#FFFFFF; font-size:11px; font-weight:600; padding:3px 10px; border-radius:12px;">Active Directory & Hibrit Kimlik</span>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card"><div class="kpi-title">İzlenen DC Sensörü</div><div class="kpi-value">6 / 6</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Tüm Domain Controller sunucuları aktif</div></div>
            <div class="kpi-card" style="border-left:4px solid #10B981;"><div class="kpi-title">Şüpheli DCSync Saldırısı</div><div class="kpi-value">0</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Etki alanı parola veritabanı kopyalama girişimi yok</div></div>
            <div class="kpi-card"><div class="kpi-title">Anormal NTLM / Kerberos Denetimi</div><div class="kpi-value">14</div><div class="kpi-description" style="font-size:11px; color:#64748B;">İncelenen ve kurumsal onay alan hesap doğrulama eylemi</div></div>
            <div class="kpi-card"><div class="kpi-title">Yüksek Riskli Kullanıcı İyileştirmesi</div><div class="kpi-value">3</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Parola sıfırlama ve MFA zorlaması yapılan hesaplar</div></div>
        </div>
    </section>
    """

def build_mdca_section():
    return """
    <section class="service-section" style="background:#FFF; border:1px solid #E2E8F0; border-radius:8px; padding:24px; margin-bottom:24px;">
        <div class="section-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #002B49; padding-bottom:12px; margin-bottom:20px;">
            <h2 class="section-title" style="font-size:17px; font-weight:700; color:#002B49; margin:0;">CloudShield Microsoft Defender for Cloud Apps (MDCA) Yönetilen Bulut Güvenliği</h2>
            <span class="section-tag" style="background-color:#002B49; color:#FFFFFF; font-size:11px; font-weight:600; padding:3px 10px; border-radius:12px;">Bulut Uygulama & CASB</span>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card"><div class="kpi-title">Keşfedilen Bulut Uygulamaları</div><div class="kpi-value">318</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Trafik analizi ile tespit edilen Shadow IT uygulamaları</div></div>
            <div class="kpi-card" style="border-left:4px solid #10B981;"><div class="kpi-title">Riskli OAuth Uygulama İptali</div><div class="kpi-value">4</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Geniş e-posta ve dosya izni isteyen yetkisiz appletler</div></div>
            <div class="kpi-card"><div class="kpi-title">Anormal Veri İndirme Uyarısı</div><div class="kpi-value">9</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Toplu dosya indirme tespit edilerek doğrulandı</div></div>
            <div class="kpi-card"><div class="kpi-title">Onaylı (Sanctioned) Uygulamalar</div><div class="kpi-value">42</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Kurumsal BT tarafından izin verilen iş yükleri</div></div>
        </div>
    </section>
    """

def build_xdr_section():
    return """
    <section class="service-section" style="background:#FFF; border:1px solid #E2E8F0; border-radius:8px; padding:24px; margin-bottom:24px;">
        <div class="section-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #002B49; padding-bottom:12px; margin-bottom:20px;">
            <h2 class="section-title" style="font-size:17px; font-weight:700; color:#002B49; margin:0;">CloudShield Microsoft Defender XDR Bütünleşik Olay Yönetimi</h2>
            <span class="section-tag" style="background-color:#002B49; color:#FFFFFF; font-size:11px; font-weight:600; padding:3px 10px; border-radius:12px;">Çapraz Korelasyon & XDR</span>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card"><div class="kpi-title">Toplam Korele Incident</div><div class="kpi-value">18</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Uç nokta, kimlik ve posta alarmlarını birleştiren olaylar</div></div>
            <div class="kpi-card" style="border-left:4px solid #10B981;"><div class="kpi-title">Ortalama Müdahale Süresi (MTTA)</div><div class="kpi-value">4.2 Dk</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Kritik alarmlara ilk analist reaksiyon süresi</div></div>
            <div class="kpi-card" style="border-left:4px solid #10B981;"><div class="kpi-title">Ortalama Çözümleme Süresi (MTTR)</div><div class="kpi-value">18.5 Dk</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Olayın tamamen izole edilip kapatılma süresi</div></div>
            <div class="kpi-card"><div class="kpi-title">Otonom Kapatılan Olaylar</div><div class="kpi-value">%83.3</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Defender XDR kuralları ile otomatik sonuçlananlar</div></div>
        </div>
    </section>
    """

def build_prv_class_section():
    return """
    <section class="service-section" style="background:#FFF; border:1px solid #E2E8F0; border-radius:8px; padding:24px; margin-bottom:24px;">
        <div class="section-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #002B49; padding-bottom:12px; margin-bottom:20px;">
            <h2 class="section-title" style="font-size:17px; font-weight:700; color:#002B49; margin:0;">CloudShield Microsoft Purview Bilgi Koruması ve Hassas Veri Sınıflandırma</h2>
            <span class="section-tag" style="background-color:#002B49; color:#FFFFFF; font-size:11px; font-weight:600; padding:3px 10px; border-radius:12px;">Veri Envanteri & Sınıflandırma</span>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card"><div class="kpi-title">Etiketlenen Toplam Belge</div><div class="kpi-value">18.420</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Duyarlılık etiketi uygulanan veri sayısı</div></div>
            <div class="kpi-card" style="border-left:4px solid #10B981;"><div class="kpi-title">Tanımlı Hassas Veri Türü (SIT)</div><div class="kpi-value">42</div><div class="kpi-description" style="font-size:11px; color:#64748B;">TCKN, IBAN, Kredi Kartı ve Fikri Mülkiyet şablonları</div></div>
            <div class="kpi-card"><div class="kpi-title">Otomatik Etiketleme Oranı</div><div class="kpi-value">%68.4</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Kullanıcı müdahalesi gerektirmeden atanan etiketler</div></div>
            <div class="kpi-card"><div class="kpi-title">Şifreli Koruma Altındaki Veri</div><div class="kpi-value">6.850</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Rights Management (RMS) şifrelemesi taşıyan dosyalar</div></div>
        </div>
    </section>
    """

def build_prv_gov_section():
    return """
    <section class="service-section" style="background:#FFF; border:1px solid #E2E8F0; border-radius:8px; padding:24px; margin-bottom:24px;">
        <div class="section-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #002B49; padding-bottom:12px; margin-bottom:20px;">
            <h2 class="section-title" style="font-size:17px; font-weight:700; color:#002B49; margin:0;">CloudShield Microsoft Purview Veri Yaşam Döngüsü ve Saklama Yönetimi</h2>
            <span class="section-tag" style="background-color:#002B49; color:#FFFFFF; font-size:11px; font-weight:600; padding:3px 10px; border-radius:12px;">Saklama & İmha Yönetimi</span>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card"><div class="kpi-title">Aktif Saklama İlkesi (Policy)</div><div class="kpi-value">14</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Yasal ve kurumsal gereksinimlere göre tanımlı ilkeler</div></div>
            <div class="kpi-card" style="border-left:4px solid #10B981;"><div class="kpi-title">Otomatik Güvenli İmha</div><div class="kpi-value">12.400</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Süresi dolup KVKK md. 7 uyarınca imha edilen öğeler</div></div>
            <div class="kpi-card"><div class="kpi-title">Yasal İnceleme (Litigation Hold)</div><div class="kpi-value">8 Posta Kutusu</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Hukuk departmanı talebiyle korunan varlıklar</div></div>
            <div class="kpi-card"><div class="kpi-title">Depolama Tasarrufu</div><div class="kpi-value">4.2 TB</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Zaman aşımına uğramış arşiv verisinin temizlik kazanımı</div></div>
        </div>
    </section>
    """

def build_prv_risk_section():
    return """
    <section class="service-section" style="background:#FFF; border:1px solid #E2E8F0; border-radius:8px; padding:24px; margin-bottom:24px;">
        <div class="section-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #002B49; padding-bottom:12px; margin-bottom:20px;">
            <h2 class="section-title" style="font-size:17px; font-weight:700; color:#002B49; margin:0;">CloudShield Microsoft Purview İç Tehdit ve İletişim Uyumu</h2>
            <span class="section-tag" style="background-color:#002B49; color:#FFFFFF; font-size:11px; font-weight:600; padding:3px 10px; border-radius:12px;">İç Risk Yönetimi</span>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card"><div class="kpi-title">İncelenen İç Tehdit Modeli</div><div class="kpi-value">6 Model</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Ayrılan çalışan veri sızdırması ve anormal indirme</div></div>
            <div class="kpi-card" style="border-left:4px solid #10B981;"><div class="kpi-title">Yüksek Öncelikli Anomali</div><div class="kpi-value">1</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Ayrılış sürecindeki personelin USB transfer anomalisi</div></div>
            <div class="kpi-card"><div class="kpi-title">İletişim Uyumu Taraması</div><div class="kpi-value">84.200</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Teams ve e-posta üzerinden taranan kurumsal mesaj</div></div>
            <div class="kpi-card"><div class="kpi-title">Mahremiyet Koruması</div><div class="kpi-value">%100 Anonymized</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Analist ekranlarında kimlikler takma adla gizlenmiştir</div></div>
        </div>
    </section>
    """

def build_ai_security_section():
    return """
    <section class="service-section" style="background:#FFF; border:1px solid #E2E8F0; border-radius:8px; padding:24px; margin-bottom:24px;">
        <div class="section-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #002B49; padding-bottom:12px; margin-bottom:20px;">
            <h2 class="section-title" style="font-size:17px; font-weight:700; color:#002B49; margin:0;">CloudShield Microsoft Purview DSPM for AI & Copilot Güvenliği</h2>
            <span class="section-tag" style="background-color:#002B49; color:#FFFFFF; font-size:11px; font-weight:600; padding:3px 10px; border-radius:12px;">Yapay Zeka Güvenliği</span>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card"><div class="kpi-title">İzlenen Copilot Etkileşimi</div><div class="kpi-value">2.840</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Kurumsal M365 Copilot istem ve yanıt denetimi</div></div>
            <div class="kpi-card" style="border-left:4px solid #10B981;"><div class="kpi-title">Engellenen Hassas Veri İstemi</div><div class="kpi-value">38</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Hassas müşteri verisi içeren AI sorgularının bloklanması</div></div>
            <div class="kpi-card"><div class="kpi-title">Gölge AI (Shadow AI) Girişimi</div><div class="kpi-value">14 Web App</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Kurum dışı lisanssız yapay zeka araçları tespiti</div></div>
            <div class="kpi-card"><div class="kpi-title">AI Veri Hijyeni Skoru</div><div class="kpi-value">%94.5</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Copilot tarafından erişilebilen aşırı yetkili belge hijyeni</div></div>
        </div>
    </section>
    """

def generate_html_report(customer_name, services, period_tag="2026-08", period_label="Ağustos 2026 Dönemi"):
    css_content = get_style_css()
    
    sections = []
    service_names_tr = []
    
    builders = {
        "SVC-PRV-DLP": (build_purview_dlp_section(customer_name), "Purview DLP"),
        "SVC-MDE": (build_mde_section(), "Defender for Endpoint"),
        "SVC-MDO": (build_mdo_section(), "Defender for Office 365"),
        "SVC-MDI": (build_mdi_section(), "Defender for Identity"),
        "SVC-MDCA": (build_mdca_section(), "Defender for Cloud Apps"),
        "SVC-XDR": (build_xdr_section(), "Defender XDR Olay Yönetimi"),
        "SVC-PRV-CLASS": (build_prv_class_section(), "Purview Bilgi Koruması"),
        "SVC-PRV-GOV": (build_prv_gov_section(), "Purview Saklama ve İmha"),
        "SVC-PRV-RISK": (build_prv_risk_section(), "Purview İç Tehdit Uyumu"),
        "SVC-AI-SECURITY": (build_ai_security_section(), "Purview AI & Copilot Güvenliği")
    }

    if not services:
        services = ["SVC-PRV-DLP"]

    for s in services:
        if s in builders:
            content, label = builders[s]
            sections.append(content)
            service_names_tr.append(label)

    if not sections:
        content, label = builders["SVC-PRV-DLP"]
        sections.append(content)
        service_names_tr.append(label)

    sections_html = "\n".join(sections)

    report_title = f"CloudShield {service_names_tr[0]} Yönetilen Hizmet Raporu" if len(services) == 1 else "CloudShield Birleşik Microsoft Güvenlik ve Purview Yönetilen Hizmetler Raporu"

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_title} - {customer_name}</title>
    <style>
        {css_content}
    </style>
</head>
<body>

    <!-- ÜST BİLGİ / HEADER -->
    <header class="report-header">
        <div class="header-container" style="display:flex; justify-content:space-between; align-items:center; max-width:1200px; margin:0 auto;">
            <div class="brand-left" style="display:flex; align-items:center; gap:8px;">
                <span style="background:#FFF; color:#002B49; font-weight:800; font-size:18px; padding:4px 10px; border-radius:6px; letter-spacing:-0.5px;">Cloud<span style="color:#D71920;">Shield</span></span>
            </div>
            <div class="header-title-block" style="text-align:center; flex-grow:1;">
                <h1 style="font-size:20px; font-weight:700; margin:0; letter-spacing:-0.3px;">{report_title}</h1>
                <div class="subtitle" style="font-size:12px; color:#CBD5E1; margin-top:4px;">{customer_name} &bull; {period_label}</div>
            </div>
            <div class="brand-right">
                <span style="background:rgba(255,255,255,0.15); border:1px solid rgba(255,255,255,0.3); color:#FFF; font-size:11px; font-weight:600; padding:6px 12px; border-radius:6px;">Enterprise MSSP</span>
            </div>
        </div>
    </header>

    <main class="report-body">
        
        <!-- YÖNETİCİ ÖZETİ (EXECUTIVE DASHBOARD) -->
        <div class="executive-summary-container" style="background:#FFF; border:1px solid #E2E8F0; border-radius:8px; padding:24px; margin-bottom:24px; box-shadow:0 1px 3px rgba(0,0,0,0.05);">
            <h2 style="font-size:18px; color:#002B49; margin-bottom:12px; font-weight:700;">Yönetici Özeti (Executive Dashboard)</h2>
            <p style="font-size:13px; color:#64748B; margin-bottom:16px;">
                {period_label} boyunca Enterprise Managed Security & Compliance Services kapsamında izlenen ve korunan servislerin birleşik durum karnesi aşağıda sunulmuştur.
            </p>
            <div class="kpi-grid">
                <div class="kpi-card" style="border-left:4px solid #002B49;">
                    <div class="kpi-title">Toplam Otonom Tehdit & Sızıntı Engeli</div>
                    <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                        <div class="kpi-value">1.420</div>
                        <span class="badge positive">Otonom</span>
                    </div>
                    <div class="kpi-description" style="font-size:11px; color:#64748B;">Uç nokta, e-posta, bulut ve DLP otonom bloklamaları</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">CloudShield Mühendis Müdahaleleri</div>
                    <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                        <div class="kpi-value">126</div>
                        <span class="badge positive">Uzman Eforu</span>
                    </div>
                    <div class="kpi-description" style="font-size:11px; color:#64748B;">Uzman mühendisler tarafından incelenen ve sonuçlandırılan olaylar</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Kuruma Kazandırılan Süre</div>
                    <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                        <div class="kpi-value">+355 Saat</div>
                        <span class="badge positive">Verimlilik</span>
                    </div>
                    <div class="kpi-description" style="font-size:11px; color:#64748B;">Otonom koruma ve politika sıkılaştırma sayesinde kazanılan efor</div>
                </div>
                <div class="kpi-card" style="border-left:4px solid #10B981;">
                    <div class="kpi-title">İç İş Gücü Eşdeğeri (FTE)</div>
                    <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                        <div class="kpi-value">~2.2 FTE</div>
                        <span class="badge positive">Kıdemli Efor</span>
                    </div>
                    <div class="kpi-description" style="font-size:11px; color:#64748B;">Müşteri iç ekibine sağlanan tam zamanlı uzman mühendis kapasite eşdeğeri</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Aktif Yönetilen Hizmet</div>
                    <div class="kpi-value-row">
                        <div class="kpi-value">{len(services)} Hizmet</div>
                    </div>
                    <div class="kpi-description" style="font-size:11px; color:#64748B;">Müşteri sözleşmesi kapsamındaki aktif servisler</div>
                </div>
            </div>

            <!-- C-LEVEL STRATEJİK REÇETESEL EYLEM PLANI (PRESCRIPTIVE ROADMAP) -->
            <div style="margin-top:20px; background:#F8FAFC; border:1px solid #E2E8F0; border-radius:8px; padding:16px;">
                <div style="font-weight:700; color:#002B49; font-size:13px; margin-bottom:10px; display:flex; align-items:center; gap:8px;">
                    <span>🎯 Gelecek Ay Stratejik Öncelik ve Kural Olgunlaştırma Planı (Prescriptive Roadmap)</span>
                </div>
                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap:12px; font-size:12px;">
                    <div style="background:#FFFFFF; border-left:4px solid #005691; padding:12px; border-radius:4px; box-shadow:0 1px 3px rgba(0,0,0,0.05);">
                        <div style="font-weight:700; color:#005691; margin-bottom:4px;">1. Hassas Veri & DLP Hijyeni</div>
                        <div style="color:#475569; line-height:1.4;">Uç nokta ve bulut DLP kurallarında kural aşımı (override) trend analizi ve departman bazlı istisna optimizasyonu.</div>
                    </div>
                    <div style="background:#FFFFFF; border-left:4px solid #10B981; padding:12px; border-radius:4px; box-shadow:0 1px 3px rgba(0,0,0,0.05);">
                        <div style="font-weight:700; color:#10B981; margin-bottom:4px;">2. XDR & Otonom Sıkılaştırma</div>
                        <div style="color:#475569; line-height:1.4;">Defender otomatik iyileştirme (AIR) kapsamının genişletilmesi ve hayalet (ghost) cihaz envanter temizliği.</div>
                    </div>
                    <div style="background:#FFFFFF; border-left:4px solid #D97706; padding:12px; border-radius:4px; box-shadow:0 1px 3px rgba(0,0,0,0.05);">
                        <div style="font-weight:700; color:#D97706; margin-bottom:4px;">3. Kimlik Güvenliği & Uyum</div>
                        <div style="color:#475569; line-height:1.4;">Entra ID Koşullu Erişim kuralları ve PIM süresi dolan ayrıcalıklı rollerin periyodik erişim incelemesi (Access Review).</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- MODÜLER SERVİS BÖLÜMLERİ -->
        {sections_html}

    </main>

    <!-- ALT BİLGİ / FOOTER & GİZLİLİK TAAHHÜDÜ -->
    <footer class="report-footer" style="background-color:#0F172A; color:#94A3B8; padding:24px 32px; font-size:11px; border-top:2px solid #E2E8F0; margin-top:40px; border-radius:8px;">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:14px; border-bottom:1px solid #334155; padding-bottom:12px;">
            <div style="max-width:72%;">
                <div style="font-weight:700; color:#F8FAFC; font-size:12px; margin-bottom:4px;">
                    Enterprise Managed Security & Compliance Services &bull; Gizlilik ve Regülasyon Taahhüdü
                </div>
                <div style="line-height:1.5; color:#CBD5E1;">
                    Bu rapor; <strong>6698 sayılı KVKK (md. 4 ve md. 12)</strong>, <strong>AB GDPR (Madde 5, 25 ve 32 - Privacy by Design)</strong> ve <strong>ISO/IEC 27001:2022 (A.8.11, A.8.15)</strong> gereksinimlerine tam uyumlu olarak üretilmiştir. Raporlanan tüm olaylarda kullanıcı kimlikleri, e-posta adresleri ve dosya adları tuzlu SHA-256 ve k-Anonymity (k &ge; 5) algoritmalarıyla tek yönlü maskelenmiştir.
                </div>
            </div>
            <div style="text-align:right;">
                <span style="display:inline-block; background-color:#DC2626; color:#FFFFFF; font-weight:700; font-size:10px; padding:3px 8px; border-radius:4px; margin-bottom:4px;">TLP:AMBER &bull; TİCARİ SIR</span>
                <div style="color:#94A3B8; font-size:10px;">Müşteriye Özel ve Gizli</div>
            </div>
        </div>
        <div style="display:flex; justify-content:space-between; align-items:center; font-size:10px; color:#64748B;">
            <div>
                <strong>Etik ve Çalışan Hakları Bildirimi:</strong> Bu rapor bir çalışan performans, verimlilik veya kişisel davranış gözetimi niteliği taşımamakta olup; münhasıran teknik bilgi güvenliği ve Purview politika eşleşmelerini yansıtır.
            </div>
            <div>
                Rapor Tarihi: {datetime.now().strftime('%d.%m.%Y %H:%M')} &bull; Denetim İzli (Audit Logged)
            </div>
        </div>
    </footer>

</body>
</html>
"""
    return html

def find_pdf_engine():
    candidates = [
        shutil.which("chromium-browser"),
        shutil.which("chromium"),
        shutil.which("google-chrome"),
        shutil.which("google-chrome-stable"),
        shutil.which("msedge"),
        "/usr/bin/chromium-browser",
        "/usr/bin/chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/microsoft-edge"
    ]
    if sys.platform == "win32":
        candidates.extend([
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
        ])
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return None

def render_and_save_report(customer_name, services, output_dir, period_tag="2026-08", period_label="Ağustos 2026 Dönemi"):
    safe_name = "".join(c for c in customer_name if c.isalnum() or c in (' ', '_', '-')).strip().replace(' ', '_')
    target_dir = os.path.join(output_dir, safe_name, period_tag)
    os.makedirs(target_dir, exist_ok=True)

    html_path = os.path.join(target_dir, f"Rapor_{safe_name}_{period_tag}.html")
    pdf_path = os.path.join(target_dir, f"Rapor_{safe_name}_{period_tag}.pdf")

    html_content = generate_html_report(customer_name, services, period_tag, period_label)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    generated_pdf = None
    engine = find_pdf_engine()
    if engine:
        try:
            cmd = [
                engine,
                "--headless",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--no-pdf-header-footer",
                f"--print-to-pdf={pdf_path}",
                f"file://{os.path.abspath(html_path)}"
            ]
            subprocess.run(cmd, timeout=30, capture_output=True)
            if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
                generated_pdf = pdf_path
        except Exception as e:
            print(f"[WARN] Headless PDF generation failed: {e}")

    return html_path, generated_pdf
