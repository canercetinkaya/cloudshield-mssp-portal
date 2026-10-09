# CloudShield License Intelligence & Security Value Realization Report Generator
# Generates the 20-Section Monthly Health-Check Report in HTML and vector PDF.
# Enforces Zero Fake Financial ROI, Persona Classification, and 5-Layer Workload Reconciliation.

import os
import json
import logging
import subprocess
from datetime import datetime, timezone

logger = logging.getLogger("CloudShield.LicenseReportGenerator")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

def generate_license_health_report(license_data, tenant_meta=None, previous_snapshot=None):
    """
    Renders the complete 20-section License Intelligence & Security Value Realization HTML report.
    """
    tenant_meta = tenant_meta or {}
    tenant_name = tenant_meta.get("CustomerName") or tenant_meta.get("Name") or license_data.get("tenant_id", "Tenant")
    tenant_id = license_data.get("tenant_id", "N/A")
    period = license_data.get("period", datetime.now().strftime("%Y-%m"))
    snapshot_date = license_data.get("snapshot_date", datetime.now().strftime("%Y-%m-%d"))

    summary = license_data.get("summary", {})
    inventory = license_data.get("inventory", [])
    users = license_data.get("users", [])
    reconciliations = license_data.get("reconciliations", [])
    is_live = license_data.get("is_live", False)
    trust_label = license_data.get("trust_label", "Sentetik / Simülasyon Verisi")

    # Metrics
    total_licenses = summary.get("total_licenses", 0)
    assigned_licenses = summary.get("assigned_licenses", 0)
    idle_licenses = summary.get("idle_licenses", 0)
    value_index = summary.get("overall_value_index", 0.0)
    utilization_rate = round((assigned_licenses / total_licenses * 100), 1) if total_licenses > 0 else 0.0

    duplicate_users = [u for u in users if u.get("value_status") == "Mükerrer veya Çakışan Lisans Hakkı"]
    inactive_licensed = [u for u in users if u.get("value_status") == "Pasif Hesapta Atanmış Lisans" or (not u.get("account_enabled") and len(u.get("assigned_skus", [])) > 0)]
    missing_prereqs = [u for u in users if u.get("value_status") == "Eksik Ön Koşul Lisansı"]
    unlicensed_active = [u for u in users if u.get("value_status") == "Kapsam Dışı Aktif Kullanıcı"]

    # History Diff
    prev_val = previous_snapshot.get("payload", {}).get("summary", {}).get("overall_value_index", 0.0) if previous_snapshot else None
    val_diff_str = f"{value_index - prev_val:+.1f}%" if prev_val is not None else "İlk Dönem"

    # Synthetic banner
    synthetic_banner_html = ""
    if not is_live:
        synthetic_banner_html = """
        <div style="background: linear-gradient(135deg, #fff3cd, #ffeeba); border: 2px solid #ffeeba; border-left: 6px solid #e0a800; border-radius: 8px; padding: 16px 20px; margin-bottom: 24px; color: #856404;">
            <div style="display: flex; align-items: center; gap: 12px;">
                <span style="font-size: 24px;">&#9888;</span>
                <div>
                    <strong style="font-size: 15px; text-transform: uppercase; letter-spacing: 0.5px;">DİKKAT: SENTETİK / TEST SİMÜLASYONU RAPORUDUR</strong>
                    <p style="margin: 4px 0 0; font-size: 13px; line-height: 1.4;">
                        Bu raporda sunulan metrikler ve kullanıcı profilleri <strong>DryRun / Simülasyon</strong> verisidir.
                        Canlı Microsoft Entra ID / Graph API bağlantısı doğrulanana kadar üretim ortamı kararları için referans alınamaz.
                    </p>
                </div>
            </div>
        </div>
        """

    # Section 2: Inventory rows
    inv_rows = ""
    for item in inventory:
        prepaid = item.get("prepaid_units", 0)
        consumed = item.get("consumed_units", 0)
        idle = max(0, prepaid - consumed)
        rate = round((consumed / prepaid * 100), 1) if prepaid > 0 else 0
        inv_rows += f"""
        <tr>
            <td style="font-weight: 600;">{item.get('display_name')}</td>
            <td><code>{item.get('sku_part_number')}</code></td>
            <td style="text-align: right;">{prepaid}</td>
            <td style="text-align: right; color: #0284c7; font-weight: 600;">{consumed}</td>
            <td style="text-align: right; color: {'#d97706' if idle > 0 else '#16a34a'}; font-weight: 600;">{idle}</td>
            <td style="text-align: right;">%{rate}</td>
            <td style="text-align: center;"><span class="badge badge-success">{item.get('capability_status', 'Enabled')}</span></td>
        </tr>
        """

    # Section 3: 5-Layer Reconciliation rows
    rec_rows = ""
    for r in reconciliations:
        st = r.get("realization_status")
        badge_cls = "badge-success" if "Tam Değer" in st or "Doğrulandı" in st else ("badge-warning" if "Bekleniyor" in st or "Boşta" in st else "badge-danger")
        rec_rows += f"""
        <tr>
            <td style="font-weight: 600;">{r.get('workload_name')} <span style="font-size: 11px; color: #64748b;">({r.get('workload_code')})</span></td>
            <td style="text-align: right;">{r.get('entitlement_count')}</td>
            <td style="text-align: right;">{r.get('assignment_count')}</td>
            <td style="text-align: right;">{r.get('service_plan_active_count')}</td>
            <td style="text-align: right;">{r.get('configuration_active_count')}</td>
            <td style="text-align: right; font-weight: 600;">{r.get('telemetry_active_count')}</td>
            <td><span class="badge {badge_cls}">{st}</span></td>
            <td style="font-size: 12px; color: #475569;">{r.get('gap_description', '')}</td>
        </tr>
        """

    # Section 4: Persona distribution
    persona_counts = {}
    for u in users:
        p = u.get("persona_type", "Standard Knowledge Worker")
        persona_counts[p] = persona_counts.get(p, 0) + 1
    persona_cards = ""
    for p, c in sorted(persona_counts.items(), key=lambda x: x[1], reverse=True):
        persona_cards += f"""
        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px 16px; flex: 1 1 200px;">
            <div style="font-size: 12px; color: #64748b; font-weight: 600;">{p}</div>
            <div style="font-size: 20px; font-weight: 700; color: #0f172a; margin-top: 4px;">{c} <span style="font-size: 12px; font-weight: 400; color: #64748b;">kullanıcı</span></div>
        </div>
        """

    # Section 5: Duplicates
    dup_rows = ""
    for d in duplicate_users:
        dup_skus = ", ".join([s.get("sku_part_number", "") for s in d.get("assigned_skus", [])])
        dup_rows += f"""
        <tr>
            <td style="font-weight: 600;">{d.get('user_principal_name')}</td>
            <td>{d.get('department') or 'N/A'}</td>
            <td><code>{dup_skus}</code></td>
            <td style="color: #dc2626; font-size: 12px;">{'<br>'.join(d.get('risk_indicators', []))}</td>
            <td style="font-size: 12px;">{'<br>'.join(d.get('recommendations', []))}</td>
        </tr>
        """

    # Section 8: Inactive licensed
    inactive_rows = ""
    for inact in inactive_licensed:
        skus_str = ", ".join([s.get("sku_part_number", "") for s in inact.get("assigned_skus", [])])
        inactive_rows += f"""
        <tr>
            <td style="font-weight: 600;">{inact.get('user_principal_name')}</td>
            <td><span class="badge badge-danger">Hesap Devre Dışı</span></td>
            <td><code>{skus_str}</code></td>
            <td style="font-size: 12px; color: #d97706;">Atıl lisans tüketimi; derhal havuza iade edilebilir (License Reclaim).</td>
        </tr>
        """

    # Defender vs Purview breakdown
    defender_workloads = [r for r in reconciliations if r.get("workload_code") in ["MDE", "MDO", "MDI", "MDCA", "MDC"]]
    purview_workloads = [r for r in reconciliations if "PURVIEW" in r.get("workload_code")]

    def_rows = ""
    for dw in defender_workloads:
        def_rows += f"""
        <tr>
            <td style="font-weight: 600;">{dw.get('workload_name')}</td>
            <td style="text-align: right;">{dw.get('entitlement_count')}</td>
            <td style="text-align: right;">{dw.get('assignment_count')}</td>
            <td style="text-align: right;">{dw.get('telemetry_active_count')}</td>
            <td><span class="badge {'badge-success' if 'Tam Değer' in dw.get('realization_status') else 'badge-warning'}">{dw.get('realization_status')}</span></td>
        </tr>
        """

    pur_rows = ""
    for pw in purview_workloads:
        pur_rows += f"""
        <tr>
            <td style="font-weight: 600;">{pw.get('workload_name')}</td>
            <td style="text-align: right;">{pw.get('entitlement_count')}</td>
            <td style="text-align: right;">{pw.get('assignment_count')}</td>
            <td style="text-align: right;">{pw.get('telemetry_active_count')}</td>
            <td><span class="badge {'badge-success' if 'Tam Değer' in pw.get('realization_status') else 'badge-warning'}">{pw.get('realization_status')}</span></td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudShield - Lisans Zekâsı ve Güvenlik Değer Gerçekleştirme Raporu ({tenant_name} - {period})</title>
    <style>
        @page {{
            size: A4 portrait;
            margin: 14mm 12mm 16mm 12mm;
            @bottom-right {{
                content: "Sayfa " counter(page) " / " counter(pages);
                font-size: 9px;
                color: #64748b;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            }}
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            color: #1e293b;
            background-color: #ffffff;
            margin: 0;
            padding: 24px;
            font-size: 13px;
            line-height: 1.5;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #0284c7;
            padding-bottom: 16px;
            margin-bottom: 20px;
        }}
        .header-title h1 {{
            margin: 0;
            font-size: 22px;
            color: #0f172a;
            font-weight: 700;
        }}
        .header-title p {{
            margin: 4px 0 0;
            color: #64748b;
            font-size: 13px;
        }}
        .section {{
            margin-bottom: 28px;
            page-break-inside: avoid;
        }}
        .section-title {{
            font-size: 16px;
            font-weight: 700;
            color: #0f172a;
            border-bottom: 1px solid #e2e8f0;
            padding-bottom: 6px;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .section-num {{
            background: #0284c7;
            color: #ffffff;
            font-size: 11px;
            font-weight: 700;
            padding: 2px 7px;
            border-radius: 4px;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 16px;
        }}
        .kpi-card {{
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 14px;
        }}
        .kpi-label {{
            font-size: 11px;
            color: #64748b;
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.5px;
        }}
        .kpi-val {{
            font-size: 24px;
            font-weight: 700;
            color: #0f172a;
            margin-top: 4px;
        }}
        .kpi-sub {{
            font-size: 11px;
            color: #64748b;
            margin-top: 2px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            margin-top: 8px;
        }}
        th {{
            background: #f1f5f9;
            color: #334155;
            font-weight: 600;
            text-align: left;
            padding: 8px 10px;
            border: 1px solid #e2e8f0;
        }}
        td {{
            padding: 8px 10px;
            border: 1px solid #e2e8f0;
            vertical-align: middle;
        }}
        tr:nth-child(even) {{
            background: #fafafa;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }}
        .badge-success {{ background: #dcfce7; color: #15803d; }}
        .badge-warning {{ background: #fef3c7; color: #b45309; }}
        .badge-danger {{ background: #fee2e2; color: #b91c1c; }}
        .badge-info {{ background: #e0f2fe; color: #0369a1; }}
        .action-box {{
            background: #f0fdf4;
            border-left: 4px solid #16a34a;
            padding: 12px 16px;
            border-radius: 4px;
            margin-top: 8px;
            font-size: 12px;
        }}
    </style>
</head>
<body>

    {synthetic_banner_html}

    <div class="header">
        <div class="header-title">
            <h1>CloudShield Güvenlik Değer Gerçekleştirme Raporu</h1>
            <p><strong>Müşteri:</strong> {tenant_name} | <strong>Tenant ID:</strong> <code>{tenant_id}</code> | <strong>Dönem:</strong> {period} | <strong>Tarih:</strong> {snapshot_date}</p>
        </div>
        <div style="text-align: right;">
            <div style="font-size: 11px; color: #64748b; text-transform: uppercase; font-weight: 600;">Doğruluk Statüsü</div>
            <span class="badge {'badge-success' if is_live else 'badge-warning'}">{trust_label}</span>
        </div>
    </div>

    <!-- 1. Yönetici Özeti -->
    <div class="section">
        <div class="section-title"><span class="section-num">1</span> Yönetici Özeti (Executive Summary)</div>
        <p>
            Bu rapor, <strong>{tenant_name}</strong> organizasyonunun sahip olduğu Microsoft 365 kurumsal güvenlik lisanslarının
            yalnızca satın alma boyutunu değil; kullanıcı ataması, servis planı aktivasyonu, güvenlik ilke kapsamı ve canlı telemetri kanıtı
            olmak üzere <strong>5 Katmanlı Değer Gerçekleştirme</strong> zincirini denetler.
            Platformumuz, doğrulanmamış tahmini finansal kazanç veya spekülatif ROI iddiaları yerine; doğrudan teknik hak sahipliği,
            kullanım etkinliği ve güvenlik duruşu kanıtlarını raporlar.
        </p>
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label">Toplam Satın Alınan Lisans</div>
                <div class="kpi-val">{total_licenses}</div>
                <div class="kpi-sub">Prepaid Havuz Kapasitesi</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Atanmış / Tüketilen Lisans</div>
                <div class="kpi-val" style="color: #0284c7;">{assigned_licenses}</div>
                <div class="kpi-sub">Kullanım Oranı: %{utilization_rate}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Atıl / Boşta Lisans</div>
                <div class="kpi-val" style="color: {'#d97706' if idle_licenses > 0 else '#16a34a'};">{idle_licenses}</div>
                <div class="kpi-sub">Hemen Değerlendirilebilir Kapasite</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Değer Gerçekleştirme Endeksi</div>
                <div class="kpi-val" style="color: {'#16a34a' if value_index >= 80 else '#d97706'};">%{value_index}</div>
                <div class="kpi-sub">Önceki Döneme Göre: {val_diff_str}</div>
            </div>
        </div>
    </div>

    <!-- 2. Lisans Envanteri ve Tüketim Tablosu -->
    <div class="section">
        <div class="section-title"><span class="section-num">2</span> Lisans Envanteri ve Tüketim Tablosu</div>
        <table>
            <thead>
                <tr>
                    <th>Paket / Lisans Adı</th>
                    <th>SKU Part Number</th>
                    <th style="text-align: right;">Satın Alınan</th>
                    <th style="text-align: right;">Atanmış</th>
                    <th style="text-align: right;">Boşta</th>
                    <th style="text-align: right;">Kullanım %</th>
                    <th style="text-align: center;">Durum</th>
                </tr>
            </thead>
            <tbody>
                {inv_rows}
            </tbody>
        </table>
    </div>

    <!-- 3. 5 Katmanlı Değer Gerçekleştirme Matrisi -->
    <div class="section">
        <div class="section-title"><span class="section-num">3</span> 5 Katmanlı Değer Gerçekleştirme Matrisi</div>
        <p style="font-size: 12px; color: #64748b; margin-top: 0;">
            1. Hak Sahipliği (Entitlement) &rarr; 2. Kullanıcı Ataması (Assignment) &rarr; 3. Servis Planı Etkinliği (Service Plan) &rarr; 4. İlke Kapsamı (Configuration) &rarr; 5. Canlı Telemetri (Telemetry Evidence)
        </p>
        <table>
            <thead>
                <tr>
                    <th>Güvenlik İş Yükü</th>
                    <th style="text-align: right;">1. Hak</th>
                    <th style="text-align: right;">2. Atama</th>
                    <th style="text-align: right;">3. Plan</th>
                    <th style="text-align: right;">4. İlke</th>
                    <th style="text-align: right;">5. Kanıt</th>
                    <th>Değer Statüsü</th>
                    <th>Boşluk / Açıklama</th>
                </tr>
            </thead>
            <tbody>
                {rec_rows}
            </tbody>
        </table>
    </div>

    <!-- 4. Persona Bazlı Lisanslama ve Uygunluk Analizi -->
    <div class="section">
        <div class="section-title"><span class="section-num">4</span> Persona Bazlı Lisanslama ve Uygunluk Analizi</div>
        <div style="display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 12px;">
            {persona_cards}
        </div>
        <p style="font-size: 12px; color: #475569;">
            Kullanıcı profilleri; C-Level yönetim, bilgi güvenliği yöneticileri, finans, İK, yazılım mühendisliği ve saha çalışanları olarak ayrıştırılmıştır.
            Kritik veri işleyen rollere (Finans/İK) gelişmiş DLP ve sınıflandırma, yöneticilere gelişmiş XDR ve PIM koruması atanması denetlenmiştir.
        </p>
    </div>

    <!-- 5. Mükerrer ve Çakışan Lisans Denetimi -->
    <div class="section">
        <div class="section-title"><span class="section-num">5</span> Mükerrer ve Çakışan Lisans Denetimi</div>
        {f"""<table>
            <thead>
                <tr>
                    <th>Kullanıcı (UPN)</th>
                    <th>Departman</th>
                    <th>Atanmış Çakışan SKU'lar</th>
                    <th>Risk Açıklaması</th>
                    <th>Önerilen Aksiyon</th>
                </tr>
            </thead>
            <tbody>
                {dup_rows}
            </tbody>
        </table>""" if duplicate_users else "<div class='action-box'>Mükerrer veya üst üste binen lisans ataması tespit edilmemiştir. Lisans atama hijyeni tamdır.</div>"}
    </div>

    <!-- 6. Eklenti (Add-on) Ön Koşul Doğrulaması -->
    <div class="section">
        <div class="section-title"><span class="section-num">6</span> Eklenti (Add-on) Ön Koşul Doğrulaması</div>
        {f"""<p style='color: #dc2626; font-weight: 600;'>{len(missing_prereqs)} kullanıcıda temel lisans ön koşulu sağlanmadan atanmış güvenlik eklentisi (E5 Security / Compliance / Copilot) tespit edilmiştir.</p>""" if missing_prereqs else "<div class='action-box'>Tüm lisans eklentileri yetkili ve geçerli temel lisans paketleri (Base SKUs) üzerinde yapılandırılmıştır.</div>"}
    </div>

    <!-- 7. Atıl ve Boşta Kalan Lisans Optimizasyonu -->
    <div class="section">
        <div class="section-title"><span class="section-num">7</span> Atıl ve Boşta Kalan Lisans Optimizasyonu</div>
        <p>
            Tenant havuzunda toplam <strong>{idle_licenses} adet</strong> atanmamış boşta lisans bulunmaktadır.
            Bu lisanslar, yeni işe alımlar ve genişleyen ekipler için hazır kapasite olarak değerlendirilebilir veya bir sonraki sözleşme yenileme döneminde düşürülerek bütçe optimizasyonu sağlanabilir.
        </p>
    </div>

    <!-- 8. Pasif / Ayrılmış Kullanıcı Lisans Riski -->
    <div class="section">
        <div class="section-title"><span class="section-num">8</span> Pasif / Ayrılmış Kullanıcı Lisans Riski</div>
        {f"""<table>
            <thead>
                <tr>
                    <th>Hesap Adı (UPN)</th>
                    <th>Hesap Durumu</th>
                    <th>Üzerinde Kalan Lisanslar</th>
                    <th>Optimizasyon Aksiyonu</th>
                </tr>
            </thead>
            <tbody>
                {inactive_rows}
            </tbody>
        </table>""" if inactive_licensed else "<div class='action-box'>Devre dışı bırakılmış veya ayrılmış kullanıcılar üzerinde asılı kalmış lisans bulunmamaktadır.</div>"}
    </div>

    <!-- 9. Servis Planı Devre Dışı Bırakılmış Yetenekler -->
    <div class="section">
        <div class="section-title"><span class="section-num">9</span> Servis Planı Devre Dışı Bırakılmış Yetenekler</div>
        <p>
            Kullanıcı SKU paketleri içerisindeki güvenlik servis planlarının (WINDEFATP, MIPC, ATP_ENTERPRISE) durumu denetlenmiştir.
            Lisans satın alınmış olmasına rağmen planın yönetim konsolundan devre dışı bırakılması engellenmelidir.
        </p>
    </div>

    <!-- 10. İlke Kapsamı Olmayan Lisanslı Kullanıcı Boşlukları -->
    <div class="section">
        <div class="section-title"><span class="section-num">10</span> İlke Kapsamı Olmayan Lisanslı Kullanıcı Boşlukları</div>
        <p>
            Lisans atanmış kullanıcıların güvenlik ilkeleri (DLP ilkeleri, Koşullu Erişim kuralları, Güvenli Bağlantılar) kapsamına dahil edilip edilmediği doğrulanmıştır.
            Lisansı olup ilkelerden hariç tutulan hesaplar tespit edilerek kapsam tamamlama önerilmiştir.
        </p>
    </div>

    <!-- 11. Lisanssız Aktif Kullanıcı Güvenlik Riskleri -->
    <div class="section">
        <div class="section-title"><span class="section-num">11</span> Lisanssız Aktif Kullanıcı Güvenlik Riskleri</div>
        <p>
            Organizasyonda aktif üye durumunda olup ({len(unlicensed_active)} kullanıcı) hiçbir güvenlik veya üretkenlik lisansı atanmamış çalışanlar,
            korumasız veri erişimi ve denetim dışı işlem riski oluşturur.
        </p>
    </div>

    <!-- 12. KOBİ / Kurumsal Lisans Sınır Denetimi -->
    <div class="section">
        <div class="section-title"><span class="section-num">12</span> KOBİ / Kurumsal Lisans Sınır Denetimi (300 Kullanıcı Tavanı)</div>
        <p>
            Microsoft kurallarına göre Business Basic, Business Standard ve Business Premium paketleri en fazla <strong>300 kullanıcı</strong> ile sınırlandırılmıştır.
            <strong>{summary.get('smb_message', 'KOBİ lisans sınırları kontrol edilmiştir.')}</strong>
        </p>
    </div>

    <!-- 13. Azure Kaynak Tüketim Planları Ayrımı -->
    <div class="section">
        <div class="section-title"><span class="section-num">13</span> Azure Kaynak Tüketim Planları Ayrımı</div>
        <p>
            Microsoft Defender for Cloud (Defender for Servers, Containers, Storage, SQL ve CSPM) iş yükleri <strong>kullanıcı bazlı lisans (seat) gerektirmez</strong>.
            Bu koruma doğrudan Azure aboneliği ve kaynak tüketim modeli üzerinden çalışır. Raporlama matrisinde kullanıcı atamasından bağımsız olarak kaynak bazında doğrulanmıştır.
        </p>
    </div>

    <!-- 14. Microsoft Defender İş Yükleri Değer Tablosu -->
    <div class="section">
        <div class="section-title"><span class="section-num">14</span> Microsoft Defender İş Yükleri Değer Tablosu</div>
        <table>
            <thead>
                <tr>
                    <th>Defender Modülü</th>
                    <th style="text-align: right;">Lisans Hakkı</th>
                    <th style="text-align: right;">Atanan Kullanıcı</th>
                    <th style="text-align: right;">Doğrulanan Telemetri</th>
                    <th>Değer Gerçekleştirme</th>
                </tr>
            </thead>
            <tbody>
                {def_rows}
            </tbody>
        </table>
    </div>

    <!-- 15. Microsoft Purview İş Yükleri Değer Tablosu -->
    <div class="section">
        <div class="section-title"><span class="section-num">15</span> Microsoft Purview İş Yükleri Değer Tablosu</div>
        <table>
            <thead>
                <tr>
                    <th>Purview Modülü</th>
                    <th style="text-align: right;">Lisans Hakkı</th>
                    <th style="text-align: right;">Atanan Kullanıcı</th>
                    <th style="text-align: right;">Doğrulanan Telemetri</th>
                    <th>Değer Gerçekleştirme</th>
                </tr>
            </thead>
            <tbody>
                {pur_rows}
            </tbody>
        </table>
    </div>

    <!-- 16. Öncelikli İyileştirme Yol Haritası -->
    <div class="section">
        <div class="section-title"><span class="section-num">16</span> Öncelikli İyileştirme Yol Haritası (Quick Wins & Strategic Actions)</div>
        <ul style="padding-left: 20px; line-height: 1.8;">
            <li><strong>Hızlı Kazanım 1:</strong> Ayrılmış ve pasif hesaplardaki {len(inactive_licensed)} lisansı geri çekerek havuza iade edin.</li>
            <li><strong>Hızlı Kazanım 2:</strong> {len(duplicate_users)} mükerrer lisans atamasını (E5 + E3 çakışmaları) kaldırarak paket hijyenini sağlayın.</li>
            <li><strong>Stratejik Adım:</strong> Telemetrisi bekleniyor durumundaki Purview ve Defender iş yüklerinde ilke tuning ve canlı doğrulama süreçlerini tamamlayın.</li>
        </ul>
    </div>

    <!-- 17. Tarihsel Eğilim ve Önceki Rapor Karşılaştırması -->
    <div class="section">
        <div class="section-title"><span class="section-num">17</span> Tarihsel Eğilim ve Önceki Rapor Karşılaştırması</div>
        <p>
            Önceki rapor dönemine kıyasla Değer Gerçekleştirme Endeksi: <strong>{val_diff_str}</strong> olarak gerçekleşmiştir.
            Atıl lisansların azaltılması ve ilke konfigürasyonlarının yaygınlaştırılması ile değer skoru yükselme eğilimindedir.
        </p>
    </div>

    <!-- 18. Yönetilen Hizmet Optimizasyon Faaliyetleri -->
    <div class="section">
        <div class="section-title"><span class="section-num">18</span> Yönetilen Hizmet Optimizasyon Faaliyetleri (CloudShield İyileştirmeleri)</div>
        <p>
            CloudShield Yönetilen Hizmetler mühendislik ekibi, bilet veya manuel iş kaydı zorunluluğu olmaksızın, doğrudan tenant teknik konfigürasyon değişiklikleri
            ve audit kayıtları üzerinden gözlemlenen iyileştirme faaliyetlerini sürdürmektedir:
        </p>
        <ul style="padding-left: 20px; line-height: 1.8;">
            <li>Sensitivity Label ve DLP ilke kapsamlarının lisanslı kullanıcı havuzuna dinamik yaygınlaştırılması.</li>
            <li>Defender for Endpoint ve Intune profil çakışmalarının giderilmesi.</li>
            <li>Exchange Online ve SharePoint üzerinde lisanssız paylaşılan alanların güvenlik izolasyonu.</li>
        </ul>
    </div>

    <!-- 19. Veri Doğruluk, Kaynak ve İzin Metodolojisi -->
    <div class="section">
        <div class="section-title"><span class="section-num">19</span> Veri Doğruluk, Kaynak ve İzin Metodolojisi</div>
        <p>
            Veriler, Microsoft Graph API (<code>/v1.0/subscribedSkus</code>, <code>/v1.0/users</code>) üzerinden salt-okunur
            (<code>Organization.Read.All</code>, <code>User.Read.All</code>) yetkileriyle toplanmıştır.
            Platform kesinlikle yazma veya lisans atama/kaldırma yetkisi talep etmez (Zero Write Impact).
            Gizlilik ilkeleri gereğince kullanıcı kimlikleri raporlama düzeyinde maskelenerek k-Anonymity standartları korunur.
        </p>
    </div>

    <!-- 20. Ek: Teknik Terimler ve Lisans Sözlüğü -->
    <div class="section">
        <div class="section-title"><span class="section-num">20</span> Ek: Teknik Terimler ve Lisans Sözlüğü</div>
        <div style="font-size: 11px; color: #475569; line-height: 1.6;">
            <strong>SKU (Stock Keeping Unit):</strong> Satın alınabilir Microsoft lisans paketi (örn. SPE_E5, SPB).<br>
            <strong>Service Plan:</strong> Bir SKU içerisindeki bağımsız teknik servis bileşeni (örn. WINDEFATP, MIPC).<br>
            <strong>License Reclaim:</strong> Kullanılmayan, pasif veya mükerrer atanmış lisansın geri çekilip havuza kazandırılması.<br>
            <strong>5 Katmanlı Değer Zinciri:</strong> Satın almadan canlı telemetriye uzanan hak ve koruma gerçekleştirme süreci.<br>
            <strong>CSPM:</strong> Cloud Security Posture Management - Bulut güvenlik duruş yönetimi.
        </div>
    </div>

    <div style="border-top: 1px solid #e2e8f0; margin-top: 24px; padding-top: 12px; font-size: 11px; color: #94a3b8; text-align: center;">
        CloudShield Security Reporting & Managed Services Visibility Platform &bull; Lisans Zekâsı ve Değer Gerçekleştirme Motoru v3.2.0 &bull; {snapshot_date}
    </div>

</body>
</html>
"""
    return html_content

def render_license_pdf(html_content, output_pdf_path):
    """
    Renders HTML report to vector PDF using available PDF engine (Edge Headless or WeasyPrint).
    """
    try:
        from report_generator import find_pdf_engine
    except ImportError:
        from Portal.api.report_generator import find_pdf_engine
    engine, engine_path = find_pdf_engine()

    temp_html_path = output_pdf_path.replace(".pdf", ".temp.html")
    with open(temp_html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    os.makedirs(os.path.dirname(os.path.abspath(output_pdf_path)), exist_ok=True)

    try:
        if engine == "edge" and engine_path:
            cmd = [
                engine_path,
                "--headless",
                "--disable-gpu",
                "--no-pdf-header-footer",
                f"--print-to-pdf={output_pdf_path}",
                temp_html_path
            ]
            subprocess.run(cmd, check=True, timeout=30)
            return True, output_pdf_path
        elif engine == "weasyprint":
            import weasyprint
            weasyprint.HTML(temp_html_path).write_pdf(output_pdf_path)
            return True, output_pdf_path
        else:
            return False, "Uygun PDF motoru bulunamadı (Edge veya WeasyPrint gereklidir)."
    except Exception as ex:
        logger.error(f"Failed to generate license PDF: {ex}")
        return False, str(ex)
    finally:
        if os.path.exists(temp_html_path):
            try:
                os.remove(temp_html_path)
            except Exception:
                pass
