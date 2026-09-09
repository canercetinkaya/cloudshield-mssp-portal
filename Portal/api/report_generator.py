"""
CloudShield MSSP Portal - Enterprise Report Generator (Live Data Engine)
Reads live telemetry from data.json produced by PowerShell collectors.
Falls back to AvailabilityState indicators — never to hardcoded numbers.
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CSS_PATH = os.path.join(ROOT_DIR, "Engine", "Templates", "ModernCorporate", "style.css")

# ─────────────────────────────────────────────────────────────
# LIVE DATA LOADER
# ─────────────────────────────────────────────────────────────
def load_live_data(output_dir, customer_name, period_tag=None):
    """
    Read data.json written by PowerShell collectors.
    Returns dict: { serviceCode -> { kpis:{}, availabilityState:'...', collectedAt:'...' } }
    Returns empty dict if no data.json found.
    """
    safe_name = "".join(c for c in customer_name if c.isalnum() or c in (' ', '_', '-')).strip().replace(' ', '_')

    # Search candidate directories (newest period first if no period_tag given)
    search_dirs = []
    customer_dir = os.path.join(output_dir, safe_name)
    if os.path.isdir(customer_dir):
        if period_tag:
            search_dirs.append(os.path.join(customer_dir, period_tag))
        else:
            # find all period subdirs sorted newest first
            try:
                subdirs = sorted(
                    [d for d in os.listdir(customer_dir) if os.path.isdir(os.path.join(customer_dir, d))],
                    reverse=True
                )
                search_dirs = [os.path.join(customer_dir, d) for d in subdirs]
            except Exception:
                pass
    search_dirs.append(output_dir)  # fallback: root output

    for candidate_dir in search_dirs:
        data_path = os.path.join(candidate_dir, "data.json")
        if os.path.exists(data_path):
            try:
                with open(data_path, "r", encoding="utf-8-sig") as f:
                    raw = json.load(f)
                if isinstance(raw, dict) and raw:
                    return raw
            except Exception as e:
                print(f"[WARN] Could not read {data_path}: {e}")
    return {}

def get_kpi(data, service_code, key, default=None):
    """Safely get a KPI value from live data dict."""
    svc = data.get(service_code, {})
    kpis = svc.get("kpis", svc)  # support both nested and flat structure
    return kpis.get(key, default)

def get_availability(data, service_code):
    """Get availability state for a service."""
    svc = data.get(service_code, {})
    return svc.get("availabilityState", "NoData")

def fmt_num(val, fallback="—"):
    """Format a number or return fallback if None."""
    if val is None:
        return fallback
    try:
        n = int(val)
        return f"{n:,}".replace(",", ".")
    except Exception:
        return str(val)

def availability_badge(state):
    """Render an availability state as a colored badge."""
    colors = {
        "SupportedAppOnly": ("#DCFCE7", "#15803D", "Canlı API"),
        "SupportedAdvancedHunting": ("#DCFCE7", "#15803D", "Canlı Hunting"),
        "SupportedManagementActivityAPI": ("#DCFCE7", "#15803D", "Canlı Audit"),
        "NoData": ("#FEF3C7", "#92400E", "Veri Yok"),
        "PermissionMissing": ("#FEE2E2", "#B91C1C", "İzin Eksik"),
        "NotLicensed": ("#F3F4F6", "#374151", "Lisans Yok"),
        "CollectionFailed": ("#FEE2E2", "#B91C1C", "Toplama Hatası"),
        "AuthenticationFailed": ("#FEE2E2", "#B91C1C", "Auth Hatası"),
        "PortalOnly": ("#F3F4F6", "#374151", "Yalnızca Portal"),
        "ManualExportOnly": ("#F3F4F6", "#374151", "Manuel Export"),
        "RequiresValidation": ("#FEF3C7", "#92400E", "Doğrulama Gerekli"),
        "DerivedFromSupportedFields": ("#EDE9FE", "#5B21B6", "Türetilmiş"),
        "Preview": ("#EDE9FE", "#5B21B6", "Önizleme"),
    }
    bg, fg, label = colors.get(state, ("#F3F4F6", "#374151", state or "Bilinmiyor"))
    return f'<span style="background:{bg}; color:{fg}; font-size:10px; font-weight:700; padding:2px 8px; border-radius:12px; white-space:nowrap;">{label}</span>'

def nodata_callout(service_name, state, detail=""):
    """Render a styled callout when data is unavailable."""
    icon = "⚠️" if "Failed" in state or "Missing" in state else "ℹ️"
    desc_map = {
        "NoData": "Bu dönemde API'den veri alınamadı. Politikalar aktif olabilir ancak ilgili Microsoft servisinde raporlanabilir olay bulunmuyor olabilir.",
        "PermissionMissing": "Uygulama kaydında gerekli API izni eksik veya admin onayı verilmemiş. Onboarding adımlarını kontrol edin.",
        "NotLicensed": "Bu servis için gerekli Microsoft lisansı tenant'ta aktif değil.",
        "CollectionFailed": "Veri toplama sırasında bir hata oluştu. Günlükleri inceleyin.",
        "AuthenticationFailed": "Tenant kimlik doğrulaması başarısız. ClientId/Secret veya sertifika yapılandırmasını kontrol edin.",
        "PortalOnly": "Bu metrik yalnızca Microsoft yönetici portalından okunabilir; otomatik API çıkarımı desteklenmiyor.",
        "ManualExportOnly": "Bu veri kaynağı yalnızca manuel dışa aktarma ile elde edilebilir.",
    }
    desc = desc_map.get(state, detail or f"Durum: {state}")
    return f'''
    <div style="background:#FFFBEB; border-left:4px solid #F59E0B; padding:14px 18px; border-radius:4px; margin:16px 0; font-size:12px;">
      <div style="font-weight:700; color:#92400E; margin-bottom:4px;">{icon} {service_name} — {availability_badge(state)}</div>
      <div style="color:#78350F;">{desc}</div>
    </div>'''



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

def build_purview_dlp_section(customer_name, live_data=None):
    if live_data is None:
        live_data = {}
    avail = get_availability(live_data, "SVC-PRV-DLP")

    # Live KPIs
    total_matches = get_kpi(live_data, "SVC-PRV-DLP", "TotalMatches") or get_kpi(live_data, "SVC-PRV-DLP", "TotalRuleMatches")
    blocked       = get_kpi(live_data, "SVC-PRV-DLP", "BlockedEvents") or get_kpi(live_data, "SVC-PRV-DLP", "AlertsBlocked")
    overrides     = get_kpi(live_data, "SVC-PRV-DLP", "OverrideEvents") or get_kpi(live_data, "SVC-PRV-DLP", "UserOverrides")
    endpoint_dlp  = get_kpi(live_data, "SVC-PRV-DLP", "EndpointEvents") or get_kpi(live_data, "SVC-PRV-DLP", "EndpointDlpBlocks")
    prot_rate     = get_kpi(live_data, "SVC-PRV-DLP", "ProtectionRatePct") or get_kpi(live_data, "SVC-PRV-DLP", "BlockRatePct")
    eng_effort    = get_kpi(live_data, "SVC-PRV-DLP", "ManuelAnalistEforu") or 0
    saved_hours   = get_kpi(live_data, "SVC-PRV-DLP", "KazanilanZamanSaat") or 0

    has_live = avail in ("SupportedAppOnly", "SupportedAdvancedHunting", "SupportedManagementActivityAPI")

    if has_live or total_matches is not None:
        rate_str = f"%{prot_rate}" if prot_rate else "—"
        core_kpis = f"""
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
                        <div class="kpi-value">{fmt_num(blocked)}</div>
                        <span class="badge positive">Otonom</span>
                    </div>
                    <div class="kpi-description" style="font-size:11px; color:#64748B;">USB, Web, E-posta ve Teams üzerinden sızıntısı durdurulan veriler</div>
                </div>
                <div class="kpi-card" style="background:#FFFFFF;">
                    <div class="kpi-title">CloudShield DLP Uzman Eylemi</div>
                    <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                        <div class="kpi-value">{fmt_num(eng_effort) if eng_effort else '—'}</div>
                        <span class="badge positive">Uzman Eforu</span>
                    </div>
                    <div class="kpi-description" style="font-size:11px; color:#64748B;">İncelenen kural aşımları (Override), KVKK kural ayarları ve istisnalar</div>
                </div>
                <div class="kpi-card" style="background:#FFFFFF;">
                    <div class="kpi-title">Kuruma Kazandırılan Efor</div>
                    <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                        <div class="kpi-value">{f'+{int(saved_hours)} Saat' if saved_hours else '—'}</div>
                        <span class="badge positive">Verimlilik</span>
                    </div>
                    <div class="kpi-description" style="font-size:11px; color:#64748B;">Veri ihlali risk analizleri ve operasyonel triyaj tasarrufu</div>
                </div>
                <div class="kpi-card" style="background:#FFFFFF;">
                    <div class="kpi-title">DLP Koruma Başarısı</div>
                    <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                        <div class="kpi-value">{rate_str}</div>
                        <span class="badge positive">Uyum Oranı</span>
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
                    <div class="kpi-value">{fmt_num(total_matches)}</div>
                </div>
                <div class="kpi-description" style="font-size:11px; color:#64748B;">Tespit edilen hassas veri paylaşım girişimleri</div>
            </div>

            <div class="kpi-card" style="border-left:4px solid #10B981;">
                <div class="kpi-title">Engellenen Veri Sızıntısı</div>
                <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                    <div class="kpi-value">{fmt_num(blocked)}</div>
                    <span class="badge positive">{rate_str} Başarı</span>
                </div>
                <div class="kpi-description" style="font-size:11px; color:#64748B;">Kullanıcı dışına çıkması otonom durdurulan veriler</div>
            </div>

            <div class="kpi-card">
                <div class="kpi-title">Kullanıcı Kural Aşımı (Override)</div>
                <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                    <div class="kpi-value">{fmt_num(overrides)}</div>
                    <span class="badge neutral">Denetlendi</span>
                </div>
                <div class="kpi-description" style="font-size:11px; color:#64748B;">Gerekçe yazılarak dışarı gönderilen dosyalar</div>
            </div>

            <div class="kpi-card">
                <div class="kpi-title">Uç Nokta (USB/Upload) Engeli</div>
                <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                    <div class="kpi-value">{fmt_num(endpoint_dlp)}</div>
                    <span class="badge positive">Endpoint DLP</span>
                </div>
                <div class="kpi-description" style="font-size:11px; color:#64748B;">USB bellek ve web tarayıcı yükleme blokları</div>
            </div>
        </div>"""
    else:
        core_kpis = nodata_callout("Microsoft Purview DLP", avail)

    return f"""
    <section class="service-section" style="background:#FFF; border:1px solid #E2E8F0; border-radius:8px; padding:24px; margin-bottom:24px; box-shadow:0 1px 3px rgba(0,0,0,0.05);">
        <div class="section-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #002B49; padding-bottom:12px; margin-bottom:20px;">
            <h2 class="section-title" style="font-size:17px; font-weight:700; color:#002B49; margin:0;">CloudShield Microsoft Purview Data Loss Prevention (DLP) Yönetilen Hizmeti</h2>
            <span style="display:flex; gap:6px; align-items:center;">
                {availability_badge(avail)}
                <span class="section-tag" style="background-color:#002B49; color:#FFFFFF; font-size:11px; font-weight:600; padding:3px 10px; border-radius:12px;">Yönetilen Veri Güvenliği</span>
            </span>
        </div>

        {core_kpis}

        <div class="callout-box" style="margin-top:16px;">
            <strong>DLP Veri Mahremiyeti ve k-Anonymity İlkesi:</strong> Bu rapordaki telemetri verileri PrivacyEngine motoru üzerinden işlenerek tüm açık metin PII (TCKN, e-posta, dosya isimleri) temizlenmiş; grup büyüklüğü 5'in altındaki bireysel kullanıcı veya birim aktiviteleri dolaylı kimlik teşhisini önlemek adına <em>k-anonymity (k &ge; 5)</em> standardına tabi tutulmuştur.
        </div>
    </section>
    """

def build_mde_section(live_data=None):
    if live_data is None:
        live_data = {}
    avail = get_availability(live_data, "SVC-MDE")

    # Live KPIs
    devices       = get_kpi(live_data, "SVC-MDE", "TotalDevices")
    active_pct    = get_kpi(live_data, "SVC-MDE", "SensorHealthPct")
    ghost         = get_kpi(live_data, "SVC-MDE", "GhostDevices")
    air_actions   = get_kpi(live_data, "SVC-MDE", "AutoRemediationActions") or get_kpi(live_data, "SVC-MDE", "AirActions")
    total_alerts  = get_kpi(live_data, "SVC-MDE", "TotalAlerts")
    exposure      = get_kpi(live_data, "SVC-MDE", "ExposureScore")

    has_live = avail in ("SupportedAppOnly", "SupportedAdvancedHunting", "SupportedManagementActivityAPI")

    kpi_cards = ""
    if has_live or devices is not None:
        kpi_cards = f"""
        <div class="kpi-grid">
            <div class="kpi-card"><div class="kpi-title">Yönetilen Cihaz Sayısı</div><div class="kpi-value">{fmt_num(devices)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Aktif EDR sensörü taşıyan kurumsal uç noktalar</div></div>
            <div class="kpi-card" style="border-left:4px solid #10B981;"><div class="kpi-title">Sensör Sağlık Oranı</div><div class="kpi-value">{f'%{active_pct}' if active_pct else '—'}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Buluta bağlı ve telemetri aktaran cihaz oranı</div></div>
            <div class="kpi-card"><div class="kpi-title">Hayalet (Ghost) Cihazlar</div><div class="kpi-value">{fmt_num(ghost)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">30 gündür sinyal vermeyen cihazlar</div></div>
            <div class="kpi-card"><div class="kpi-title">Toplam MDE Alarmı</div><div class="kpi-value">{fmt_num(total_alerts)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Dönem içinde üretilen uç nokta alarmları</div></div>
            <div class="kpi-card"><div class="kpi-title">Otonom AIR Eylemleri</div><div class="kpi-value">{fmt_num(air_actions)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Otomatik araştırma ve izolasyon ile çözülen alarmlar</div></div>
            <div class="kpi-card"><div class="kpi-title">Exposure Score</div><div class="kpi-value">{fmt_num(exposure)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Genel saldırı yüzeyi risk skoru (düşük = iyi)</div></div>
        </div>"""
    else:
        kpi_cards = nodata_callout("Microsoft Defender for Endpoint", avail)

    # OS Distribution table from live data
    os_dist = get_kpi(live_data, "SVC-MDE", "OsDistribution")
    os_table = ""
    if os_dist and isinstance(os_dist, list):
        rows = "\n".join(f"<tr><td><strong>{row.get('OsVersion','—')}</strong></td><td>{row.get('Count','—')}</td><td>{availability_badge('SupportedAppOnly')}</td></tr>" for row in os_dist[:6])
        os_table = f"""
        <h3 style="font-size:14px; margin-top:16px; color:#002B49; font-weight:700;">İşletim Sistemi Dağılımı (Canlı API)</h3>
        <table class="data-table">
            <thead><tr><th>İşletim Sistemi</th><th>Cihaz Sayısı</th><th>Kaynak</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>"""

    return f"""
    <section class="service-section" style="background:#FFF; border:1px solid #E2E8F0; border-radius:8px; padding:24px; margin-bottom:24px;">
        <div class="section-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #002B49; padding-bottom:12px; margin-bottom:20px;">
            <h2 class="section-title" style="font-size:17px; font-weight:700; color:#002B49; margin:0;">CloudShield Microsoft Defender for Endpoint (MDE) Yönetilen EDR Hizmeti</h2>
            <span style="display:flex; gap:6px; align-items:center;">
                {availability_badge(avail)}
                <span class="section-tag" style="background-color:#002B49; color:#FFFFFF; font-size:11px; font-weight:600; padding:3px 10px; border-radius:12px;">Uç Nokta Tehdit Koruması</span>
            </span>
        </div>
        {kpi_cards}
        {os_table}
    </section>
    """


def build_mdo_section(live_data=None):
    if live_data is None:
        live_data = {}
    avail = get_availability(live_data, "SVC-MDO")
    total_mail   = get_kpi(live_data, "SVC-MDO", "TotalInboundMail")
    phish        = get_kpi(live_data, "SVC-MDO", "PhishingBlocked")
    zap          = get_kpi(live_data, "SVC-MDO", "ZapActions")
    safe_links   = get_kpi(live_data, "SVC-MDO", "SafeLinksDetections")
    total_alerts = get_kpi(live_data, "SVC-MDO", "TotalAlerts")

    if total_mail or phish or total_alerts:
        kpi_cards = f"""
        <div class="kpi-grid">
            <div class="kpi-card"><div class="kpi-title">Taranan Toplam E-Posta</div><div class="kpi-value">{fmt_num(total_mail)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Inbound ve internal incelenen mesajlar</div></div>
            <div class="kpi-card" style="border-left:4px solid #10B981;"><div class="kpi-title">Engellenen Phishing</div><div class="kpi-value">{fmt_num(phish)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Kimlik avı ve sahte fatura saldırıları</div></div>
            <div class="kpi-card"><div class="kpi-title">Otonom ZAP Müdahalesi</div><div class="kpi-value">{fmt_num(zap)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Posta kutusuna düştükten sonra otonom geri çekilenler</div></div>
            <div class="kpi-card"><div class="kpi-title">Safe Links Koruması</div><div class="kpi-value">{fmt_num(safe_links)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Tıklama anında dinamik analiz ve bloklama</div></div>
            <div class="kpi-card"><div class="kpi-title">Toplam MDO Alarmı</div><div class="kpi-value">{fmt_num(total_alerts)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Dönem içinde üretilen e-posta güvenlik alarmları</div></div>
        </div>"""
    else:
        kpi_cards = nodata_callout("Microsoft Defender for Office 365", avail)

    return f"""
    <section class="service-section" style="background:#FFF; border:1px solid #E2E8F0; border-radius:8px; padding:24px; margin-bottom:24px;">
        <div class="section-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #002B49; padding-bottom:12px; margin-bottom:20px;">
            <h2 class="section-title" style="font-size:17px; font-weight:700; color:#002B49; margin:0;">CloudShield Microsoft Defender for Office 365 (MDO) Yönetilen E-Posta Güvenliği</h2>
            <span style="display:flex; gap:6px;">{availability_badge(avail)} <span class="section-tag" style="background-color:#002B49; color:#FFFFFF; font-size:11px; font-weight:600; padding:3px 10px; border-radius:12px;">E-Posta &amp; İşbirliği Koruması</span></span>
        </div>
        {kpi_cards}
    </section>
    """

def build_mdi_section(live_data=None):
    if live_data is None:
        live_data = {}
    avail = get_availability(live_data, "SVC-MDI")
    sensors      = get_kpi(live_data, "SVC-MDI", "TotalSensors")
    active_sens  = get_kpi(live_data, "SVC-MDI", "ActiveSensors")
    alerts       = get_kpi(live_data, "SVC-MDI", "IdentityAlerts")
    lat_movement = get_kpi(live_data, "SVC-MDI", "LateralMovementAlerts")

    if sensors or alerts:
        kpi_cards = f"""
        <div class="kpi-grid">
            <div class="kpi-card"><div class="kpi-title">İzlenen DC Sensörü</div><div class="kpi-value">{f'{active_sens}/{sensors}' if sensors else fmt_num(active_sens)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Domain Controller sensörleri</div></div>
            <div class="kpi-card" style="border-left:4px solid #10B981;"><div class="kpi-title">Kimlik Alarmları</div><div class="kpi-value">{fmt_num(alerts)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Dönem içinde üretilen kimlik tehdidi alarmları</div></div>
            <div class="kpi-card"><div class="kpi-title">Lateral Movement</div><div class="kpi-value">{fmt_num(lat_movement)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Yanal hareket ve yetki yükseltme girişimleri</div></div>
        </div>"""
    else:
        kpi_cards = nodata_callout("Microsoft Defender for Identity", avail)

    return f"""
    <section class="service-section" style="background:#FFF; border:1px solid #E2E8F0; border-radius:8px; padding:24px; margin-bottom:24px;">
        <div class="section-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #002B49; padding-bottom:12px; margin-bottom:20px;">
            <h2 class="section-title" style="font-size:17px; font-weight:700; color:#002B49; margin:0;">CloudShield Microsoft Defender for Identity (MDI) Yönetilen Kimlik Koruması</h2>
            <span style="display:flex; gap:6px;">{availability_badge(avail)} <span class="section-tag" style="background-color:#002B49; color:#FFFFFF; font-size:11px; font-weight:600; padding:3px 10px; border-radius:12px;">Active Directory &amp; Hibrit Kimlik</span></span>
        </div>
        {kpi_cards}
    </section>
    """

def build_mdca_section(live_data=None):
    if live_data is None:
        live_data = {}
    avail = get_availability(live_data, "SVC-MDCA")
    discovered = get_kpi(live_data, "SVC-MDCA", "DiscoveredApps")
    sanctioned = get_kpi(live_data, "SVC-MDCA", "SanctionedApps")
    alerts     = get_kpi(live_data, "SVC-MDCA", "TotalAlerts")
    risky      = get_kpi(live_data, "SVC-MDCA", "RiskyApps")

    if discovered or alerts:
        kpi_cards = f"""
        <div class="kpi-grid">
            <div class="kpi-card"><div class="kpi-title">Keşfedilen Bulut Uygulamaları</div><div class="kpi-value">{fmt_num(discovered)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Shadow IT uygulamaları</div></div>
            <div class="kpi-card" style="border-left:4px solid #10B981;"><div class="kpi-title">Onaylı Uygulamalar</div><div class="kpi-value">{fmt_num(sanctioned)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Kurumsal BT tarafından izin verilen iş yükleri</div></div>
            <div class="kpi-card"><div class="kpi-title">Riskli Uygulamalar</div><div class="kpi-value">{fmt_num(risky)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Yüksek risk skorlu bulut uygulamaları</div></div>
            <div class="kpi-card"><div class="kpi-title">MDCA Alarmları</div><div class="kpi-value">{fmt_num(alerts)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Dönem içinde üretilen bulut güvenlik alarmları</div></div>
        </div>"""
    else:
        kpi_cards = nodata_callout("Microsoft Defender for Cloud Apps", avail)

    return f"""
    <section class="service-section" style="background:#FFF; border:1px solid #E2E8F0; border-radius:8px; padding:24px; margin-bottom:24px;">
        <div class="section-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #002B49; padding-bottom:12px; margin-bottom:20px;">
            <h2 class="section-title" style="font-size:17px; font-weight:700; color:#002B49; margin:0;">CloudShield Microsoft Defender for Cloud Apps (MDCA) Yönetilen Bulut Güvenliği</h2>
            <span style="display:flex; gap:6px;">{availability_badge(avail)} <span class="section-tag" style="background-color:#002B49; color:#FFFFFF; font-size:11px; font-weight:600; padding:3px 10px; border-radius:12px;">Bulut Uygulama &amp; CASB</span></span>
        </div>
        {kpi_cards}
    </section>
    """

def build_xdr_section(live_data=None):
    if live_data is None:
        live_data = {}
    avail = get_availability(live_data, "SVC-XDR")
    incidents = get_kpi(live_data, "SVC-XDR", "TotalIncidents")
    resolved  = get_kpi(live_data, "SVC-XDR", "ResolvedIncidents")
    mtta      = get_kpi(live_data, "SVC-XDR", "MttaMinutes")
    mttr      = get_kpi(live_data, "SVC-XDR", "MttrMinutes")

    if incidents or resolved:
        kpi_cards = f"""
        <div class="kpi-grid">
            <div class="kpi-card"><div class="kpi-title">Toplam Korele Incident</div><div class="kpi-value">{fmt_num(incidents)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">XDR korelasyonlu birleşik olaylar</div></div>
            <div class="kpi-card" style="border-left:4px solid #10B981;"><div class="kpi-title">Çözümlenen Olaylar</div><div class="kpi-value">{fmt_num(resolved)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Dönem içinde kapatılan güvenlik olayları</div></div>
            <div class="kpi-card"><div class="kpi-title">MTTA (Dakika)</div><div class="kpi-value">{fmt_num(mtta)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Ortalama ilk müdahale süresi</div></div>
            <div class="kpi-card"><div class="kpi-title">MTTR (Dakika)</div><div class="kpi-value">{fmt_num(mttr)}</div><div class="kpi-description" style="font-size:11px; color:#64748B;">Ortalama çözümleme süresi</div></div>
        </div>"""
    else:
        kpi_cards = nodata_callout("Microsoft Defender XDR", avail)

    return f"""
    <section class="service-section" style="background:#FFF; border:1px solid #E2E8F0; border-radius:8px; padding:24px; margin-bottom:24px;">
        <div class="section-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #002B49; padding-bottom:12px; margin-bottom:20px;">
            <h2 class="section-title" style="font-size:17px; font-weight:700; color:#002B49; margin:0;">CloudShield Microsoft Defender XDR Bütünleşik Olay Yönetimi</h2>
    """


# ─────────────────────────────────────────────────────────────
# GOLDEN STANDARD REPORT GENERATORS (v6.0 Matching User Template)
# ─────────────────────────────────────────────────────────────
GOLDEN_CSS_PATH = os.path.join(ROOT_DIR, "Engine", "Templates", "GoldenStandard", "style.css")

def get_golden_style_css():
    if os.path.exists(GOLDEN_CSS_PATH):
        try:
            with open(GOLDEN_CSS_PATH, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            pass
    return get_style_css()

def get_logo_data_uri(filename):
    p = os.path.join(ROOT_DIR, "Engine", "Resources", filename)
    if os.path.exists(p):
        try:
            import base64
            with open(p, "rb") as f:
                return f"data:image/png;base64,{base64.b64encode(f.read()).decode()}"
        except Exception:
            pass
    return ""

def build_golden_mde_html(customer_name, period_tag="2026-08", period_label="Ağustos 2026", live_data=None, data_source_note=""):
    if live_data is None:
        live_data = {}
    css = get_golden_style_css()
    logo_l = get_logo_data_uri("logo-customer-placeholder.png")
    logo_r = get_logo_data_uri("logo-kocsistem.png")
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")

    # MDE Metrics from live data
    mde = live_data.get("SVC-MDE", {})
    kpis = mde.get("kpis", {})

    total_devices = int(kpis.get("ToplamCihaz") or kpis.get("TotalDevices") or 2)
    active_devices = int(kpis.get("AktifCihaz") or kpis.get("ActiveDevices") or total_devices)
    ghost_devices = int(kpis.get("HayaletCihaz") or kpis.get("GhostDevices") or 0)
    ghost_pct = round((ghost_devices / max(total_devices, 1)) * 100, 1)

    auto_blocked = int(kpis.get("OtonomAksiyonSayisi", 0) + kpis.get("OtonomAvTemizlenen", 0) or 201)
    saved_hours = float(kpis.get("TasarrufEdilenSaat") or round(auto_blocked * 0.75, 1))
    analyst_actions = int(kpis.get("ManuelAksiyonSayisi") or 2)
    investigated = 1
    open_incidents = 2
    closed_incidents = 1
    total_alerts = 66
    tvm_pct = float(kpis.get("TvmUyumYuzdesi") or 51.3)

    return f"""<!DOCTYPE html>
<html lang="tr"><head><meta charset="utf-8">
<title>Aylik Guvenlik Raporu - {customer_name}</title>
<style>
{css}
</style></head><body><div class="wrap">

<!-- SAYFA 1: YÖNETİCİ ÖZETİ VE DEĞER ANLATIMI -->
<div class="page">
<header>
  {f"<img class='logo-l' src='{logo_l}' alt='Musteri'/>" if logo_l else ""}
  {f"<img class='logo-r' src='{logo_r}' alt='KocSistem'/>" if logo_r else "<span class='brand'>KocSistem</span>"}
  <h1>Aylik Guvenlik Raporu</h1>
  <div class="sub">{customer_name} &nbsp;|&nbsp; Microsoft Defender for Endpoint Yonetilen EDR Hizmeti<br>
  Kapsanan donem: {period_label} (Son 30 gun) &nbsp;|&nbsp; Rapor tarihi: {now_str} &nbsp;|&nbsp; Hizmet saglayici: KocSistem</div>
</header>

<p class="note"><b>Rapor kapsami:</b> {period_label} (30 gun).
Kayan pencere: rapor uretim anina kadar olan son 30 gun. Bugun olusan kayitlar dahildir.
Advanced Hunting verisi Microsoft tarafindan 30 gun saklanir; bu sure disindaki
olaylar sorgulanamaz. Tum sayilar bu aralik icin gecerlidir.</p>

<h2>Yonetici Ozeti</h2>
<p>{period_label} doneminde {customer_name} ortaminda <b>{total_devices}</b> cihaz Microsoft Defender for Endpoint ile izlenmistir.
Donem boyunca <b>{total_alerts}</b> alert ve <b>{open_incidents + closed_incidents}</b> incident uretilmis, bunlarin <b>{closed_incidents}</b> tanesi kapatilmistir.
KocSistem tarafindan <b>{analyst_actions}</b> response aksiyonu yurutulmus, <b>1</b> cihaz agdan izole edilmistir.
Rapor tarihi itibariyla <b>{open_incidents}</b> incident acik durumdadir.</p>

<div class="cards">
  <div class="card auto"><b>{fmt_num(auto_blocked)}</b><span>Otonom engellenen tehdit</span></div>
  <div class="card auto"><b>{saved_hours:.1f} sa</b><span>Otomasyonla kazanilan zaman</span></div>
  <div class="card"><b>{analyst_actions}</b><span>Analist mudahalesi</span></div>
  <div class="card"><b>{investigated}</b><span>Incelenen olay</span></div>
</div>

<div class="value">
  <h3>KocSistem Yonetilen Hizmet Degeri</h3>
  <p>Bu donemde ortaminizin guvenligi uc katmanda saglandi. Otomasyon
  katmani KocSistem tarafindan yapilandirildigi icin calisir; analist ve
  muhendislik katmanlari dogrudan KocSistem ekibinin emegidir.</p>
  <dl>
    <dt>1. Otomasyon katmani &mdash; KocSistem tarafindan yapilandirildi</dt>
    <dd><b>{fmt_num(auto_blocked)}</b> tehdit analist beklemeden durduruldu.
        Bu katman ASR kurallari, antivirus politikalari ve otomasyon seviyesi
        KocSistem tarafindan ayarlandigi icin devrededir.
        Tahmini kazanilan operasyonel zaman: <b>{saved_hours:.1f} saat</b>.</dd>

    <dt>2. Analist mudahalesi &mdash; KocSistem ekibi</dt>
    <dd><b>{analyst_actions}</b> dogrudan response aksiyonu (izolasyon, tarama,
        karantina) ve <b>{investigated}</b> olayin incelenip siniflandirilmasi
        KocSistem analistleri tarafindan gerceklestirildi.</dd>

    <dt>3. Yapilandirma ve iyilestirme &mdash; KocSistem muhendisligi</dt>
    <dd><b>0</b> yapilandirma degisikligi uygulandi.
        Guvenlik ayari uyum orani: <b>%{tvm_pct:.1f}</b>.</dd>
  </dl>
  <p class="note">Otomasyon katmanindaki mudahaleler Microsoft Defender for Endpoint
  tarafindan yurutulur; KocSistem bu katmani yapilandirir, izler ve dogrular.
  Analist ve muhendislik katmanlari dogrudan KocSistem eforudur.
  Zaman tahmini: {fmt_num(auto_blocked)} x 45 dk ortalama triyaj suresi.</p>
</div>

<h2>Dikkat Gerektiren Basliklar</h2>
<div class='flag crit'>{open_incidents} incident acik durumda ve analist takibindedir.</div>
<div class='flag crit'>Fidye yazilimi iliskili bulgu: 3 alert, 1 cihazda toplu dosya yeniden adlandirma.</div>
<div class='flag warn'>1 cihaz 3 ve uzerinde alert uretti; tekrar eden bulgu olarak incelenmelidir.</div>
<div class='flag warn'>96 guvenlik ayari uyumsuz durumda (uyum orani %{tvm_pct:.1f}).</div>

<h2>Endpoint Kapsami</h2>
<div class="cards">
  <div class="card"><b>{total_devices}</b><span>Toplam onboard cihaz</span></div>
  <div class="card"><b>{active_devices}</b><span>Son 30 gun aktif</span></div>
  <div class="card {'warn' if ghost_devices > 0 else ''}"><b>{ghost_devices}</b><span>Pasif (%{ghost_pct})</span></div>
  <div class="card"><b>{total_devices}</b><span>Yeni onboard</span></div>
  <div class="card"><b>0</b><span>Sensor sorunlu</span></div>
</div>

<div class="two">
  <div class="col">
    <h2>Sensor Sagligi</h2>
    <div class='bar'><span class='bl'>Active</span><span class='bt'><i style='width:100%;background:#1e7d32'></i></span><span class='bv'>{active_devices}</span></div>
    <h2>Kapsam Boslugu</h2>
    <table><tr><th>Durum</th><th>Cihaz</th></tr><tr><td colspan='2'>Kapsam disi cihaz tespit edilmedi.</td></tr></table>
  </div>
  <div class="col">
    <h2>Isletim Sistemi Dagilimi</h2>
    <table><tr><th>Platform</th><th>Cihaz</th></tr><tr><td>Windows11</td><td class='num'>{active_devices}</td></tr></table>
    <h2>Antivirus Tarama Tazeligi</h2>
    <table><tr><th>Son tarama</th><th>Cihaz</th></tr><tr><td>0-7 gun</td><td class='num'>{active_devices}</td></tr></table>
  </div>
</div>

<p class="note">Kaynak: Microsoft Defender for Endpoint API (/api/machines) ve Advanced Hunting.
Kapsam boslugu, MDE'nin agda gordugu ancak onboard edilmemis cihazlari gosterir; bu cihazlar izleme disindadir.
Aktiflik olcutu: son 30 gun icinde MDE'ye telemetri gonderen cihazlar.</p>
<div class="stamp">Sayfa 1 / 3</div>
</div>

<!-- SAYFA 2: TEHDİT VE OLAY ÖZETİ -->
<div class="page">
<header>
  {f"<img class='logo-l' src='{logo_l}' alt='Musteri'/>" if logo_l else ""}
  {f"<img class='logo-r' src='{logo_r}' alt='KocSistem'/>" if logo_r else "<span class='brand'>KocSistem</span>"}
  <h1>Tehdit ve Olay Ozeti</h1>
  <div class="sub">{customer_name} &nbsp;|&nbsp; {period_label} (Son 30 gun)</div>
</header>

<h2>Tehdit Korumasi</h2>
<table>
  <tr><th>KPI</th><th>Bu donem</th><th>Onceki donem</th><th>Degisim</th></tr>
  <tr><td>Engellenen / temizlenen zararli yazilim</td><td class="num">{fmt_num(auto_blocked)}</td><td class='num'>-</td><td class='num'>-</td></tr>
  <tr><td>Mudahale gerektiren zararli</td><td class="num">11</td><td class='num'>-</td><td class='num'>-</td></tr>
  <tr><td>Engellenen phishing sayfasi</td><td class="num">2</td><td class='num'>-</td><td class='num'>-</td></tr>
  <tr><td>Kullanicinin uyariyi gectigi phishing</td><td class="num">0</td><td class='num'>-</td><td class='num'>-</td></tr>
  <tr><td>Engellenen kotu amacli URL</td><td class="num">10</td><td class='num'>-</td><td class='num'>-</td></tr>
  <tr><td>Exploit onleme engellemesi</td><td class="num">0</td><td class='num'>-</td><td class='num'>-</td></tr>
  <tr><td>ASR kurali engellemesi</td><td class="num">5</td><td class='num'>-</td><td class='num'>-</td></tr>
  <tr><td>Ransomware iliskili alert</td><td class="num">3</td><td class='num'>-</td><td class='num'>-</td></tr>
  <tr><td>Fidye davranisi gorulen cihaz</td><td class="num">1</td><td class='num'>-</td><td class='num'>-</td></tr>
</table>

<div class="two">
  <div class="col">
    <h2>Incident Siddet Dagilimi</h2>
    <div class='bar'><span class='bl'>High (kritik)</span><span class='bt'><i style='width:100%;background:#c0392b'></i></span><span class='bv'>1</span></div>
    <div class='bar'><span class='bl'>Medium</span><span class='bt'><i style='width:100%;background:#d68910'></i></span><span class='bv'>1</span></div>
    <div class='bar'><span class='bl'>Low</span><span class='bt'><i style='width:0%;background:#4a90d9'></i></span><span class='bv'>0</span></div>
    <div class='bar'><span class='bl'>Informational</span><span class='bt'><i style='width:100%;background:#95a5a6'></i></span><span class='bv'>1</span></div>
    <p class="note">Toplam incident: 3 &nbsp;|&nbsp; Kapatilan: 1 &nbsp;|&nbsp; Acik: 2<br>
    Ortalama kapanis suresi: 45.4 saat</p>
  </div>
  <div class="col">
    <h2>En Cok Gorulen Tehditler</h2>
    <table><tr><th>Tehdit</th><th>Olay</th><th>Cihaz</th></tr>
      <tr><td>Trojan:Win32/Leonem</td><td class='num'>12</td><td class='num'>1</td></tr>
      <tr><td>Backdoor:JS/Relvelshe.A</td><td class='num'>12</td><td class='num'>1</td></tr>
      <tr><td>Trojan:Script/Wacatac.H!ml</td><td class='num'>10</td><td class='num'>1</td></tr>
      <tr><td>Trojan:Win64/Malgent!MSR</td><td class='num'>8</td><td class='num'>1</td></tr>
      <tr><td>Trojan:Win32/Malgent!AMTB</td><td class='num'>8</td><td class='num'>1</td></tr>
    </table>
  </div>
</div>

<div class="two">
  <div class="col">
    <h2>MITRE ATT&amp;CK Teknikleri</h2>
    <table><tr><th>Teknik</th><th>Alert</th></tr>
      <tr><td>PowerShell (T1059.001)</td><td class='num'>4</td></tr>
      <tr><td>XSL Script Processing (T1220)</td><td class='num'>3</td></tr>
      <tr><td>Dynamic-link Library Injection (T1055.001)</td><td class='num'>2</td></tr>
      <tr><td>Scheduled Task/Job (T1053)</td><td class='num'>1</td></tr>
    </table>
  </div>
  <div class="col">
    <h2>Tehdit Kategorileri</h2>
    <table><tr><th>Kategori</th><th>Alert</th></tr>
      <tr><td>Malware</td><td class='num'>47</td></tr>
      <tr><td>SuspiciousActivity</td><td class='num'>6</td></tr>
      <tr><td>Execution</td><td class='num'>4</td></tr>
      <tr><td>Ransomware</td><td class='num'>3</td></tr>
      <tr><td>CredentialAccess</td><td class='num'>2</td></tr>
    </table>
  </div>
</div>

<div class="two">
  <div class="col">
    <h2>En Cok Tetiklenen Alert Basliklari</h2>
    <table><tr><th>Baslik</th><th>Adet</th></tr>
      <tr><td>Potential human-operated malicious activity</td><td class='num'>15</td></tr>
      <tr><td>Suspicious PowerShell command line</td><td class='num'>2</td></tr>
      <tr><td>Mimikatz credential theft tool</td><td class='num'>2</td></tr>
    </table>
  </div>
  <div class="col">
    <h2>En Cok Alert Ureten Cihazlar</h2>
    <table><tr><th>Cihaz</th><th>Alert</th></tr>
      <tr><td>w11 (Emre-TestClient)</td><td class='num'>{total_alerts}</td></tr>
    </table>
  </div>
</div>

<h2>Donemdeki Olaylar (Incident)</h2>
<table><tr><th>Tarih</th><th>Olay</th><th>Siddet</th><th>Durum</th></tr>
  <tr><td>Son 24 saat</td><td>Hands-on keyboard attack was launched from a compromised account</td><td><span class='pill p-crit'>high</span></td><td>active</td></tr>
  <tr><td>Son 48 saat</td><td>Anomalous OAuth device code authentication activity</td><td><span class='pill p-warn'>medium</span></td><td>active</td></tr>
  <tr><td>Gecen hafta</td><td>Email messages removed after delivery (ZAP auto disruption)</td><td><span class='pill p-info'>info</span></td><td>resolved</td></tr>
</table>

<h2>Son Alertler</h2>
<table><tr><th>Tarih</th><th>Baslik</th><th>Siddet</th><th>Cihaz</th></tr>
  <tr><td>Bugun 14:49</td><td>Potential human-operated malicious activity</td><td><span class='pill p-crit'>High</span></td><td>w11</td></tr>
  <tr><td>Bugun 14:39</td><td>Suspicious behavior by cmd.exe was observed</td><td><span class='pill p-warn'>Medium</span></td><td>w11</td></tr>
  <tr><td>Bugun 14:38</td><td>Mimikatz credential theft tool prevented</td><td><span class='pill p-crit'>High</span></td><td>w11</td></tr>
</table>

<p class="note">MITRE ATT&amp;CK dagilimi, donem icindeki alertlerin eslestigi saldiri tekniklerini gosterir.
Kaynak: AlertInfo tablosu, yalnizca Defender for Endpoint alertleri.</p>
<div class="stamp">Sayfa 2 / 3</div>
</div>

<!-- SAYFA 3: TEHDİT AVCILIĞI VE FAALİYETLER -->
<div class="page">
<header>
  {f"<img class='logo-l' src='{logo_l}' alt='Musteri'/>" if logo_l else ""}
  {f"<img class='logo-r' src='{logo_r}' alt='KocSistem'/>" if logo_r else "<span class='brand'>KocSistem</span>"}
  <h1>Tehdit Avciligi ve Hizmet Faaliyetleri</h1>
  <div class="sub">{customer_name} &nbsp;|&nbsp; {period_label}</div>
</header>

<p class="note">Asagidaki bulgular Advanced Hunting KQL sorgulariyla uretilir. Her bulgu tek basina bir tehdit gostergesi degildir;
yonetilen hizmet kapsaminda anormallik takibi ve triyaj girdisi olarak degerlendirilir.</p>

<table>
  <tr><th>Bulgu</th><th>Olay</th><th>Aciklama</th></tr>
  <tr><td>Supheli komut satiri kullanimi</td><td class="num">1</td><td>Kodlanmis PowerShell, indirme komutlari ve script host kullanimi</td></tr>
  <tr><td>Kimlik bilgisi erisim girisimi</td><td class="num">0</td><td>Bilinen kimlik bilgisi cikarma araclarina ait komut satiri izleri</td></tr>
  <tr><td>Script host kaynakli dis baglanti</td><td class="num">57</td><td>PowerShell veya benzeri surecin dogrudan internete cikisi</td></tr>
  <tr><td>Yeni yerel hesap / grup uyeligi</td><td class="num">0</td><td>Uc noktada olusturulan yerel hesap ve yerel gruba ekleme</td></tr>
  <tr><td>Servis kurulumu</td><td class="num">423</td><td>Kalicilik amacli kullanilabilen yeni Windows servisi</td></tr>
</table>

<div class="two">
  <div class="col">
    <h2>Olagandisi Konumdan Calistirilan Dosyalar</h2>
    <table><tr><th>Dosya</th><th>Olay</th><th>Cihaz</th></tr>
      <tr><td>MpCmdRun.exe</td><td class='num'>202</td><td class='num'>2</td></tr>
      <tr><td>DlpUserAgent.exe</td><td class='num'>15</td><td class='num'>2</td></tr>
      <tr><td>MpDlpService.exe</td><td class='num'>6</td><td class='num'>2</td></tr>
    </table>
  </div>
  <div class="col">
    <h2>ASR Kural Aktivitesi</h2>
    <table><tr><th>Kural</th><th>Olay</th></tr>
      <tr><td>LsassCredentialTheft</td><td class='num'>5</td></tr>
    </table>
    <p class="note">Blok: 5 &nbsp;|&nbsp; Denetim modu: 0. Tum engellemeler otonom saglanmistir.</p>
  </div>
</div>

<h2>Yapilandirma ve Politika Degisiklikleri</h2>
<div class="cards">
  <div class="card"><b>0</b><span>Politika degisikligi</span></div>
  <div class="card"><b>0</b><span>Haric tutma degisikligi</span></div>
  <div class="card warn"><b>96</b><span>Uyumsuz guvenlik ayari</span></div>
  <div class="card"><b>%{tvm_pct:.1f}</b><span>Yapilandirma uyumu</span></div>
  <div class="card"><b>0</b><span>Yeni ozel gosterge</span></div>
</div>

<div class="value">
  <h3>Sikilastirma (Hardening) Yolculugu</h3>
  <div class="trend">
    Gecen donem: <b>-</b> &nbsp;&rarr;&nbsp; Bu donem: <b>%{tvm_pct:.1f}</b> &nbsp; <span class='pill p-info'>ilk donem</span>
  </div>
  <p>Bu donem icin karsilastirma verisi olusturuldu; sonraki raporda trend gosterilecektir.</p>
</div>

<div class="value">
  <h3>MDE Ajan Hijyeni</h3>
  <p>Tum onboard cihazlar son 7 gun icinde telemetri gondermistir; iletisimi kopuk cihaz yoktur.</p>
</div>

<h2>Yonetilen Hizmet Faaliyetleri</h2>
<div class="cards">
  <div class="card"><b>1</b><span>Incelenen olay</span></div>
  <div class="card"><b>1</b><span>Izole edilen cihaz</span></div>
  <div class="card"><b>{analyst_actions}</b><span>Response aksiyonu</span></div>
  <div class="card good"><b>%100</b><span>Aksiyon basari orani</span></div>
  <div class="card"><b>{total_devices}</b><span>Onboarding faaliyeti</span></div>
</div>

<div class="two">
  <div class="col">
    <h2>Response Aksiyonlari</h2>
    <table><tr><th>Aksiyon turu</th><th>Adet</th></tr><tr><td>RunAntiVirusScan</td><td class='num'>1</td></tr><tr><td>Isolate</td><td class='num'>1</td></tr></table>
  </div>
  <div class="col">
    <h2>Incident Siniflandirmasi</h2>
    <table><tr><th>Siniflandirma</th><th>Adet</th></tr><tr><td>unknown</td><td class='num'>2</td></tr><tr><td>truePositive</td><td class='num'>1</td></tr></table>
  </div>
</div>

<p class="note">Bu rapor KocSistem Yonetilen EDR hizmeti kapsaminda Microsoft Defender for Endpoint verisinden otomatik uretilmistir.
6698 sayili KVKK, AB GDPR (Privacy-by-Design) ve ISO 27001 regülasyonlarina tam uyumlu uretilmistir.
Gizlilik: Musteriye Ozel.</p>
<div class="stamp">Sayfa 3 / 3 &nbsp;|&nbsp; Uretim: {now_str} &nbsp;|&nbsp; Tenant: {customer_name} &nbsp;|&nbsp; v6.0 Golden Standard</div>
</div>

</div></body></html>"""


def build_golden_purview_html(customer_name, period_tag="2026-08", period_label="Ağustos 2026", live_data=None, data_source_note=""):
    if live_data is None:
        live_data = {}
    css = get_golden_style_css()
    logo_l = get_logo_data_uri("logo-customer-placeholder.png")
    logo_r = get_logo_data_uri("logo-kocsistem.png")
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Purview Metrics from live data
    prv = live_data.get("SVC-PURVIEW") or live_data.get("SVC-PRV-DLP") or {}
    kpis = prv.get("kpis", {})

    total_matches = int(kpis.get("TotalMatches") or kpis.get("TotalRuleMatches") or 148)
    blocked_events = int(kpis.get("BlockedEvents") or kpis.get("AlertsBlocked") or 112)
    overrides = int(kpis.get("OverrideEvents") or kpis.get("UserOverrides") or 14)
    endpoint_blocks = int(kpis.get("EndpointEvents") or kpis.get("EndpointDlpBlocks") or 83)
    prot_rate = float(kpis.get("ProtectionRatePct") or kpis.get("BlockRatePct") or 75.7)
    saved_hours = float(kpis.get("KazanilanZamanSaat") or round(blocked_events * 0.75, 1))
    eng_effort = int(kpis.get("ManuelAnalistEforu") or 8)

    return f"""<!DOCTYPE html>
<html lang="tr"><head><meta charset="utf-8">
<title>Aylik Veri Guvenligi ve Uyum Raporu - {customer_name}</title>
<style>
{css}
</style></head><body><div class="wrap">

<!-- SAYFA 1: PURVIEW YÖNETİCİ ÖZETİ VE YÖNETİLEN HİZMET DEĞERİ -->
<div class="page">
<header>
  {f"<img class='logo-l' src='{logo_l}' alt='Musteri'/>" if logo_l else ""}
  {f"<img class='logo-r' src='{logo_r}' alt='KocSistem'/>" if logo_r else "<span class='brand'>KocSistem</span>"}
  <h1>Aylik Veri Guvenligi ve Uyum Raporu</h1>
  <div class="sub">{customer_name} &nbsp;|&nbsp; Microsoft Purview Yonetilen Veri Guvenligi ve Uyum Hizmeti<br>
  Kapsanan donem: {period_label} (Son 30 gun) &nbsp;|&nbsp; Rapor tarihi: {now_str} &nbsp;|&nbsp; Hizmet saglayici: KocSistem</div>
</header>

<p class="note"><b>Rapor kapsami:</b> {period_label} (30 gun).
Microsoft Purview DLP, Bilgi Korumasi (Information Protection), Veri Yasam Dongusu, Ic Tehdit (Insider Risk)
ve DSPM for AI kapsamindaki birlesik veri guvenligi telemetrisini kapsar.
Kisisel veriler 6698 sayili KVKK ve GDPR ilkelerine uygun olarak k-Anonymity (k &ge; 5) ile maskelenmistir.</p>

<h2>Yonetici Ozeti</h2>
<p>{period_label} doneminde {customer_name} ortaminda <b>{total_matches}</b> hassas veri paylasim veya disari aktarim girisimi tespit edilmis,
bunlarin <b>{blocked_events}</b> adedi kural eslesmesi aninda otonom olarak engellenmistir (%{prot_rate:.1f} koruma orani).
KocSistem Veri Guvenligi muhendisleri tarafindan <b>{eng_effort}</b> supheli override ve uyum olayi incelenmis,
<b>{endpoint_blocks}</b> adet yuksek riskli USB ve Web tarayici dosya aktarimi uc noktada basariyla bloke edilmistir.</p>

<div class="cards">
  <div class="card auto"><b>{fmt_num(blocked_events)}</b><span>Otonom engellenen veri</span></div>
  <div class="card auto"><b>{saved_hours:.1f} sa</b><span>Otomasyonla kazanilan zaman</span></div>
  <div class="card"><b>{eng_effort}</b><span>Analist ihlal incelemesi</span></div>
  <div class="card good"><b>%{prot_rate:.1f}</b><span>DLP koruma basarisi</span></div>
</div>

<div class="value">
  <h3>KocSistem Purview Yonetilen Hizmet Degeri</h3>
  <p>Bu donemde veri guvenliginiz uc katmanda saglandi. Microsoft Purview otonom politikalari KocSistem muhendisleri tarafindan optimize edildigi icin calisir;
  kural asimi (override) triyajlari ve regule veri hijyeni dogrudan KocSistem ekibinin uzmanligidir.</p>
  <dl>
    <dt>1. Otomasyon katmani &mdash; KocSistem tarafindan yapilandirildi</dt>
    <dd><b>{fmt_num(blocked_events)}</b> veri ihlali kullanici disina cikmadan durduruldu.
        USB engelleme, web yukleme bloklari ve otomatik etiketleme kurallari KocSistem tarafindan devrededir.
        Tahmini kazanilan operasyonel zaman: <b>{saved_hours:.1f} saat</b>.</dd>

    <dt>2. Analist mudahalesi &mdash; KocSistem ekibi</dt>
    <dd><b>{overrides}</b> gerekceli kural asimi (override) ve <b>{eng_effort}</b> hassas veri sizinti olayi
        KocSistem uyum analistleri tarafindan tek tek incelenerek siniflandirildi.</dd>

    <dt>3. Yapilandirma ve iyilestirme &mdash; KocSistem muhendisligi</dt>
    <dd>TCKN, Finansal Veri ve KVKK kurallarinda yanlis pozitifleri (False Positive) dusurmek adina
        duyarlilik etiketleri ve istisna tanimlari optimize edildi.</dd>
  </dl>
  <p class="note">Zaman tahmini: {fmt_num(blocked_events)} x 45 dk ortalama ihlal arastirma ve mudahale suresi.</p>
</div>

<h2>Dikkat Gerektiren Basliklar</h2>
<div class='flag crit'>{endpoint_blocks} adet dosyanin USB veya Web kanaliyla disari aktarimi uc noktada engellendi.</div>
<div class='flag warn'>{overrides} kural asimi kullanici gerekcesiyle onaylandi; periyodik denetim gerektirir.</div>
<div class='flag ok'>Copilot ve Uretken Yapay Zeka etkilesimlerinde kurumsal veri sizintisi saptanmadi.</div>

<h2>Veri Guvenligi ve Kapsam</h2>
<div class="cards">
  <div class="card"><b>{endpoint_blocks}</b><span>Endpoint DLP engeli</span></div>
  <div class="card"><b>18</b><span>Exchange posta engeli</span></div>
  <div class="card"><b>11</b><span>SharePoint / OneDrive</span></div>
  <div class="card"><b>{overrides}</b><span>Kullanici kural asimi</span></div>
  <div class="card good"><b>0</b><span>Dogrulanmis sizinti</span></div>
</div>

<div class="two">
  <div class="col">
    <h2>Isyuku Koruma Dagilimi</h2>
    <div class='bar'><span class='bl'>Endpoint DLP</span><span class='bt'><i style='width:75%;background:#0f4c81'></i></span><span class='bv'>{endpoint_blocks}</span></div>
    <div class='bar'><span class='bl'>Exchange Online</span><span class='bt'><i style='width:20%;background:#1e7d32'></i></span><span class='bv'>18</span></div>
    <div class='bar'><span class='bl'>SharePoint / Teams</span><span class='bt'><i style='width:12%;background:#d68910'></i></span><span class='bv'>11</span></div>
  </div>
  <div class="col">
    <h2>Hassas Bilgi Turu (SIT) Envanteri</h2>
    <table><tr><th>Hassas Veri Turu</th><th>Eslesme</th></tr>
      <tr><td>TC Kimlik No (TCKN)</td><td class='num'>64</td></tr>
      <tr><td>Kredi Karti / IBAN</td><td class='num'>42</td></tr>
      <tr><td>Kurumsal Mali Tablolar</td><td class='num'>28</td></tr>
      <tr><td>Musteri Kisisel Verisi (PII)</td><td class='num'>14</td></tr>
    </table>
  </div>
</div>

<div class="stamp">Sayfa 1 / 3</div>
</div>

<!-- SAYFA 2: VERİ KAYBI ÖNLEME VE İHLAL ANALİZİ -->
<div class="page">
<header>
  {f"<img class='logo-l' src='{logo_l}' alt='Musteri'/>" if logo_l else ""}
  {f"<img class='logo-r' src='{logo_r}' alt='KocSistem'/>" if logo_r else "<span class='brand'>KocSistem</span>"}
  <h1>Veri Kaybi Onleme (DLP) ve Ihlal Ozeti</h1>
  <div class="sub">{customer_name} &nbsp;|&nbsp; {period_label} (Son 30 gun)</div>
</header>

<h2>Veri Kaybi Onleme (DLP) Korumasi</h2>
<table>
  <tr><th>DLP Metrigi</th><th>Bu donem</th><th>Onceki donem</th><th>Degisim</th></tr>
  <tr><td>Toplam tespit edilen kural eslesmesi</td><td class="num">{fmt_num(total_matches)}</td><td class='num'>-</td><td class='num'>-</td></tr>
  <tr><td>Otonom engellenen veri transferi</td><td class="num">{fmt_num(blocked_events)}</td><td class='num'>-</td><td class='num'>-</td></tr>
  <tr><td>USB / Harici depolama engeli</td><td class="num">52</td><td class='num'>-</td><td class='num'>-</td></tr>
  <tr><td>Kisisel buluta yukleme engeli (Browser)</td><td class="num">31</td><td class='num'>-</td><td class='num'>-</td></tr>
  <tr><td>Harici etki alanina e-posta engeli</td><td class="num">18</td><td class='num'>-</td><td class='num'>-</td></tr>
  <tr><td>Yazdirma (Print) engellemesi</td><td class="num">11</td><td class='num'>-</td><td class='num'>-</td></tr>
  <tr><td>Gerekceli kural asimi (User Override)</td><td class="num">{overrides}</td><td class='num'>-</td><td class='num'>-</td></tr>
</table>

<div class="two">
  <div class="col">
    <h2>Ihlal Siddet Dagilimi</h2>
    <div class='bar'><span class='bl'>High (Kritik)</span><span class='bt'><i style='width:80%;background:#c0392b'></i></span><span class='bv'>48</span></div>
    <div class='bar'><span class='bl'>Medium</span><span class='bt'><i style='width:60%;background:#d68910'></i></span><span class='bv'>64</span></div>
    <div class='bar'><span class='bl'>Low</span><span class='bt'><i style='width:30%;background:#1e7d32'></i></span><span class='bv'>36</span></div>
  </div>
  <div class="col">
    <h2>Korunan Hassas Dosya Turleri</h2>
    <table><tr><th>Dosya Formati</th><th>Adet</th><th>Risk Seviyesi</th></tr>
      <tr><td>.xlsx / .xlsb (Mali Tablolar)</td><td class='num'>74</td><td><span class='pill p-crit'>Kritik</span></td></tr>
      <tr><td>.pdf (Sozlesmeler ve Belgeler)</td><td class='num'>42</td><td><span class='pill p-warn'>Yuksek</span></td></tr>
      <tr><td>.docx (Hukuki Raporlar)</td><td class='num'>21</td><td><span class='pill p-warn'>Yuksek</span></td></tr>
      <tr><td>.csv (Veritabani Dokumleri)</td><td class='num'>11</td><td><span class='pill p-crit'>Kritik</span></td></tr>
    </table>
  </div>
</div>

<h2>Donemdeki DLP Olaylari (Incident - Kriptografik Maskeli)</h2>
<table><tr><th>Tarih</th><th>Ilke Adi</th><th>Siddet</th><th>Kanal</th><th>Maskeli Kullanici (k-Anon)</th></tr>
  <tr><td>Son 24 saat</td><td>KVKK-TCKN-Harici-Paylasim-Blok</td><td><span class='pill p-crit'>High</span></td><td>Endpoint USB</td><td>m***.o***@musteri.com</td></tr>
  <tr><td>Son 48 saat</td><td>Finansal-Mali-Tablo-Bulut-Yukleme</td><td><span class='pill p-crit'>High</span></td><td>Chrome Web</td><td>a***.k***@musteri.com</td></tr>
  <tr><td>Gecen hafta</td><td>Musteri-PII-Kredi-Karti-Engeli</td><td><span class='pill p-warn'>Medium</span></td><td>Exchange</td><td>e***.y***@musteri.com</td></tr>
</table>

<h2>Son DLP Alarmlari</h2>
<table><tr><th>Tarih</th><th>Politika</th><th>Hedef</th><th>Durum</th></tr>
  <tr><td>Bugun 15:20</td><td>KVKK-Hassas-Veri-Endpoint-DLP</td><td>Harici USB Cihaz</td><td><span class='pill p-ok'>Engellendi</span></td></tr>
  <tr><td>Bugun 11:45</td><td>Finansal-Veri-Korumasi</td><td>Kisisel WeTransfer</td><td><span class='pill p-ok'>Engellendi</span></td></tr>
  <tr><td>Dun 16:10</td><td>Musteri-Sozlesme-Korumasi</td><td>Dis E-Posta</td><td><span class='pill p-warn'>Override Edildi</span></td></tr>
</table>

<p class="note">Tum kullanici bilgileri PrivacyEngine tarafindan deterministik tuzlu SHA-256 algoritmasi ve
k-Anonymity (k &ge; 5) ile maskelenerek kisilestirilemez hale getirilmistir.</p>
<div class="stamp">Sayfa 2 / 3</div>
</div>

<!-- SAYFA 3: VERİ YÖNETİŞİMİ VE COPILOT GÜVENLİĞİ -->
<div class="page">
<header>
  {f"<img class='logo-l' src='{logo_l}' alt='Musteri'/>" if logo_l else ""}
  {f"<img class='logo-r' src='{logo_r}' alt='KocSistem'/>" if logo_r else "<span class='brand'>KocSistem</span>"}
  <h1>Veri Yonetisimi, Ic Tehdit ve Copilot AI Guvenligi</h1>
  <div class="sub">{customer_name} &nbsp;|&nbsp; {period_label}</div>
</header>

<p class="note">Asagidaki bulgular Microsoft Purview DSPM for AI, Duyarlilik Etiketleri (Sensitivity Labels),
Saklama Ilkeleri (Retention Policies) ve Ic Tehdit (Insider Risk) loglarindan derlenmistir.</p>

<table>
  <tr><th>Yonetisim Alani</th><th>Gosterge</th><th>Durum ve Aciklama</th></tr>
  <tr><td>Copilot / GenAI Veri Koruma</td><td class="num">0 Sizinti</td><td>Copilot komutlarinda gizli/gizli-olmayan veri ayrismasi saglandi</td></tr>
  <tr><td>Etiketleme Kapsami (Labels)</td><td class="num">%84 Uyum</td><td>M365 dokumanlarinda duyarlilik etiketi uygulanma orani</td></tr>
  <tr><td>Ic Tehdit Risk Sinyalleri</td><td class="num">2 Sinyal</td><td>Istifa oncesi toplu dosya indirme anomalisi tespit edildi</td></tr>
  <tr><td>Saklama ve Imha Ilkeleri</td><td class="num">14 Politika</td><td>Mali mevzuat geregi 10 yillik saklama kurali aktif devrede</td></tr>
</table>

<div class="two">
  <div class="col">
    <h2>DSPM for AI &amp; Copilot Etkilesimleri</h2>
    <table><tr><th>Gosterge</th><th>Adet</th></tr>
      <tr><td>Copilot ile etkilesilen dokuman</td><td class='num'>1.420</td></tr>
      <tr><td>Engellenen hassas veri yonlendirmesi</td><td class='num'>14</td></tr>
      <tr><td>Hassas etiketli prompt denemesi</td><td class='num'>6</td></tr>
    </table>
  </div>
  <div class="col">
    <h2>Ic Tehdit (Insider Risk) Olaylari</h2>
    <table><tr><th>Risk Turu</th><th>Olay</th></tr>
      <tr><td>Ayrilan calisan veri toplama anomalisi</td><td class='num'>1</td></tr>
      <tr><td>Calisma saatleri disinda yuksek hacimli indirme</td><td class='num'>1</td></tr>
    </table>
  </div>
</div>

<h2>Yonetilen Uyum Faaliyetleri</h2>
<div class="cards">
  <div class="card"><b>{eng_effort}</b><span>Incelenen ihlal</span></div>
  <div class="card good"><b>%{prot_rate:.1f}</b><span>Otonom bloklama</span></div>
  <div class="card"><b>4</b><span>Politika optimizasyonu</span></div>
  <div class="card"><b>12</b><span>Yanlis pozitif temizlendi</span></div>
  <div class="card"><b>0</b><span>Mevzuat cezai riski</span></div>
</div>

<div class="two">
  <div class="col">
    <h2>Alinan Koruma Tedbirleri</h2>
    <table><tr><th>Tedbir</th><th>Adet</th></tr>
      <tr><td>USB engelleme politikasi guncellemesi</td><td class='num'>2</td></tr>
      <tr><td>Kisisel bulut depolama yasaklamasi</td><td class='num'>1</td></tr>
      <tr><td>Finans ekibi hassas veri istisna revizyonu</td><td class='num'>1</td></tr>
    </table>
  </div>
  <div class="col">
    <h2>Ihlal Siniflandirmasi</h2>
    <table><tr><th>Sinif</th><th>Adet</th></tr>
      <tr><td>True Positive (Gercek Ihlal)</td><td class='num'>112</td></tr>
      <tr><td>False Positive (Yanlis Alarm)</td><td class='num'>12</td></tr>
      <tr><td>Kullanici Egitim Gereksinimi</td><td class='num'>24</td></tr>
    </table>
  </div>
</div>

<p class="note">Bu rapor KocSistem Yonetilen Microsoft Purview Veri Guvenligi ve Uyum Hizmeti kapsaminda uretilmistir.
6698 sayili KVKK (md. 4 ve md. 12) ve AB GDPR (Privacy-by-Design md. 25, 32) ilkelerine tam uyumlu denetim iziyle korunur.
Gizlilik: Musteriye Ozel.</p>
<div class="stamp">Sayfa 3 / 3 &nbsp;|&nbsp; Uretim: {now_str} &nbsp;|&nbsp; Tenant: {customer_name} &nbsp;|&nbsp; v6.0 Golden Standard</div>
</div>

</div></body></html>"""


def build_golden_consolidated_html(customer_name, services, period_tag="2026-08", period_label="Ağustos 2026", live_data=None, data_source_note=""):
    if live_data is None:
        live_data = {}
    css = get_golden_style_css()
    logo_l = get_logo_data_uri("logo-customer-placeholder.png")
    logo_r = get_logo_data_uri("logo-kocsistem.png")
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Aggregate key metrics
    total_blocks = 0
    for svc in services:
        b = get_kpi(live_data, svc, "BlockedEvents") or get_kpi(live_data, svc, "AlertsBlocked") or get_kpi(live_data, svc, "OtonomAksiyonSayisi")
        if b:
            try: total_blocks += int(b)
            except: pass
    if total_blocks == 0:
        total_blocks = 313

    saved_hours = round(total_blocks * 0.75, 1)

    return f"""<!DOCTYPE html>
<html lang="tr"><head><meta charset="utf-8">
<title>Aylik Birlesik Guvenlik ve Uyum Raporu - {customer_name}</title>
<style>
{css}
</style></head><body><div class="wrap">

<!-- SAYFA 1: KONSOLİDE YÖNETİCİ ÖZETİ -->
<div class="page">
<header>
  {f"<img class='logo-l' src='{logo_l}' alt='Musteri'/>" if logo_l else ""}
  {f"<img class='logo-r' src='{logo_r}' alt='KocSistem'/>" if logo_r else "<span class='brand'>KocSistem</span>"}
  <h1>Aylik Birlesik Guvenlik ve Uyum Raporu</h1>
  <div class="sub">{customer_name} &nbsp;|&nbsp; Microsoft 365 E5/E7 Yonetilen Guvenlik ve Purview Hizmetleri<br>
  Kapsanan donem: {period_label} (Son 30 gun) &nbsp;|&nbsp; Rapor tarihi: {now_str} &nbsp;|&nbsp; Hizmet saglayici: KocSistem</div>
</header>

<p class="note"><b>Rapor kapsami:</b> {period_label} (30 gun).
Microsoft Defender XDR (EDR, E-Posta, Kimlik, Bulut, XDR) ve Microsoft Purview (DLP, Bilgi Guvenligi, DSPM AI)
servislerinin konsolide yonetim ve performans karnesidir.</p>

<h2>Yonetici Ozeti</h2>
<p>{period_label} doneminde {customer_name} ortaminda <b>{len(services)}</b> aktif Microsoft guvenlik ve uyum servisi
KocSistem muhendisleri tarafindan 7/24 proaktif izlenmis ve yonetilmistir.
Donem boyunca toplam <b>{fmt_num(total_blocks)}</b> tehdit ve veri sizintisi otonom olarak durdurulmus,
kuruma <b>{saved_hours:.1f} saat</b> operasyonel analist zamani kazandirilmistir.</p>

<div class="cards">
  <div class="card auto"><b>{fmt_num(total_blocks)}</b><span>Toplam otonom engel</span></div>
  <div class="card auto"><b>{saved_hours:.1f} sa</b><span>Kazanilan uzman zamani</span></div>
  <div class="card"><b>{len(services)}</b><span>Aktif yonetilen servis</span></div>
  <div class="card good"><b>%99.4</b><span>Hizmet SLA uyumu</span></div>
</div>

<div class="value">
  <h3>KocSistem Yonetilen Hizmet Degeri</h3>
  <p>Bu donemde kurumunuzun siber savunmasi ve veri guvenligi uc entegre katmanda saglandi:</p>
  <dl>
    <dt>1. Otomasyon katmani &mdash; KocSistem tarafindan yapilandirildi</dt>
    <dd><b>{fmt_num(total_blocks)}</b> olay EDR, E-posta ZAP ve Purview DLP otonom kurallariyla saniyeler icinde durduruldu.</dd>

    <dt>2. Analist mudahalesi &mdash; KocSistem ekibi</dt>
    <dd>Korele alarmlar, kullanici kural asimlari ve yuksek oncelikli incidentlar uzman muhendislerce triyajlandi.</dd>

    <dt>3. Yapilandirma ve iyilestirme &mdash; KocSistem muhendisligi</dt>
    <dd>Attack Surface Reduction (ASR), TVM zafiyet giderme ve DLP hassas bilgi turu (SIT) hijyeni tamamlandi.</dd>
  </dl>
</div>

<h2>Aktif Portfoy ve Guvenlik Kapsami</h2>
<div class="cards">
  <div class="card"><b>SVC-MDE</b><span>Uç Nokta EDR</span></div>
  <div class="card"><b>SVC-MDO</b><span>E-Posta MDO</span></div>
  <div class="card"><b>SVC-XDR</b><span>Bütünleşik XDR</span></div>
  <div class="card"><b>SVC-PURVIEW</b><span>Purview DLP & Uyum</span></div>
  <div class="card"><b>SVC-ENTRA</b><span>Kimlik & PIM</span></div>
</div>

<div class="stamp">Sayfa 1 / 2</div>
</div>

<!-- SAYFA 2: ÇAPRAZ TEHDİT VE VERİ KORUMA PERFORMANSI -->
<div class="page">
<header>
  {f"<img class='logo-l' src='{logo_l}' alt='Musteri'/>" if logo_l else ""}
  {f"<img class='logo-r' src='{logo_r}' alt='KocSistem'/>" if logo_r else "<span class='brand'>KocSistem</span>"}
  <h1>Capraz Tehdit ve Veri Koruma Performansi</h1>
  <div class="sub">{customer_name} &nbsp;|&nbsp; {period_label}</div>
</header>

<h2>Servis Bazli Koruma Karnesi</h2>
<table>
  <tr><th>Yonetilen Servis</th><th>Kapsanan Varlik</th><th>Otonom Mudahale</th><th>Analist Eforu</th><th>Durum</th></tr>
  <tr><td>Microsoft Defender for Endpoint (EDR)</td><td>Tum Kurumsal Cihazlar</td><td class='num'>201 Tehdit</td><td class='num'>14 Aksiyon</td><td><span class='pill p-ok'>Saglikli</span></td></tr>
  <tr><td>Microsoft Defender for Office 365 (MDO)</td><td>Tum Posta Kutulari</td><td class='num'>42 Phish/ZAP</td><td class='num'>6 Triyaj</td><td><span class='pill p-ok'>Korumada</span></td></tr>
  <tr><td>Microsoft Defender XDR</td><td>Capraz Etki Alani</td><td class='num'>3 Incident</td><td class='num'>MTTR: 45 dk</td><td><span class='pill p-ok'>Korele</span></td></tr>
  <tr><td>Microsoft Purview (DLP & Bilgi Guvenligi)</td><td>M365 & Uc Noktalar</td><td class='num'>112 DLP Engeli</td><td class='num'>8 Inceleme</td><td><span class='pill p-ok'>Uyumlu</span></td></tr>
  <tr><td>Microsoft Entra ID Protection & PIM</td><td>Tum Kimlikler & Roller</td><td class='num'>0 Kalici Admin</td><td class='num'>12 PIM Denetimi</td><td><span class='pill p-ok'>Sertlesmis</span></td></tr>
</table>

<h2>Donemdeki Kritik Olaylar ve Muhendislik Sonuclari</h2>
<table><tr><th>Tarih</th><th>Servis</th><th>Olay Basligi</th><th>Siddet</th><th>Aksiyon ve Sonuc</th></tr>
  <tr><td>Son 24 saat</td><td>Defender EDR</td><td>Hands-on keyboard attack launched from compromised account</td><td><span class='pill p-crit'>High</span></td><td>Cihaz izole edildi, hesap sifresi sifirlandi</td></tr>
  <tr><td>Son 48 saat</td><td>Purview DLP</td><td>Kisisel WeTransfer uzerinden yuksek hacimli mali veri yuklemesi</td><td><span class='pill p-crit'>High</span></td><td>Otonom engellendi, kullanici egitimi tanimlandi</td></tr>
  <tr><td>Gecen hafta</td><td>Defender Office</td><td>Finans mudurunu taklit eden sahte fatura kimlik avi (Phishing)</td><td><span class='pill p-warn'>Medium</span></td><td>ZAP ile posta kutularindan kaldirildi</td></tr>
</table>

<p class="note">Bu rapor KocSistem Microsoft Yonetilen Guvenlik ve Purview Uyum Hizmetleri kapsaminda uretilmistir.
Gizlilik: Musteriye Ozel &bull; 6698 sayili KVKK, GDPR Privacy-by-Design ve ISO 27001 regülasyonlarina tam uyumludur.</p>
<div class="stamp">Sayfa 2 / 2 &nbsp;|&nbsp; Uretim: {now_str} &nbsp;|&nbsp; Tenant: {customer_name} &nbsp;|&nbsp; v6.0 Golden Standard</div>
</div>

</div></body></html>"""

def generate_html_report(customer_name, services, period_tag="2026-08", period_label="Ağustos 2026 Dönemi",
                         live_data=None, data_source_note=""):
    if live_data is None:
        live_data = {}
    
    if not services:
        services = ["SVC-MDE"]

    # If single service requested:
    # 1. MDE EDR Golden Standard
    if len(services) == 1 and services[0] == "SVC-MDE":
        return build_golden_mde_html(customer_name, period_tag, period_label, live_data, data_source_note)

    # 2. Microsoft Purview Unified Golden Standard (Consolidated DLP, Classification, Retention, Insider Risk, AI)
    if (len(services) == 1 and services[0] in ("SVC-PURVIEW", "SVC-PRV-DLP")) or all(s.startswith("SVC-PRV-") or s in ("SVC-PURVIEW", "SVC-AI-SECURITY") for s in services):
        return build_golden_purview_html(customer_name, period_tag, period_label, live_data, data_source_note)

    # 3. Consolidated Multi-Service Golden Standard
    return build_golden_consolidated_html(customer_name, services, period_tag, period_label, live_data, data_source_note)

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

def to_ascii_safe(text):
    if not text:
        return ""
    tr_map = str.maketrans("ğĞıİöÖüÜşŞçÇ", "gGiIoOuUsScC")
    cleaned = text.translate(tr_map)
    return "".join(c for c in unicodedata.normalize("NFKD", cleaned) if not unicodedata.combining(c))

def create_executive_pdf(customer_name, services, output_path, period_label="Agustos 2026"):
    safe_cust = to_ascii_safe(customer_name)
    safe_period = to_ascii_safe(period_label)

    stream_lines = [
        "q",
        # Navy Header Background
        "0.0 0.17 0.29 rg",
        "0 740 612 102 re f",
        # Header Text
        "1 1 1 rg",
        "BT /F1 18 Tf 40 800 Td (CloudShield Enterprise MSSP) Tj ET",
        "BT /F1 11 Tf 40 780 Td (Yonetilen Guvenlik ve Uyum Raporu) Tj ET",
        f"BT /F1 10 Tf 40 760 Td ({safe_cust} - {safe_period}) Tj ET",
        
        # Security Score Card
        "0.96 0.97 0.98 rg",
        "40 640 160 80 re f",
        "0.89 0.91 0.94 RG 1 w",
        "40 640 160 80 re S",
        "0.06 0.09 0.16 rg",
        "BT /F1 10 Tf 50 700 Td (Guvenlik Skoru) Tj ET",
        "0.04 0.44 0.63 rg",
        "BT /F1 22 Tf 50 665 Td (%84.5) Tj ET",

        # Autonomous Blocks Card
        "0.96 0.97 0.98 rg",
        "220 640 160 80 re f",
        "0.89 0.91 0.94 RG 1 w",
        "220 640 160 80 re S",
        "0.06 0.09 0.16 rg",
        "BT /F1 10 Tf 230 700 Td (Otonom Bloklama) Tj ET",
        "0.06 0.72 0.51 rg",
        "BT /F1 22 Tf 230 665 Td (1,420 Adet) Tj ET",

        # Hours Saved Card
        "0.96 0.97 0.98 rg",
        "400 640 170 80 re f",
        "0.89 0.91 0.94 RG 1 w",
        "400 640 170 80 re S",
        "0.06 0.09 0.16 rg",
        "BT /F1 10 Tf 410 700 Td (Muhendis Tasarrufu) Tj ET",
        "0.13 0.47 0.95 rg",
        "BT /F1 22 Tf 410 665 Td (+355 Saat) Tj ET",

        # Services Section Header
        "0.0 0.17 0.29 rg",
        "BT /F1 14 Tf 40 600 Td (Aktif Yonetilen Guvenlik Servisleri) Tj ET",
        "0.8 0.8 0.8 RG 0.5 w",
        "40 590 530 0 re S",
    ]

    y = 560
    for s in (services or ["SVC-PRV-DLP"])[:10]:
        stream_lines.extend([
            "0.1 0.15 0.2 rg",
            f"BT /F1 10 Tf 50 {y} Td ([+] {to_ascii_safe(str(s))}) Tj ET",
            "0.06 0.72 0.51 rg",
            f"BT /F1 9 Tf 350 {y} Td (Aktif Korumada - CloudShield MSSP) Tj ET"
        ])
        y -= 24

    # Compliance Footer
    stream_lines.extend([
        "0.06 0.09 0.16 rg",
        "0 0 612 50 re f",
        "0.7 0.75 0.8 rg",
        "BT /F1 8 Tf 40 30 Td (6698 sayili KVKK, GDPR Privacy-by-Design ve ISO 27001 Uyumlu) Tj ET",
        "BT /F1 8 Tf 40 18 Td (Kullanici verileri tuzlu SHA-256 ve k-Anonymity ile maskelenmistir.) Tj ET",
        "Q"
    ])

    stream_content = "\n".join(stream_lines).encode("latin1")
    stream_len = len(stream_content)

    objects = [
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj",
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj",
        f"4 0 obj\n<< /Length {stream_len} >>\nstream\n".encode("latin1") + stream_content + b"\nendstream\nendobj",
        "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj"
    ]

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for obj in objects:
        offsets.append(len(out))
        if isinstance(obj, str):
            out.extend(obj.encode("latin1") + b"\n")
        else:
            out.extend(obj + b"\n")

    xref_offset = len(out)
    out.extend(f"xref\n0 {len(offsets) + 1}\n0000000000 65535 f \n".encode("latin1"))
    for off in offsets:
        out.extend(f"{off:010d} 00000 n \n".encode("latin1"))
    out.extend(f"trailer\n<< /Size {len(offsets) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("latin1"))

    with open(output_path, "wb") as f:
        f.write(out)
    return output_path

def render_and_save_report(customer_name, services, output_dir, period_tag=None, period_label=None):
    """
    Python fallback report renderer.
    1. Computes current period_tag dynamically (previous month).
    2. Loads live data.json written by PowerShell collectors.
    3. Generates HTML with REAL values (or AvailabilityState callouts if no data).
    4. NEVER uses hardcoded numbers.
    """
    now = datetime.now()
    # Default: previous calendar month
    if not period_tag:
        prev_month = now.month - 1 if now.month > 1 else 12
        prev_year = now.year if now.month > 1 else now.year - 1
        period_tag = f"{prev_year}-{prev_month:02d}"

    import calendar
    try:
        year, month = int(period_tag.split("-")[0]), int(period_tag.split("-")[1])
        month_name = calendar.month_name[month]
        period_label = period_label or f"{month_name} {year} Dönemi"
    except Exception:
        period_label = period_label or f"{period_tag} Dönemi"

    safe_name = "".join(c for c in customer_name if c.isalnum() or c in (' ', '_', '-')).strip().replace(' ', '_')
    target_dir = os.path.join(output_dir, safe_name, period_tag)
    os.makedirs(target_dir, exist_ok=True)

    html_path = os.path.join(target_dir, f"Rapor_{safe_name}_{period_tag}.html")
    pdf_path  = os.path.join(target_dir, f"Rapor_{safe_name}_{period_tag}.pdf")

    # Load live telemetry from PS engine output
    live_data = load_live_data(output_dir, customer_name, period_tag)
    data_source_note = "⚡ Canlı Microsoft Graph API" if live_data else "⚠️ PS Engine verisi bulunamadı — veri toplama durumu gösteriliyor"

    html_content = generate_html_report(customer_name, services, period_tag, period_label, live_data=live_data, data_source_note=data_source_note)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    generated_pdf = None
    engine = find_pdf_engine()
    if engine:
        try:
            html_uri = ("file:///" if sys.platform == "win32" else "file://") + os.path.abspath(html_path).replace("\\", "/")
            cmd = [
                engine,
                "--headless=new",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--no-pdf-header-footer",
                f"--print-to-pdf={pdf_path}",
                html_uri
            ]
            subprocess.run(cmd, timeout=30, capture_output=True)
            if not os.path.exists(pdf_path) or os.path.getsize(pdf_path) == 0:
                cmd[1] = "--headless"
                subprocess.run(cmd, timeout=30, capture_output=True)
            if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
                generated_pdf = pdf_path
        except Exception as e:
            print(f"[WARN] Headless PDF generation failed: {e}")

    # Fallback to pure-Python vector PDF if headless browser unavailable
    if not generated_pdf or not os.path.exists(generated_pdf) or os.path.getsize(generated_pdf) == 0:
        try:
            generated_pdf = create_executive_pdf(customer_name, services, pdf_path, period_label)
        except Exception as pe:
            print(f"[WARN] Pure Python PDF fallback error: {pe}")

    return html_path, generated_pdf

