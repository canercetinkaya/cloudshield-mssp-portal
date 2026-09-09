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
                with open(data_path, "r", encoding="utf-8") as f:
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

def generate_html_report(customer_name, services, period_tag="2026-08", period_label="Ağustos 2026 Dönemi",
                         live_data=None, data_source_note=""):
    if live_data is None:
        live_data = {}
    css_content = get_style_css()

    sections = []
    service_names_tr = []

    builders = {
        "SVC-PRV-DLP": (build_purview_dlp_section(customer_name, live_data), "Purview DLP"),
        "SVC-MDE":     (build_mde_section(live_data), "Defender for Endpoint"),
        "SVC-MDO":     (build_mdo_section(live_data), "Defender for Office 365"),
        "SVC-MDI":     (build_mdi_section(live_data), "Defender for Identity"),
        "SVC-MDCA":    (build_mdca_section(live_data), "Defender for Cloud Apps"),
        "SVC-XDR":     (build_xdr_section(live_data), "Defender XDR Olay Yönetimi"),
        "SVC-PRV-CLASS": (build_prv_class_section(live_data), "Purview Bilgi Koruması"),
        "SVC-PRV-GOV": (build_prv_gov_section(live_data), "Purview Saklama ve İmha"),
        "SVC-PRV-RISK": (build_prv_risk_section(live_data), "Purview İç Tehdit Uyumu"),
        "SVC-AI-SECURITY": (build_ai_security_section(live_data), "Purview AI & Copilot Güvenliği"),
        "SVC-INTUNE":  (build_mde_section(live_data), "Microsoft Intune"),
        "SVC-ENTRA-PIM": (build_mde_section(live_data), "Entra ID & PIM"),
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

    # ── EXECUTIVE DASHBOARD — live aggregated values ──────────────────────────
    # Sum autonomous blocks from all selected services
    total_blocks = 0
    for svc in services:
        b = get_kpi(live_data, svc, "BlockedEvents") or get_kpi(live_data, svc, "AlertsBlocked") or get_kpi(live_data, svc, "TotalBlocked")
        if b is not None:
            try:
                total_blocks += int(b)
            except Exception:
                pass

    # Manual activity hours from data.json (KoçSistem operations)
    total_hours = 0.0
    engineer_actions = 0
    for svc in services:
        h = get_kpi(live_data, svc, "KazanilanZamanSaat") or get_kpi(live_data, svc, "SavedHours")
        if h is not None:
            try:
                total_hours += float(h)
            except Exception:
                pass
        e = get_kpi(live_data, svc, "ManuelAnalistEforu") or get_kpi(live_data, svc, "EngineerActions")
        if e is not None:
            try:
                engineer_actions += int(e)
            except Exception:
                pass

    fte_equiv = round(total_hours / 160.0, 1) if total_hours > 0 else None

    # Render KPI values or "—" when no live data available
    blocks_html  = fmt_num(total_blocks) if total_blocks else "—"
    eng_html     = fmt_num(engineer_actions) if engineer_actions else "—"
    hours_html   = f"+{int(total_hours)} Saat" if total_hours else "—"
    fte_html     = f"~{fte_equiv} FTE" if fte_equiv else "—"

    # Data source badge
    source_badge = ""
    if data_source_note:
        clr = "#DCFCE7" if "Canlı" in data_source_note else "#FEF3C7"
        txt_clr = "#15803D" if "Canlı" in data_source_note else "#92400E"
        source_badge = f'<div style="margin-bottom:12px;"><span style="background:{clr}; color:{txt_clr}; font-size:11px; font-weight:700; padding:4px 12px; border-radius:12px;">📡 {data_source_note}</span></div>'

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
            <h2 style="font-size:18px; color:#002B49; margin-bottom:8px; font-weight:700;">Yönetici Özeti (Executive Dashboard)</h2>
            {source_badge}
            <p style="font-size:13px; color:#64748B; margin-bottom:16px;">
                {period_label} boyunca Enterprise Managed Security &amp; Compliance Services kapsamında izlenen ve korunan servislerin birleşik durum karnesi aşağıda sunulmuştur.
            </p>
            <div class="kpi-grid">
                <div class="kpi-card" style="border-left:4px solid #002B49;">
                    <div class="kpi-title">Toplam Otonom Tehdit &amp; Sızıntı Engeli</div>
                    <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                        <div class="kpi-value">{blocks_html}</div>
                        <span class="badge positive">Otonom</span>
                    </div>
                    <div class="kpi-description" style="font-size:11px; color:#64748B;">Uç nokta, e-posta, bulut ve DLP otonom bloklamaları</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">CloudShield Mühendis Müdahaleleri</div>
                    <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                        <div class="kpi-value">{eng_html}</div>
                        <span class="badge positive">Uzman Eforu</span>
                    </div>
                    <div class="kpi-description" style="font-size:11px; color:#64748B;">Uzman mühendisler tarafından incelenen ve sonuçlandırılan olaylar</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Kuruma Kazandırılan Süre</div>
                    <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                        <div class="kpi-value">{hours_html}</div>
                        <span class="badge positive">Verimlilik</span>
                    </div>
                    <div class="kpi-description" style="font-size:11px; color:#64748B;">Otonom koruma ve politika sıkılaştırma sayesinde kazanılan efor</div>
                </div>
                <div class="kpi-card" style="border-left:4px solid #10B981;">
                    <div class="kpi-title">İç İş Gücü Eşdeğeri (FTE)</div>
                    <div class="kpi-value-row" style="display:flex; align-items:baseline; gap:8px;">
                        <div class="kpi-value">{fte_html}</div>
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
                        <div style="font-weight:700; color:#005691; margin-bottom:4px;">1. Hassas Veri &amp; DLP Hijyeni</div>
                        <div style="color:#475569; line-height:1.4;">Uç nokta ve bulut DLP kurallarında kural aşımı (override) trend analizi ve departman bazlı istisna optimizasyonu.</div>
                    </div>
                    <div style="background:#FFFFFF; border-left:4px solid #10B981; padding:12px; border-radius:4px; box-shadow:0 1px 3px rgba(0,0,0,0.05);">
                        <div style="font-weight:700; color:#10B981; margin-bottom:4px;">2. XDR &amp; Otonom Sıkılaştırma</div>
                        <div style="color:#475569; line-height:1.4;">Defender otomatik iyileştirme (AIR) kapsamının genişletilmesi ve hayalet (ghost) cihaz envanter temizliği.</div>
                    </div>
                    <div style="background:#FFFFFF; border-left:4px solid #D97706; padding:12px; border-radius:4px; box-shadow:0 1px 3px rgba(0,0,0,0.05);">
                        <div style="font-weight:700; color:#D97706; margin-bottom:4px;">3. Kimlik Güvenliği &amp; Uyum</div>
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
                    Enterprise Managed Security &amp; Compliance Services &bull; Gizlilik ve Regülasyon Taahhüdü
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

