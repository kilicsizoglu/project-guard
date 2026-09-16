use super::report::ScanSummary;
use anyhow::Result;
use chrono::Utc;
use std::fs;
use std::path::Path;

pub struct HtmlReportGenerator;

impl HtmlReportGenerator {
    pub fn generate(summary: &ScanSummary, output_path: &Path) -> Result<()> {
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
        let status_color = if summary.infected_files > 0 { "#ef4444" } else { "#10b981" };
        let status_text = if summary.infected_files > 0 {
            format!("{} TEHDIT TESPIT EDILDI", summary.infected_files)
        } else {
            "SISTEM TEMIZ / TEHDIT BULUNAMADI".to_string()
        };

        let mut threats_rows = String::new();
        for rep in &summary.reports {
            if rep.is_infected {
                for det in &rep.detections {
                    let sev_badge = match det.severity.to_string().as_str() {
                        "CRITICAL" => "<span class='badge badge-critical'>KRITIK</span>",
                        "HIGH" => "<span class='badge badge-high'>YUKSEK</span>",
                        "MEDIUM" => "<span class='badge badge-medium'>ORTA</span>",
                        _ => "<span class='badge badge-suspicious'>SUPHELI</span>",
                    };

                    threats_rows.push_str(&format!(
                        r#"<tr>
                            <td><code>{}</code></td>
                            <td>{}</td>
                            <td><strong>{}</strong></td>
                            <td><span class='engine-tag'>{}</span></td>
                            <td>{}</td>
                            <td>{}</td>
                        </tr>"#,
                        rep.file_path.display(),
                        sev_badge,
                        det.threat_name,
                        det.engine_name,
                        det.details,
                        if rep.quarantined {
                            "<span class='badge badge-quar'>Karantinada</span>"
                        } else {
                            "<span class='badge badge-warn'>Karantinaya Alinmadi</span>"
                        }
                    ));
                }
            }
        }

        if threats_rows.is_empty() {
            threats_rows = r#"<tr><td colspan="6" style="text-align: center; color: #10b981; padding: 25px;">
                Taranan hicbir dosyada zararli yazilim veya supheli desen tespit edilmedi. Sistem guvende.
            </td></tr>"#.to_string();
        }

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Project Guard - Guvenlik Tarama Raporu</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: rgba(30, 41, 59, 0.7);
            --border-color: rgba(255, 255, 255, 0.1);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-cyan: #06b6d4;
            --danger: #ef4444;
            --success: #10b981;
            --warning: #f59e0b;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{
            background-color: var(--bg-color);
            color: var(--text-main);
            padding: 30px 20px;
            background-image: radial-gradient(at 0% 0%, rgba(6, 182, 212, 0.15) 0px, transparent 50%),
                              radial-gradient(at 100% 100%, rgba(239, 68, 68, 0.1) 0px, transparent 50%);
            min-height: 100vh;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{ font-size: 26px; color: var(--accent-cyan); display: flex; align-items: center; gap: 10px; }}
        .header .date {{ color: var(--text-muted); font-size: 14px; }}
        .status-banner {{
            background: var(--card-bg);
            border-left: 6px solid {status_color};
            border-radius: 8px;
            padding: 20px 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            backdrop-filter: blur(12px);
        }}
        .status-banner h2 {{ font-size: 22px; color: {status_color}; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 35px;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            backdrop-filter: blur(12px);
            transition: transform 0.2s ease;
        }}
        .stat-card:hover {{ transform: translateY(-3px); }}
        .stat-card .label {{ font-size: 13px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }}
        .stat-card .value {{ font-size: 28px; font-weight: bold; color: var(--text-main); }}
        .table-container {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            backdrop-filter: blur(12px);
        }}
        .table-title {{ padding: 20px; font-size: 18px; border-bottom: 1px solid var(--border-color); color: var(--accent-cyan); }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; }}
        th, td {{ padding: 14px 18px; border-bottom: 1px solid var(--border-color); font-size: 14px; }}
        th {{ background: rgba(15, 23, 42, 0.6); color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 12px; }}
        tr:hover {{ background: rgba(255, 255, 255, 0.02); }}
        code {{ font-family: monospace; background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px; font-size: 13px; color: #38bdf8; word-break: break-all; }}
        .badge {{
            display: inline-block;
            padding: 3px 9px;
            border-radius: 9999px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: #f97316; border: 1px solid #f97316; }}
        .badge-medium {{ background: rgba(234, 179, 8, 0.2); color: #eab308; border: 1px solid #eab308; }}
        .badge-suspicious {{ background: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid #c084fc; }}
        .badge-quar {{ background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; }}
        .badge-warn {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #f59e0b; }}
        .engine-tag {{ background: rgba(6, 182, 212, 0.15); color: #22d3ee; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; }}
        .footer {{ text-align: center; margin-top: 40px; color: var(--text-muted); font-size: 13px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>&#128737; PROJECT GUARD :: GUVENLIK RAPORU</h1>
            <div class="date">Olusturulma: {now}</div>
        </div>

        <div class="status-banner">
            <div>
                <h2>{status_text}</h2>
                <p style="color: var(--text-muted); margin-top: 5px;">Hedef: <code>{}</code></p>
            </div>
            <div style="font-size: 32px;">{}</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">Taranan Dosya</div>
                <div class="value">{}</div>
            </div>
            <div class="stat-card">
                <div class="label">Tespit Edilen Tehdit</div>
                <div class="value" style="color: {status_color};">{}</div>
            </div>
            <div class="stat-card">
                <div class="label">Toplam Veri Hacmi</div>
                <div class="value">{:.2} MB</div>
            </div>
            <div class="stat-card">
                <div class="label">Gecen Sure</div>
                <div class="value">{} ms</div>
            </div>
        </div>

        <div class="table-container">
            <div class="table-title">Tespit Edilen Tehdit Detaylari ve Analiz Sonuclari</div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 30%;">Dosya Yolu</th>
                        <th>Seviye</th>
                        <th>Tehdit Sinifi</th>
                        <th>Tarama Motoru</th>
                        <th>Aciklama / Kural</th>
                        <th>Aksiyon</th>
                    </tr>
                </thead>
                <tbody>
                    {threats_rows}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Project Guard Multi-Engine Antivirus & Threat Hunting Platform &bull; Guvenlik Denetim Ciktisi
        </div>
    </div>
</body>
</html>"#,
            summary.target_path,
            if summary.infected_files > 0 { "&#9888;" } else { "&#9989;" },
            summary.scanned_files,
            summary.infected_files,
            summary.total_bytes as f64 / (1024.0 * 1024.0),
            summary.elapsed_ms
        );

        fs::write(output_path, html)?;
        Ok(())
    }
}
