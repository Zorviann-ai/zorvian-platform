"""Professional HTML email presentation for Caelomere Core.

All Core-generated email should pass through this renderer so recipients never
receive raw developer/system copy. Client mail can provide client_name while
Caelomere remains the discreet technology provider in the footer.
"""
from html import escape

GOLD = "#C9A45C"
BG = "#0B0B0B"
PANEL = "#151515"
TEXT = "#F5F1E8"
MUTED = "#A9A39A"


def render_email(*, title: str, body: str, client_name: str = "Caelomere", cta_label: str | None = None, cta_url: str | None = None, preheader: str = "") -> str:
    brand = escape(client_name.strip() or "Caelomere")
    safe_title = escape(title)
    paragraphs = "".join(
        f'<p style="margin:0 0 16px;color:#262626;font-size:16px;line-height:1.65">{escape(p)}</p>'
        for p in body.split("\n") if p.strip()
    )
    cta = ""
    if cta_label and cta_url:
        cta = f'''<table role="presentation" cellspacing="0" cellpadding="0" style="margin:26px 0"><tr><td style="background:{BG};border-radius:6px"><a href="{escape(cta_url, quote=True)}" style="display:inline-block;padding:13px 22px;color:{GOLD};font-weight:700;text-decoration:none;border:1px solid {GOLD};border-radius:6px">{escape(cta_label)}</a></td></tr></table>'''
    return f'''<!doctype html><html><body style="margin:0;padding:0;background:#F2F0EB;font-family:Arial,Helvetica,sans-serif"><div style="display:none;max-height:0;overflow:hidden">{escape(preheader)}</div><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#F2F0EB;padding:28px 12px"><tr><td align="center"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:640px;background:#FFFFFF;border:1px solid #DED9CE;border-radius:10px;overflow:hidden"><tr><td style="background:{BG};padding:28px 34px;border-bottom:3px solid {GOLD}"><div style="color:{GOLD};font-size:22px;font-weight:800;letter-spacing:.12em">{brand}</div><div style="color:{MUTED};font-size:12px;margin-top:7px;letter-spacing:.08em;text-transform:uppercase">Professional Business Communication</div></td></tr><tr><td style="padding:36px 34px"><h1 style="margin:0 0 22px;color:#111;font-size:25px;line-height:1.25">{safe_title}</h1>{paragraphs}{cta}</td></tr><tr><td style="background:{PANEL};padding:22px 34px;border-top:1px solid #292929"><div style="color:#D7D1C5;font-size:12px;line-height:1.6">This message was sent securely on behalf of {brand}.</div><div style="color:{MUTED};font-size:11px;line-height:1.6;margin-top:7px">Powered by Caelomere Core · Secure business intelligence and automation</div></td></tr></table></td></tr></table></body></html>'''
