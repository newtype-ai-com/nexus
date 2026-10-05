package gate

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"strings"
)

// Shared look of the approval mails and landing pages (decision 2026-10-04:
// "승인 메일도 예쁘게 디자인해줘. 버튼도 크게 만들어줘.").
//
// Landing pages carry exactly one inline <style> element whose bytes are the
// constant below. The CSP admits it by hash only, so no other inline style,
// style attribute or script is allowed by this change.

const approvalPageCSS = `:root{color-scheme:light dark;--bg:#f2f3f7;--card:#ffffff;--text:#16181d;--muted:#5b6170;--line:#e3e5ec;--code:#f6f7fa;--brand:#3b30d6;--brand-ink:#ffffff;--deny:#b42318;--ok:#067647}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#181b22;--text:#e8eaef;--muted:#a3a9b6;--line:#2b303b;--code:#11141a;--brand:#6d64ff;--brand-ink:#ffffff;--deny:#ff8a80;--ok:#5fd39a}}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--text);font:16px/1.6 -apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Malgun Gothic","Noto Sans KR","Segoe UI",Roboto,sans-serif;-webkit-text-size-adjust:100%}
main{max-width:560px;margin:0 auto;padding:32px 16px 48px}
.brand{font-size:20px;font-weight:800;letter-spacing:-.02em;color:var(--brand);margin:0 0 16px 4px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:28px 24px}
h1{font-size:24px;line-height:1.35;margin:0 0 12px;letter-spacing:-.01em}
p{margin:0 0 12px}
.lead{font-size:17px}
.muted{color:var(--muted);font-size:14px}
.badge{display:inline-block;font-size:13px;font-weight:700;color:var(--brand);border:1px solid var(--line);border-radius:999px;padding:2px 10px;margin:0 0 12px}
dl{margin:16px 0;padding:0;border-top:1px solid var(--line)}
dl div{display:flex;flex-wrap:wrap;gap:4px 12px;padding:10px 0;border-bottom:1px solid var(--line)}
dt{flex:0 0 96px;color:var(--muted);font-size:14px}
dd{flex:1 1 200px;margin:0;font-weight:600;overflow-wrap:anywhere}
pre{background:var(--code);border:1px solid var(--line);border-radius:10px;padding:14px;margin:16px 0;font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
code{font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
form{margin:24px 0 8px;display:flex;flex-direction:column;gap:12px}
button{appearance:none;-webkit-appearance:none;display:block;width:100%;min-height:56px;border-radius:12px;font:inherit;font-size:18px;font-weight:800;cursor:pointer;padding:14px 20px}
button.approve{background:var(--brand);color:var(--brand-ink);border:0}
button.deny{background:transparent;color:var(--deny);border:2px solid var(--line)}
button:focus-visible{outline:3px solid var(--brand);outline-offset:3px}
button:disabled{opacity:.45;cursor:not-allowed}
.done{font-size:20px;font-weight:800;color:var(--ok);margin:0 0 8px}
.note{margin:20px 0 0;padding:14px 16px;border-radius:10px;background:var(--code);color:var(--muted);font-size:14px}
.note p{margin:0}
.note p+p{margin-top:4px}
noscript{display:block;margin-top:12px;color:var(--deny);font-weight:700}
footer{margin:16px 4px 0;color:var(--muted);font-size:12px}`

// approvalStyleSource is the CSP hash source for approvalPageCSS.
var approvalStyleSource = func() string {
	sum := sha256.Sum256([]byte(approvalPageCSS))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}()

// approvalPageCSP is the previous policy plus a hash-pinned style-src.
var approvalPageCSP = "default-src 'none'; style-src " + approvalStyleSource + "; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// changeSurfaceCSP is the previous approvals-server policy plus the same style hash.
var changeSurfaceCSP = "default-src 'none'; script-src 'self'; connect-src 'self'; style-src " + approvalStyleSource + "; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

const approvalSecurityNote = `<div class="note"><p>직접 요청한 것이 아니면 승인하지 마세요.</p><p>메일이나 이 페이지를 여는 것만으로는 승인되지 않습니다.</p></div>`

// approvalPage wraps a body in the shared head. title and body are constant
// template source; every dynamic value inside body goes through html/template.
func approvalPage(name, title, body string) *template.Template {
	return template.Must(template.New(name).Parse(`<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><meta name="robots" content="noindex,nofollow"><title>` + title + `</title><style>` + approvalPageCSS + `</style></head><body><main><div class="brand">Newtype</div><div class="card">` + body + `</div><footer>Newtype · 승인 요청은 이 주소(같은 출처)에서만 처리됩니다.</footer></main></body></html>`))
}

var (
	enrolVerifyPage = approvalPage("enrol-verify", "Newtype 승인", `<span class="badge">설치·로그인 승인</span><h1>이 설치를 승인하시겠습니까?</h1><p class="lead">직접 요청한 설치에만 승인하세요.</p><p class="muted">승인하면 요청한 기기에서 Newtype 설치·로그인을 마칠 수 있습니다. 요청 후 30분 안에 승인해야 합니다.</p><form method="post"><button class="approve" type="submit">승인</button></form>`+approvalSecurityNote)
	enrolDonePage   = approvalPage("enrol-done", "Newtype", `<p class="done">승인되었습니다.</p><p>이 창은 닫아도 됩니다. 요청한 기기에서 설치·로그인이 이어집니다.</p>`)
	deviceConfirm   = approvalPage("device-confirm", "Newtype 로그인", `<span class="badge">로그인 승인</span><h1>이 로그인을 직접 요청하셨습니까?</h1><p class="lead">요청하지 않았다면 거절하세요.</p><p class="muted">승인하면 요청한 기기가 이 계정으로 로그인합니다. 요청 후 10분 안에 승인해야 합니다.</p><form method="post"><button class="approve" name="decision" value="approve">로그인 승인</button><button class="deny" name="decision" value="deny">거절</button></form>`+approvalSecurityNote)
	deviceDonePage  = approvalPage("device-done", "Newtype", `<p class="done">처리되었습니다.</p><p>이 창은 닫아도 됩니다.</p>`)
)

func renderStatic(t *template.Template) string {
	var b bytes.Buffer
	if err := t.Execute(&b, nil); err != nil {
		panic(err)
	}
	return b.String()
}

var (
	enrolVerifyHTML   = renderStatic(enrolVerifyPage)
	enrolDoneHTML     = renderStatic(enrolDonePage)
	deviceConfirmHTML = renderStatic(deviceConfirm)
	deviceDoneHTML    = renderStatic(deviceDonePage)
)

// ---- mail ----

type mailFact struct{ Label, Value string }

type mailView struct {
	Subject, Preheader, Badge, Title, Lead string
	Facts                                  []mailFact
	Block                                  string // shown monospace, exactly as the text part
	Expiry                                 string
	Button                                 string
	Link                                   string
}

// Outlook (Word engine) helpers. These are constant markup or escape the link
// themselves; html/template would otherwise strip conditional comments.
var mailFuncs = template.FuncMap{
	"msoOpen": func() template.HTML {
		return `<!--[if mso]><table role="presentation" width="560" align="center" cellpadding="0" cellspacing="0" border="0"><tr><td><![endif]-->`
	},
	"msoClose": func() template.HTML { return `<!--[if mso]></td></tr></table><![endif]-->` },
	"vmlButton": func(link, label string) template.HTML {
		if !strings.HasPrefix(link, "https://") {
			return ""
		}
		return template.HTML(`<!--[if mso]><v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word" href="` + template.HTMLEscapeString(link) + `" style="height:56px;v-text-anchor:middle;width:496px;" arcsize="20%" stroke="f" fillcolor="#3b30d6"><w:anchorlock/><center style="color:#ffffff;font-family:Arial,sans-serif;font-size:18px;font-weight:bold;">` + template.HTMLEscapeString(label) + `</center></v:roundrect><![endif]-->`)
	},
	"notMsoOpen":  func() template.HTML { return `<!--[if !mso]><!-->` },
	"notMsoClose": func() template.HTML { return `<!--<![endif]-->` },
}

const mailFont = `-apple-system,BlinkMacSystemFont,'Apple SD Gothic Neo','Malgun Gothic','Noto Sans KR','Segoe UI',Roboto,Arial,sans-serif`

var mailTemplate = template.Must(template.New("mail").Funcs(mailFuncs).Parse(`<!doctype html>
<html lang="ko" xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="x-apple-disable-message-reformatting">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>{{.Subject}}</title>
<style>
:root{color-scheme:light dark;supported-color-schemes:light dark}
@media (prefers-color-scheme:dark){
.nt-bg{background:#0f1115 !important}
.nt-card{background:#181b22 !important;border-color:#2b303b !important}
.nt-text{color:#e8eaef !important}
.nt-muted{color:#a3a9b6 !important}
.nt-code{background:#11141a !important;color:#e8eaef !important;border-color:#2b303b !important}
.nt-line{border-color:#2b303b !important}
.nt-brand{color:#8f88ff !important}
}
</style>
</head>
<body class="nt-bg" style="margin:0;padding:0;background:#f2f3f7;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;mso-hide:all;">{{.Preheader}}</div>
<table role="presentation" class="nt-bg" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f2f3f7;">
<tr><td align="center" style="padding:32px 12px;">
{{msoOpen}}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;width:100%;">
<tr><td class="nt-brand" style="padding:0 8px 16px;font-family:` + mailFont + `;font-size:22px;font-weight:800;letter-spacing:-0.02em;color:#3b30d6;">Newtype</td></tr>
<tr><td class="nt-card" style="background:#ffffff;border:1px solid #e3e5ec;border-radius:16px;padding:32px 28px;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
<tr><td class="nt-brand" style="font-family:` + mailFont + `;font-size:13px;font-weight:700;color:#3b30d6;padding:0 0 8px;">{{.Badge}}</td></tr>
<tr><td class="nt-text" style="font-family:` + mailFont + `;font-size:24px;line-height:1.35;font-weight:800;color:#16181d;padding:0 0 12px;">{{.Title}}</td></tr>
<tr><td class="nt-text" style="font-family:` + mailFont + `;font-size:16px;line-height:1.6;color:#16181d;padding:0 0 16px;">{{.Lead}}</td></tr>
{{range .Facts}}<tr><td class="nt-line" style="border-top:1px solid #e3e5ec;padding:10px 0;font-family:` + mailFont + `;font-size:15px;line-height:1.5;"><span class="nt-muted" style="color:#5b6170;">{{.Label}}</span><br><strong class="nt-text" style="color:#16181d;word-break:break-all;">{{.Value}}</strong></td></tr>
{{end}}{{if .Block}}<tr><td style="padding:4px 0 16px;"><pre class="nt-code" style="margin:0;padding:14px 16px;background:#f6f7fa;border:1px solid #e3e5ec;border-radius:10px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'Courier New',monospace;font-size:13px;line-height:1.55;color:#16181d;white-space:pre-wrap;word-break:break-all;">{{.Block}}</pre></td></tr>
{{end}}<tr><td style="padding:8px 0 0;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
<tr><td align="center">
{{vmlButton .Link .Button}}{{notMsoOpen}}<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td align="center" bgcolor="#3b30d6" height="56" style="background:#3b30d6;border-radius:12px;height:56px;mso-padding-alt:0;"><a href="{{.Link}}" target="_blank" rel="noopener noreferrer" style="display:block;width:100%;min-height:56px;line-height:56px;padding:0;font-family:` + mailFont + `;font-size:18px;font-weight:800;color:#ffffff;text-decoration:none;text-align:center;border-radius:12px;-webkit-text-size-adjust:none;">{{.Button}}</a></td></tr></table>{{notMsoClose}}
</td></tr>
</table>
</td></tr>
<tr><td class="nt-muted" style="padding:14px 0 0;font-family:` + mailFont + `;font-size:14px;line-height:1.5;color:#5b6170;text-align:center;">{{.Expiry}}</td></tr>
<tr><td class="nt-muted" style="padding:20px 0 0;font-family:` + mailFont + `;font-size:13px;line-height:1.5;color:#5b6170;">버튼이 열리지 않으면 아래 주소를 복사해 브라우저에 붙여 넣으세요.</td></tr>
<tr><td style="padding:6px 0 0;"><div class="nt-code" style="padding:10px 12px;background:#f6f7fa;border:1px solid #e3e5ec;border-radius:8px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'Courier New',monospace;font-size:12px;line-height:1.5;color:#16181d;word-break:break-all;">{{.Link}}</div></td></tr>
<tr><td class="nt-line" style="padding:24px 0 0;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td class="nt-code" style="padding:14px 16px;background:#f6f7fa;border:1px solid #e3e5ec;border-radius:10px;font-family:` + mailFont + `;font-size:13px;line-height:1.6;color:#5b6170;"><span class="nt-muted" style="color:#5b6170;">직접 요청한 것이 아니면 승인하지 마세요.<br>메일을 여는 것만으로는 승인되지 않습니다. 버튼을 누르면 승인 페이지가 열리고, 그 페이지에서 한 번 더 눌러야 처리됩니다.</span></td></tr></table></td></tr>
</table>
</td></tr>
<tr><td class="nt-muted" style="padding:16px 8px 0;font-family:` + mailFont + `;font-size:12px;line-height:1.5;color:#5b6170;">이 메일은 Newtype 승인 요청에 따라 자동으로 보냈습니다. 비밀번호·키·토큰은 메일로 보내지 않습니다.</td></tr>
</table>
{{msoClose}}
</td></tr>
</table>
</body>
</html>
`))

func renderMail(v mailView) (string, error) {
	var b bytes.Buffer
	if err := mailTemplate.Execute(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}
