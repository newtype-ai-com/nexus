package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

// ResendMailer has a fixed destination and does not follow redirects. API
// errors, mail bodies and approval URLs are never returned in error strings.
type ResendMailer struct {
	key, from string
	client    *http.Client
}

func NewResendMailer(key, from string) (*ResendMailer, error) {
	if key == "" || strings.ContainsAny(key, "\r\n") || strings.ContainsAny(from, "\r\n") {
		return nil, errors.New("gate: invalid mail configuration")
	}
	if _, err := mail.ParseAddress(from); err != nil {
		return nil, errors.New("gate: invalid mail sender")
	}
	return &ResendMailer{key: key, from: from, client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (m *ResendMailer) SendVerification(ctx context.Context, email, link string) error {
	text := "직접 요청한 설치나 로그인만 승인하세요. 링크의 안내와 만료 시간을 확인한 뒤 승인 버튼을 눌러 주세요.\n\n" + link
	return m.send(ctx, email, "Newtype 설치·로그인 승인", text, verificationMail(link))
}

func (m *ResendMailer) SendUserAdmission(ctx context.Context, owner, target, link string) error {
	text := "사용자 추가 요청: " + target + "\n직접 요청한 정확한 주소인지 확인하세요. 승인 전에는 가입할 수 없습니다. 관리자 권한은 부여하지 않습니다. 30분 뒤 만료됩니다.\n\n" + link
	return m.send(ctx, owner, "Newtype 사용자 추가 승인", text, userAdmissionMail(target, link))
}

func (m *ResendMailer) SendQuotaApproval(ctx context.Context, owner, summary, link string) error {
	text := summary + "\n요청만으로 적용되지 않습니다. 링크에서 정확한 값과 만료 시간을 확인하고 별도 승인하세요.\n\n" + link
	return m.send(ctx, owner, "Newtype 월간 토큰 증액 승인", text, quotaMail(summary, link))
}

func (m *ResendMailer) SendChangeApproval(ctx context.Context, owner, summary, link string) error {
	text := summary + "\n열어 보는 것만으로는 승인되지 않습니다. 변경 원문과 digest를 확인한 뒤 별도 결정하세요.\n\n" + link
	return m.send(ctx, owner, "Newtype 운영 변경 승인", text, changeMail(summary, link))
}

// The device flow and the install flow share SendVerification; only the
// path of our own link tells which expiry applies.
func verificationMail(link string) mailView {
	v := mailView{Subject: "Newtype 설치·로그인 승인", Badge: "설치 승인", Title: "Newtype 설치를 승인해 주세요", Lead: "이 주소로 Newtype 설치 요청이 들어왔습니다. 직접 요청한 설치라면 아래 버튼으로 승인 페이지를 열어 승인해 주세요.", Expiry: "요청 후 30분 안에 승인해야 합니다.", Button: "확인하고 승인하기", Link: link}
	if u, err := url.Parse(link); err == nil && u.Path == "/device/confirm" {
		v.Badge, v.Title, v.Lead, v.Expiry = "로그인 승인", "Newtype 로그인을 승인해 주세요", "이 계정으로 새 로그인 요청이 들어왔습니다. 직접 요청한 로그인이라면 아래 버튼으로 승인 페이지를 열어 승인해 주세요.", "요청 후 10분 안에 승인해야 합니다."
	}
	v.Preheader = v.Title + " · " + v.Expiry
	return v
}

func userAdmissionMail(target, link string) mailView {
	return mailView{Subject: "Newtype 사용자 추가 승인", Preheader: "사용자 추가 요청: " + target, Badge: "사용자 추가 승인", Title: "새 사용자 추가를 승인해 주세요", Lead: "직접 요청한 정확한 주소인지 확인하세요. 승인 전에는 가입할 수 없고, 관리자 권한은 부여하지 않습니다.", Facts: []mailFact{{"추가할 사용자", target}}, Expiry: "30분 안에 승인해야 합니다. 30분 뒤 만료됩니다.", Button: "확인하고 승인하기", Link: link}
}

func quotaMail(summary, link string) mailView {
	return mailView{Subject: "Newtype 월간 토큰 증액 승인", Preheader: "월간 토큰 증액 요청", Badge: "월간 토큰 증액 승인", Title: "월간 토큰 증액을 승인해 주세요", Lead: "요청만으로 적용되지 않습니다. 승인 페이지에서 정확한 값과 만료 시간을 확인하고 별도로 승인하세요.", Block: summary, Expiry: "30분 안에 승인해야 합니다.", Button: "확인하고 승인하기", Link: link}
}

func changeMail(summary, link string) mailView {
	return mailView{Subject: "Newtype 운영 변경 승인", Preheader: "운영 변경 승인 요청", Badge: "운영 변경 승인", Title: "운영 변경을 승인해 주세요", Lead: "열어 보는 것만으로는 승인되지 않습니다. 승인 페이지에서 변경 원문과 digest를 확인한 뒤 별도로 결정하세요.", Block: summary, Expiry: "만료 시각은 위 요약의 \"만료\" 항목을 확인하세요.", Button: "변경 내용 확인하기", Link: link}
}

// send delivers a multipart message: the complete text part for clients that
// show only text, and the rendered html part. Every dynamic value in the html
// part is escaped by html/template.
func (m *ResendMailer) send(ctx context.Context, email, subject, text string, view mailView) error {
	html, err := renderMail(view)
	if err != nil {
		return errors.New("gate: mail delivery failed")
	}
	return m.deliver(ctx, email, subject, text, html)
}

// SendOwnerCodeNotice is a text-only notice with no code and no link.
func (m *ResendMailer) SendOwnerCodeNotice(ctx context.Context, owner string) error {
	text := "운영자가 만든 1회용 코드(nexus enrol-owner)로 이 주소의 owner 자격이 방금 발급되었습니다. 직접 한 일이 아니라면 서버 운영자에게 알리고 자격을 폐기하세요.\n\nOwner credentials for this address were just issued through an operator code (nexus enrol-owner). If this was not you, tell the server operator and revoke them."
	return m.deliver(ctx, owner, "Newtype owner 자격 발급 알림", text, "")
}

func (m *ResendMailer) deliver(ctx context.Context, email, subject, text, html string) error {
	body := map[string]any{"from": m.from, "to": []string{email}, "subject": subject, "text": text}
	if html != "" {
		body["html"] = html
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return errors.New("gate: mail delivery failed")
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.resend.com/emails", bytes.NewReader(raw))
	if err != nil {
		return errors.New("gate: mail delivery failed")
	}
	req.Header.Set("Authorization", "Bearer "+m.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return errors.New("gate: mail delivery failed")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("gate: mail delivery failed")
	}
	return nil
}
