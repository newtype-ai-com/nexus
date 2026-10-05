package release

import (
	"crypto/ed25519"
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Public install service (docs/install-service.md), served by Nexus beside
// the release routes and from the same NEXUS_RELEASES_DIR:
//
//	GET /llm.txt, /llms.txt     instructions for an AI coding agent
//	GET /install.sh             POSIX sh installer (macOS, Linux)
//	GET /install.ps1            PowerShell installer (Windows)
//	GET /v1/releases/latest.txt the latest release as plain key=value lines
//
// All four are read-only, unauthenticated and carry no secret. They answer
// 404 while NEXUS_RELEASES_DIR is unset, like the release routes. Release
// facts (version, SHA-256) come only from a manifest whose Ed25519 signature
// verifies against the key pinned in this server build; without a pinned key
// or a verifiable manifest there is "no release" (latest.txt 404, llm.txt
// says none, the installers stop).

// PublicOrigin is the canonical origin the installers and llm.txt name.
const PublicOrigin = "https://lic.newtype-ai.com"

//go:embed installer/install.sh
var installSH string

//go:embed installer/install.ps1
var installPS1 string

// InstallScript returns the embedded installer bodies (tests, docs).
func InstallScript(name string) string {
	switch name {
	case "install.sh":
		return installSH
	case "install.ps1":
		return installPS1
	}
	return ""
}

// verifiedLatest reads the published manifest and verifies it with key.
func verifiedLatest(dir string, key ed25519.PublicKey) (Manifest, error) {
	if dir == "" || !ValidDir(dir) {
		return Manifest{}, errNoRelease
	}
	if len(key) != ed25519.PublicKeySize {
		return Manifest{}, ErrDisabled
	}
	root, err := openRootDir(dir)
	if err != nil {
		return Manifest{}, errNoRelease
	}
	defer root.Close()
	raw, sig, err := readLatest(root)
	if err != nil {
		return Manifest{}, errNoRelease
	}
	return Verify(key, raw, sig)
}

var errNoRelease = errors.New("release: no published release")

func sortedArtifacts(m Manifest) []Artifact {
	arts := append([]Artifact(nil), m.Artifacts...)
	sort.Slice(arts, func(i, j int) bool {
		return arts[i].OS+"/"+arts[i].Arch < arts[j].OS+"/"+arts[j].Arch
	})
	return arts
}

// LatestText is the /v1/releases/latest.txt body: no JSON, so install.sh can
// read it with sed. Every value already passed Manifest.Validate.
func LatestText(m Manifest) string {
	var b strings.Builder
	b.WriteString("# Newtype latest release, from the signed manifest (signature verified by the server).\n")
	b.WriteString("# <os>-<arch>=<sha256> <size>; download: /v1/releases/files/<sha256>\n")
	fmt.Fprintf(&b, "version=%s\nreleased_at=%s\n", m.Version, m.ReleasedAt)
	for _, a := range sortedArtifacts(m) {
		fmt.Fprintf(&b, "%s-%s=%s %d\n", a.OS, a.Arch, a.SHA256, a.Size)
	}
	return b.String()
}

func installRoutes(mux *http.ServeMux, dir string, key ed25519.PublicKey) {
	text := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte(body))
	}
	enabled := func(w http.ResponseWriter) bool {
		if dir == "" || !ValidDir(dir) {
			notFound(w)
			return false
		}
		return true
	}
	llm := func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		m, err := verifiedLatest(dir, key)
		var latest *Manifest
		if err == nil {
			latest = &m
		}
		text(w, LLMText(latest))
	}
	mux.HandleFunc("GET /llm.txt", llm)
	mux.HandleFunc("GET /llms.txt", llm)
	mux.HandleFunc("GET /install.sh", func(w http.ResponseWriter, r *http.Request) {
		if enabled(w) {
			text(w, installSH)
		}
	})
	mux.HandleFunc("GET /install.ps1", func(w http.ResponseWriter, r *http.Request) {
		if enabled(w) {
			text(w, installPS1)
		}
	})
	mux.HandleFunc("GET /v1/releases/latest.txt", func(w http.ResponseWriter, r *http.Request) {
		if !enabled(w) {
			return
		}
		m, err := verifiedLatest(dir, key)
		if err != nil {
			notFound(w)
			return
		}
		text(w, LatestText(m))
	})
}

// installPaths are routed to the install service by Mount.
var installPaths = map[string]bool{"/llm.txt": true, "/llms.txt": true, "/install.sh": true, "/install.ps1": true}

// LLMText is the /llm.txt body. latest is nil when no verified release is
// published.
func LLMText(latest *Manifest) string {
	var b strings.Builder
	w := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	w("# Newtype — install guide for AI coding agents / AI 코딩 에이전트용 설치 안내")
	w("")
	w("Source: " + PublicOrigin + "/llm.txt (also /llms.txt). Plain text; follow it step by step.")
	w("")
	w("## What Newtype is / Newtype 이란")
	w("")
	w("Newtype is a terminal AI agent (TUI) for one person's machine. Each session works in a trusted")
	w("folder, uses a model set up by its owner, and joins Nexus: a ledger where the sessions of one")
	w("account exchange messages, delegate tasks and ask a person for approval. Gate (" + PublicOrigin + ")")
	w("enrols devices by e-mail approval; releases are signed with an offline Ed25519 key.")
	w("")
	w("Newtype 은 개인 컴퓨터에서 도는 터미널 AI 에이전트(TUI)입니다. 세션마다 신뢰한 폴더에서 일하고, 주인이")
	w("설정한 모델을 쓰며, 같은 계정의 세션들이 메시지·작업·승인 요청을 주고받는 원장 Nexus 에 참여합니다.")
	w("기기 등록은 Gate 의 이메일 승인으로 하고, 릴리스는 오프라인 Ed25519 키로 서명됩니다.")
	w("")
	w("## Install / 설치 (one command / 명령 하나)")
	w("")
	w("macOS or Linux (arm64, amd64):")
	w("")
	w("    curl -fsSL " + PublicOrigin + "/install.sh | sh")
	w("")
	w("Windows (PowerShell, amd64 or arm64; no administrator rights needed):")
	w("")
	w("    irm " + PublicOrigin + "/install.ps1 | iex")
	w("")
	w("What it does / 하는 일:")
	w("- detects the OS and CPU; refuses anything else with a message (other platforms: no build).")
	w("- reads " + PublicOrigin + "/v1/releases/latest.txt (from the signed release manifest), downloads")
	w("  /v1/releases/files/<sha256> and checks the size and SHA-256 BEFORE installing.")
	w("- macOS/Linux: ~/.local/share/newtype/bin/newtype-<version>, symlink ~/.local/bin/newtype; no sudo.")
	w("- Windows: %USERPROFILE%\\.local\\share\\newtype\\bin\\newtype-<version>.exe plus a copy")
	w("  %USERPROFILE%\\.local\\bin\\newtype.exe; adds %USERPROFILE%\\.local\\bin to the user Path if missing")
	w("  and drops an old %LOCALAPPDATA%\\Newtype\\bin entry. On Windows, running the installer from inside a")
	w("  packaged (MSIX) app such as the Claude desktop app can land the files in that app's private")
	w("  storage: the person should run it in their own PowerShell, or the agent should use a shell")
	w("  outside the package. USER Path only (not the machine Path); no administrator rights.")
	w("- prints a PATH hint if needed and the next step. It installs nothing else and needs no account.")
	w("- OS·CPU 확인 → 서명된 매니페스트의 SHA-256 으로 내려받은 파일 확인 → 사용자 폴더에 설치(sudo·관리자 권한 없음).")
	w("")
	w("Trust: the first install trusts HTTPS plus the SHA-256 published from the signed manifest. Later")
	w("updates are verified inside the newtype client by the Ed25519 release signature (pinned key).")
	w("신뢰: 첫 설치는 HTTPS 와 서명된 매니페스트의 SHA-256, 이후 업데이트는 클라이언트가 Ed25519 서명으로 검증합니다.")
	w("")
	w("Windows note: Windows builds are Authenticode-unsigned; their trust anchor is the Ed25519 manifest")
	w("signature, as on macOS and Linux. Smart App Control may block newtype.exe (it decides unsigned files")
	w("by cloud reputation), and SmartScreen may warn. Do NOT bypass, disable or work around these")
	w("protections; tell the person instead.")
	w("Windows 안내: Windows 빌드는 Authenticode 서명이 없습니다(신뢰 기준은 macOS·Linux 와 같은 Ed25519")
	w("매니페스트 서명). Smart App Control 이 newtype.exe 를 막을 수 있습니다(서명 없는 파일은 클라우드 평판으로")
	w("판단). 우회하거나 끄지 말고 사람에게 알리세요.")
	w("")
	w("## Current release / 현재 릴리스")
	w("")
	if latest == nil {
		w("none: no signed release is published yet. The installers stop with a message; tell the person.")
		w("없음: 아직 게시된 서명 릴리스가 없습니다. 설치 스크립트는 메시지와 함께 멈춥니다.")
	} else {
		w("version: " + latest.Version)
		w("released_at: " + latest.ReleasedAt)
		for _, a := range sortedArtifacts(*latest) {
			fmt.Fprintf(&b, "sha256 %s-%s: %s (%d bytes)\n", a.OS, a.Arch, a.SHA256, a.Size)
		}
	}
	w("")
	w("## Verify / 확인")
	w("")
	w("    newtype --version")
	w("")
	w("prints \"NEWTYPE SLAVES <version>\". If the command is not found, open a new terminal or add")
	w("~/.local/bin (Windows: %USERPROFILE%\\.local\\bin) to PATH as the installer printed.")
	w("")
	w("## First run needs the person / 첫 실행은 사람이 직접")
	w("")
	w("STOP after installing. Tell the person to run `newtype` in their own terminal. The first run")
	w("asks for: (1) e-mail enrolment, approved by the person from their mailbox; (2) trusting the")
	w("work folder; (3) choosing or setting up a model. An AI agent must NEVER type, ask for, read or")
	w("store credentials, API keys or tokens, and must NEVER approve or click enrolment or approval mail")
	w("on the person's behalf. Do not run `newtype` interactively for them.")
	w("")
	w("설치가 끝나면 멈추고, 사람에게 터미널에서 `newtype` 을 실행하라고 안내하세요. 첫 실행은 (1) 이메일 등록")
	w("승인(사람이 메일함에서 승인), (2) 작업 폴더 신뢰, (3) 모델 설정을 묻습니다. AI 에이전트는 자격 증명·API 키·")
	w("토큰을 입력·요청·저장하지 말고, 등록·승인 메일을 대신 승인하지 마세요.")
	w("")
	w("## Add Nexus to Claude Code / Claude Code 에 Nexus 추가")
	w("")
	w("After the person finished the first run (saved credentials exist):")
	w("")
	w("    newtype nmcp setup claude --channel --apply")
	w("")
	w("or the remote server (the person signs in when Claude Code asks):")
	w("")
	w("    claude mcp add --transport http nexus " + PublicOrigin + "/mcp")
	w("")
	w("## Update / 업데이트")
	w("")
	w("    newtype update          # check, verify the signature, install if newer")
	w("    newtype update --check  # check only")
	w("")
	w("or inside the TUI: /update (or ask it for the latest update / \"최신 업데이트\"). Running the")
	w("installer again also installs the latest release. Restart newtype afterwards.")
	w("업데이트: `newtype update` 또는 TUI 에서 /update(\"최신 업데이트\"). 설치 뒤 newtype 을 다시 시작합니다.")
	w("")
	selfHostText(w)
	return b.String()
}

// selfHostText is the "Run your own Nexus" section of /llm.txt. Only commands
// verified in a local run (docs/selfhost.md) are given as commands; the rest
// is marked unverified. It names no server variable or secret value.
func selfHostText(w func(string)) {
	w("## Run your own Nexus (self-host) / Nexus 직접 띄우기")
	w("")
	w("Anyone may run their own Nexus instead of " + PublicOrigin + ". Full guide with expected outputs and")
	w("troubleshooting: docs/selfhost.md. Source: the public repository is planned as")
	w("https://github.com/newtype-ai-com/nexus (Apache-2.0) and is coming soon (that link works once it is published); until then, ask the person")
	w("where their copy of the source is. The self-host kit is the directory deploy/selfhost in it.")
	w("누구나 " + PublicOrigin + " 대신 자기 Nexus 를 띄울 수 있습니다. 공개 저장소(https://github.com/newtype-ai-com/nexus,")
	w("Apache-2.0)는 곧 공개 예정이며 링크는 공개 뒤에 열립니다. 그 전에는 사람에게 소스 위치를 물으세요. 키트는 deploy/selfhost, 안내는 docs/selfhost.md.")
	w("")
	w("Prerequisites / 준비:")
	w("- Docker Engine with Compose v2 (`docker compose version`).")
	w("- For other computers and remote MCP: a domain name, HTTPS for it (Caddy in the kit, or a tunnel),")
	w("  ports 80/443. The newtype client accepts https:// origins, and plain http only on loopback")
	w("  (127.0.0.1, localhost, [::1]) for local development.")
	w("- Mail (a Resend API key) only for other people: the owner can start without mail (one-time code below).")
	w("  For a mail-free start the person puts any placeholder in the mail-key and sender lines of .env.")
	w("- 준비: Docker + compose, (원격용) 도메인과 HTTPS, 80/443 포트. 메일(Resend 키)은 owner 외 사람 가입에만 필요.")
	w("")
	w("Steps (verified) / 순서(확인됨), in deploy/selfhost:")
	w("")
	w("    cp .env.example .env && chmod 600 .env")
	w("")
	w("STOP: the PERSON fills .env. They generate each secret themselves with the openssl commands listed")
	w("at the top of .env.example (`openssl rand -hex 32`, `openssl rand -base64 32`) and paste them in, and")
	w("they enter their domain, owner e-mail and mail key. You may show these commands; never generate,")
	w("read, print or store the values for them.")
	w("멈춤: .env 는 사람이 채웁니다. 비밀값은 사람이 .env.example 맨 위의 openssl 명령으로 직접 만들어 넣고,")
	w("도메인·owner 메일·메일 키도 사람이 넣습니다. 명령은 보여 줘도 되지만 값을 대신 만들거나 읽지 마세요.")
	w("")
	w("    docker compose build nexus")
	w("    docker compose up -d postgres")
	w("    docker compose run --rm nexus migrate      # BEFORE the first start / 첫 시작 전에 반드시")
	w("    docker compose up -d nexus")
	w("    curl -fsS http://127.0.0.1:8080/v1/health")
	w("")
	w("migrate prints \"Nexus and Gate migrations complete\"; health prints {…,\"ok\":true}. 8080 is the")
	w("loopback port set in .env (default 8080).")
	w("")
	w("HTTPS with the kit's Caddy (unverified with a public certificate). STOP: this opens public ports 80 and")
	w("443 on the host. The PERSON sets DNS first and confirms they want the server reachable from the internet;")
	w("only then:")
	w("멈춤: 공개 80/443 포트가 열립니다. 사람이 DNS 를 먼저 설정하고 인터넷 공개를 확인한 뒤에만 실행합니다.")
	w("")
	w("    docker compose --profile tls up -d caddy")
	w("")
	w("Owner / owner 만들기 (no mail needed). The owner is the one owner address set in .env (also the only")
	w("allowed address); the owner-code switch in .env must be on (it is in the kit's .env.example). On the")
	w("server, in deploy/selfhost:")
	w("")
	w("    docker compose run --rm enrol-owner")
	w("")
	w("It prints a one-time code (eoc_…, single use, 15 minutes, one active per owner) to that terminal.")
	w("Nexus writes it nowhere; that service's Docker logging is off. STOP: the PERSON runs, on the owner's")
	w("computer, and pastes the code at the hidden prompt (never as a command argument):")
	w("")
	w("    newtype auth enrol --gate-url https://<your-domain> --code")
	w("")
	w("Do not copy, store, type or log the code yourself. Then")
	w("`newtype auth status --credential-dir ~/.newtype/credentials` prints \"Gate: valid\". From then on")
	w("`newtype`, `newtype nexus …` and `newtype nmcp serve` use that saved server.")
	w("With mail configured, the owner may instead enrol by mail (`newtype auth enrol --gate-url")
	w("https://<your-domain> --email <owner e-mail>`) and approve the mailed link themselves.")
	w("멈춤: 코드는 사람이 직접 owner 컴퓨터로 옮겨 입력합니다(15분, 한 번만). 그 뒤 저장된 서버를 newtype·nexus·nmcp 가 그대로 씁니다.")
	w("")
	w("Claude Code remote MCP (needs the remote-MCP issuer in .env = https://<your-domain>):")
	w("")
	w("    claude mcp add --transport http nexus https://<your-domain>/mcp")
	w("")
	w("STOP: the PERSON allows the connection: the consent page shows a code and the person runs")
	w("`newtype nmcp authorize CODE` in their own terminal and answers y. Or locally:")
	w("`newtype nmcp setup claude --channel --apply`.")
	w("")
	w("Optional (see docs/selfhost.md): shared model relay (off by default; people bring their own model")
	w("profiles; unverified), a Cloudflare tunnel instead of Caddy (unverified), backups with")
	w("`docker compose exec -T postgres pg_dump -U nexus -d nexus -Fc > nexus.dump` (verified).")
	w("")
	w("Hand over to the person, always: DNS records, TLS certificates, mail-provider keys, every secret in")
	w("the environment file, and the owner's first enrolment approval or one-time code. Never type or approve these.")
	w("사람에게 넘길 것: DNS, TLS 인증서, 메일 제공자 키, 환경 파일의 모든 비밀값, owner 1회용 코드·첫 가입 승인.")
	w("")
	w("Troubleshooting / 문제 해결:")
	w("- \"schema mismatch; run explicit migration\": upgrades never migrate. After every new image:")
	w("  `docker compose stop nexus && docker compose run --rm nexus migrate && docker compose up -d nexus`.")
	w("- health fails: `docker compose logs nexus`; the first line names the problem (database connection,")
	w("  invalid enrolment configuration, …). The database password must be hex (it goes into a URL).")
	w("- POST /mcp answers 401 without a token: expected; Claude Code starts OAuth from that answer.")
	w("- \"gate: explicit HTTPS origin required\": the client needs https://; plain http only on 127.0.0.1,")
	w("  localhost or [::1].")
	w("- \"gate: not_found\" after --code: the code was used, expired or replaced, or the owner-code switch")
	w("  is off on the server; run enrol-owner again (it says so when the switch is off).")
}
