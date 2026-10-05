package gate

import (
	"context"
	"encoding/json"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// This executes the production JavaScript in Node's vm with a synthetic DOM and
// fake fetch. It is NOT browser, CSP, live mail or owner-identity verification.
const changeVMHarness = `
const vm = require('node:vm');
let raw = '';
process.stdin.on('data', chunk => { raw += chunk; });
process.stdin.on('end', async () => {
 try {
  const input = JSON.parse(raw), calls = [], buttons = [{disabled:true}, {disabled:true}];
  let listener;
  const form = {
   elements: {digest: {value: input.digest}},
   querySelectorAll: () => buttons,
   addEventListener: (type, fn) => { if (type !== 'submit') throw Error(); listener = fn; },
   textContent: ''
  };
  const context = {
   document: {getElementById: () => input.noForm ? null : form},
   location: {search: input.query}, URLSearchParams,
   fetch: async (path, options) => {
    calls.push({path, body:options.body.toString(), method:options.method,
     credentials:options.credentials, cache:options.cache, referrerPolicy:options.referrerPolicy});
    if (input.lost) throw Error('synthetic lost response');
    return {ok: input.ok};
   }
  };
  vm.runInNewContext(input.script, context, {timeout:1000});
  const enabled = buttons.every(b => !b.disabled);
  if (listener) {
   const event = {preventDefault(){}, submitter: input.noSubmitter ? null : {value:input.decision}};
   const first = listener(event);
   if (input.duplicate) await listener(event);
   await first;
   if (input.retry) await listener(event);
  }
  process.stdout.write(JSON.stringify({calls, enabled, disabled:buttons.every(b=>b.disabled), message:form.textContent}));
 } catch (_) { process.stderr.write('synthetic_vm_failed'); process.exitCode=1; }
});
`

func TestChangeDecisionScriptVM(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node unavailable: synthetic JS execution not verified")
	}
	for _, tc := range []struct {
		name, decision, wantStatus                                      string
		expired, previouslyDenied                                       bool
		duplicate, lost, retry, badDigest, noSubmitter, noForm, noToken bool
		wantCalls                                                       int
	}{
		{name: "approve", decision: "approve", wantStatus: "approved", wantCalls: 1},
		{name: "deny", decision: "deny", wantStatus: "denied", wantCalls: 1},
		{name: "duplicate_inflight", decision: "approve", duplicate: true, wantStatus: "approved", wantCalls: 1},
		{name: "lost_response_no_automatic_retry", decision: "approve", lost: true, retry: true, wantStatus: "approved", wantCalls: 1},
		{name: "denied_lost_response", decision: "deny", lost: true, retry: true, wantStatus: "denied", wantCalls: 1},
		{name: "digest_conflict", decision: "approve", badDigest: true, retry: true, wantStatus: "pending", wantCalls: 1},
		{name: "invalid_decision", decision: "approve-deny", wantStatus: "pending", wantCalls: 1},
		{name: "expired_stale_page", decision: "approve", expired: true, wantStatus: "expired", wantCalls: 1},
		{name: "previously_denied_stale_page", decision: "approve", previouslyDenied: true, wantStatus: "denied", wantCalls: 1},
		{name: "no_submitter", decision: "approve", noSubmitter: true, wantStatus: "pending"},
		{name: "no_form", decision: "approve", noForm: true, wantStatus: "pending"},
		{name: "no_token", decision: "approve", noToken: true, wantStatus: "pending"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newChangeFixture(t)
			a := f.begin(changeTestInput())
			link, _ := url.Parse(f.mail.link)
			if tc.noToken {
				q := link.Query()
				q.Del("t")
				link.RawQuery = q.Encode()
			}
			before, err := f.store.Get(a.ID, f.now)
			if err != nil || before.Status != "pending" {
				t.Fatal("initial approval state")
			}
			if tc.expired {
				f.now = f.now.Add(time.Hour)
			}
			if tc.previouslyDenied {
				form := f.form(a)
				form.Set("decision", "deny")
				if f.request(false, "POST", "/change/approve", []byte(form.Encode())).Code != 200 {
					t.Fatal("prior denial failed")
				}
			}
			// Retrieve the exact served script, rather than a copied implementation.
			script := f.request(false, "GET", "/change/decision.js", nil)
			if script.Code != 200 {
				t.Fatal("script unavailable")
			}
			digest := a.Digest
			if tc.badDigest {
				digest = strings.Repeat("0", 64)
			}
			input, err := json.Marshal(map[string]any{
				"script": script.Body.String(), "query": "?" + link.RawQuery, "digest": digest,
				"decision": tc.decision, "duplicate": tc.duplicate, "lost": tc.lost, "retry": tc.retry,
				"noSubmitter": tc.noSubmitter, "noForm": tc.noForm, "ok": !tc.badDigest && !tc.expired && !tc.previouslyDenied && tc.decision != "approve-deny",
			})
			if err != nil {
				t.Fatal("fixture encoding")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, node, "-e", changeVMHarness)
			// No developer/provider env, NODE_OPTIONS, profile, network or modules.
			cmd.Env = []string{"PATH=/usr/bin:/bin"}
			cmd.Stdin = strings.NewReader(string(input))
			out, err := cmd.Output()
			if err != nil {
				t.Fatal("synthetic VM execution failed (output withheld)")
			}
			var result struct {
				Calls             []struct{ Path, Body, Method, Credentials, Cache, ReferrerPolicy string }
				Enabled, Disabled bool
				Message           string
			}
			if json.Unmarshal(out, &result) != nil {
				t.Fatal("synthetic VM result invalid")
			}
			if len(result.Calls) != tc.wantCalls {
				t.Fatalf("POST count = %d, want %d", len(result.Calls), tc.wantCalls)
			}
			if result.Enabled == (tc.noForm || tc.noToken) {
				t.Fatal("unexpected form enabled state")
			}
			if tc.wantCalls > 0 && !result.Disabled {
				t.Fatal("submitted form re-enabled")
			}
			for _, call := range result.Calls {
				if call.Path != "/change/approve" || call.Method != "POST" || call.Credentials != "omit" || call.Cache != "no-store" || call.ReferrerPolicy != "no-referrer" {
					t.Fatal("unsafe request metadata")
				}
				body, err := url.ParseQuery(call.Body)
				if err != nil || len(body) != 4 || body.Get("decision") != tc.decision || body.Get("digest") != digest || body.Get("id") != a.ID || body.Get("t") != link.Query().Get("t") {
					t.Fatal("decision binding mismatch")
				}
				response := f.request(false, call.Method, call.Path, []byte(call.Body))
				if tc.wantStatus == "pending" || tc.expired || tc.previouslyDenied {
					if response.Code < 400 {
						t.Fatal("invalid decision accepted")
					}
				} else if response.Code != 200 {
					t.Fatal("valid decision rejected")
				}
			}
			after, err := f.store.Get(a.ID, f.now)
			if err != nil || after.Status != tc.wantStatus {
				t.Fatal("unexpected persisted decision")
			}
			if f.mail.calls != 1 {
				t.Fatal("decision resent mail")
			}
			if tc.lost && !strings.Contains(result.Message, "결과를 확인할 수 없습니다") {
				t.Fatal("lost response did not remain uncertain")
			}
			if tc.badDigest && !strings.Contains(result.Message, "원래 링크") {
				t.Fatal("conflict recovery missing")
			}
			if strings.Contains(result.Message, link.Query().Get("t")) && !tc.noToken {
				t.Fatal("token reflected")
			}
			// Opening the link after uncertain delivery reads state, never resubmits.
			if !tc.noToken {
				get := f.request(false, "GET", f.mail.link, nil)
				if get.Code != 200 {
					t.Fatal("recovery link unavailable")
				}
				state, err := f.store.Get(a.ID, f.now)
				if err != nil || state.Status != after.Status {
					t.Fatal("GET changed decision")
				}
			}
		})
	}
}
