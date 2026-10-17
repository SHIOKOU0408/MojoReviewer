package feishu

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mojoreviewer/mojoreviewer/internal/github"
)

func TestURLVerification(t *testing.T) {
	ch := &Channel{AppID: "cli_test", VerificationToken: "token-1"}
	body := []byte(`{"type":"url_verification","token":"token-1","challenge":"abc"}`)
	rec := httptest.NewRecorder()
	ch.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/feishu/events", bytes.NewReader(body)))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"challenge":"abc"`) {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestRejectsBadToken(t *testing.T) {
	ch := &Channel{AppID: "cli_test", VerificationToken: "token-1"}
	body := []byte(`{"schema":"2.0","header":{"event_id":"e1","event_type":"im.message.receive_v1","token":"nope","app_id":"cli_test"},"event":{"sender":{"sender_type":"user","sender_id":{"open_id":"ou_1"}},"message":{"message_id":"om_1","chat_id":"oc_1","message_type":"text","content":"{\"text\":\"帮助\"}"}}}`)
	rec := httptest.NewRecorder()
	ch.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/feishu/events", bytes.NewReader(body)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestEnqueueFromTextEvent(t *testing.T) {
	var got github.Review
	api, posts := fakeAPI(t)
	ch := &Channel{
		AppID:             "cli_test",
		VerificationToken: "token-1",
		AllowedChats:      map[string]bool{"oc_1": true},
		AllowedUsers:      map[string]bool{"ou_1": true},
		API:               api,
		Enqueue: func(_ context.Context, item github.Review) error {
			got = item
			return nil
		},
	}
	body := []byte(`{"schema":"2.0","header":{"event_id":"e1","event_type":"im.message.receive_v1","token":"token-1","app_id":"cli_test"},"event":{"sender":{"sender_type":"user","sender_id":{"open_id":"ou_1"}},"message":{"message_id":"om_1","chat_id":"oc_1","message_type":"text","content":"{\"text\":\"审查 fullac/MojoReviewer#23\"}"}}}`)
	rec := httptest.NewRecorder()
	ch.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/feishu/events", bytes.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if got.Repo != "fullac/MojoReviewer" || got.Number != 23 || got.Intent != github.IntentReview {
		t.Fatalf("enqueue %+v", got)
	}
	if got.AttemptID != "feishu:om_1" {
		t.Fatalf("attempt %s", got.AttemptID)
	}
	if !strings.Contains(posts.String(), "已入队") {
		t.Fatalf("reply %s", posts.String())
	}

	rec = httptest.NewRecorder()
	ch.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/feishu/events", bytes.NewReader(body)))
	if !strings.Contains(rec.Body.String(), "duplicate") {
		t.Fatalf("duplicate body %s", rec.Body.String())
	}
}

func TestEncryptedCallback(t *testing.T) {
	plain := []byte(`{"type":"url_verification","token":"token-1","challenge":"cipher"}`)
	key := sha256.Sum256([]byte("encrypt-key"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	iv := bytes.Repeat([]byte{1}, aes.BlockSize)
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	blob := append(iv, out...)
	body, _ := json.Marshal(map[string]string{"encrypt": base64.StdEncoding.EncodeToString(blob)})
	sum := sha256.Sum256([]byte("ts" + "nonce" + "encrypt-key" + string(body)))
	req := httptest.NewRequest(http.MethodPost, "/feishu/events", bytes.NewReader(body))
	req.Header.Set("X-Lark-Request-Timestamp", "ts")
	req.Header.Set("X-Lark-Request-Nonce", "nonce")
	req.Header.Set("X-Lark-Signature", strings.ToLower(fmtHex(sum[:])))
	ch := &Channel{VerificationToken: "token-1", EncryptKey: "encrypt-key"}
	rec := httptest.NewRecorder()
	ch.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "cipher") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestRejectsDisallowedChat(t *testing.T) {
	api, posts := fakeAPI(t)
	var called bool
	ch := &Channel{
		AppID: "cli_test", VerificationToken: "token-1",
		AllowedChats: map[string]bool{"oc_ok": true},
		API:          api,
		Enqueue: func(context.Context, github.Review) error {
			called = true
			return nil
		},
	}
	body := []byte(`{"schema":"2.0","header":{"event_id":"e2","token":"token-1","app_id":"cli_test","event_type":"im.message.receive_v1"},"event":{"sender":{"sender_type":"user","sender_id":{"open_id":"ou_1"}},"message":{"message_id":"om_2","chat_id":"oc_no","message_type":"text","content":"{\"text\":\"帮助\"}"}}}`)
	rec := httptest.NewRecorder()
	ch.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/feishu/events", bytes.NewReader(body)))
	if called || posts.Len() != 0 {
		t.Fatalf("disallowed chat should be silent, called=%v posts=%s", called, posts.String())
	}
}

func fakeAPI(t *testing.T) (*API, *bytes.Buffer) {
	t.Helper()
	var posts bytes.Buffer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		switch {
		case strings.Contains(r.URL.Path, "tenant_access_token"):
			_, _ = w.Write([]byte(`{"code":0,"tenant_access_token":"t","expire":7200}`))
		default:
			posts.Write(raw)
			_, _ = w.Write([]byte(`{"code":0,"msg":"ok","data":{"message_id":"om_out"}}`))
		}
	}))
	t.Cleanup(srv.Close)
	return &API{AppID: "id", AppSecret: "secret", BaseURL: srv.URL, Client: srv.Client()}, &posts
}

func fmtHex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}
