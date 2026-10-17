package feishu

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mojoreviewer/mojoreviewer/internal/github"
)

const maxCallbackBody = 1 << 20

// Enqueue 把一条已解析的审查任务交给宿主。通道不调用 agent.Runner。
type Enqueue func(ctx context.Context, item github.Review) error

// StatusFunc 返回通道可以展示的运行状态。可以为空。
type StatusFunc func() string

// Channel 是飞书事件回调适配。它只做验签、解密、命令解析和回复。
type Channel struct {
	AppID             string
	VerificationToken string
	EncryptKey        string
	AllowedChats      map[string]bool
	AllowedUsers      map[string]bool
	Enqueue           Enqueue
	Status            StatusFunc
	API               *API

	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

// Handler 返回可挂到独立路由的 HTTP 处理函数。
func (c *Channel) Handler() http.Handler {
	return http.HandlerFunc(c.ServeHTTP)
}

func (c *Channel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxCallbackBody))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 400, "msg": "读取失败"})
		return
	}
	payload, err := c.open(r, body)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"code": 403, "msg": "校验失败"})
		return
	}
	var envelope callbackEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 400, "msg": "事件无法解析"})
		return
	}
	if envelope.Type == "url_verification" || envelope.Challenge != "" && envelope.Header.EventType == "" && envelope.Event.Message.MessageID == "" {
		if !secureEqual(envelope.Token, c.VerificationToken) {
			writeJSON(w, http.StatusForbidden, map[string]any{"code": 403, "msg": "校验失败"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"challenge": envelope.Challenge})
		return
	}
	token := envelope.Header.Token
	if token == "" {
		token = envelope.Token
	}
	if !secureEqual(token, c.VerificationToken) {
		writeJSON(w, http.StatusForbidden, map[string]any{"code": 403, "msg": "校验失败"})
		return
	}
	if appID := strings.TrimSpace(envelope.Header.AppID); appID != "" && !secureEqual(appID, c.AppID) {
		writeJSON(w, http.StatusForbidden, map[string]any{"code": 403, "msg": "校验失败"})
		return
	}
	eventType := envelope.Header.EventType
	if eventType != "" && eventType != "im.message.receive_v1" {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ignored"})
		return
	}
	if id := strings.TrimSpace(envelope.Header.EventID); id != "" && c.duplicate(id) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "duplicate"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
	c.dispatch(envelope.Event)
}

func (c *Channel) open(r *http.Request, body []byte) ([]byte, error) {
	var encrypted struct {
		Encrypt string `json:"encrypt"`
	}
	_ = json.Unmarshal(body, &encrypted)
	if strings.TrimSpace(c.EncryptKey) != "" {
		if strings.TrimSpace(encrypted.Encrypt) == "" {
			return nil, fmt.Errorf("缺少密文")
		}
		if !verifyCallbackSignature(r, body, c.EncryptKey) {
			return nil, fmt.Errorf("签名无效")
		}
		return decryptEvent(c.EncryptKey, encrypted.Encrypt)
	}
	if strings.TrimSpace(encrypted.Encrypt) != "" {
		return nil, fmt.Errorf("未配置加密密钥")
	}
	return body, nil
}

func (c *Channel) duplicate(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]time.Time{}
	}
	now := time.Now()
	if c.now != nil {
		now = c.now()
	}
	for key, at := range c.seen {
		if now.Sub(at) > 10*time.Minute {
			delete(c.seen, key)
		}
	}
	if _, ok := c.seen[id]; ok {
		return true
	}
	c.seen[id] = now
	return false
}

func (c *Channel) dispatch(event messageEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	reply := func(text string) {
		if c.API == nil {
			log.Printf("飞书通道未配置发送客户端")
			return
		}
		if err := c.API.ReplyText(ctx, event.Message.ChatID, event.Message.MessageID, text); err != nil {
			log.Printf("飞书回复失败: %v", err)
		}
	}
	if strings.EqualFold(strings.TrimSpace(event.Sender.SenderType), "bot") || event.Sender.SenderType == "" && event.Sender.SenderID.OpenID == "" {
		return
	}
	sender := firstNonEmpty(event.Sender.SenderID.OpenID, event.Sender.SenderID.UserID, event.Sender.SenderID.UnionID)
	if !allowed(c.AllowedUsers, sender) || !allowed(c.AllowedChats, event.Message.ChatID) {
		return
	}
	if strings.ToLower(strings.TrimSpace(event.Message.MessageType)) != "text" && event.Message.MessageType != "" {
		reply("目前只接受文本指令。发送「帮助」查看用法。")
		return
	}
	text, err := textOf(event.Message.Content)
	if err != nil {
		reply("无法读取消息文本。")
		return
	}
	cmd, err := ParseCommand(text)
	if err != nil {
		reply(err.Error() + "\n\n" + HelpText())
		return
	}
	switch cmd.Kind {
	case KindHelp:
		reply(HelpText())
	case KindStatus:
		status := "飞书通道在线。审查状态请看 reviewer 活动记录。"
		if c.Status != nil {
			if extra := strings.TrimSpace(c.Status()); extra != "" {
				status = extra
			}
		}
		reply(status)
	case KindEnqueue:
		if c.Enqueue == nil {
			reply("审查入队未接线。")
			return
		}
		item := github.Review{
			Repo:        cmd.Repo,
			Number:      cmd.Number,
			Comment:     text,
			Instruction: cmd.Instruction,
			Intent:      cmd.Intent,
			Author:      sender,
			SessionKey:  fmt.Sprintf("%s#%d", cmd.Repo, cmd.Number),
			AttemptID:   "feishu:" + strings.TrimSpace(event.Message.MessageID),
		}
		if err := c.Enqueue(ctx, item); err != nil {
			reply("没有入队：" + err.Error())
			return
		}
		reply(fmt.Sprintf("已入队 %s #%d（%s）。审查仍由 reviewer 执行，结果发到 PR 评论。", cmd.Repo, cmd.Number, cmd.Intent))
	default:
		reply(HelpText())
	}
}

func textOf(content string) (string, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return "", fmt.Errorf("空内容")
	}
	if !strings.HasPrefix(content, "{") {
		return content, nil
	}
	var parsed struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		return "", err
	}
	return strings.TrimSpace(parsed.Text), nil
}

func allowed(list map[string]bool, value string) bool {
	if len(list) == 0 {
		return true
	}
	value = strings.TrimSpace(value)
	return value != "" && list[value]
}

func secureEqual(got, want string) bool {
	got = strings.TrimSpace(got)
	want = strings.TrimSpace(want)
	if want == "" || len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func verifyCallbackSignature(r *http.Request, body []byte, encryptKey string) bool {
	timestamp := r.Header.Get("X-Lark-Request-Timestamp")
	nonce := r.Header.Get("X-Lark-Request-Nonce")
	provided := strings.TrimSpace(r.Header.Get("X-Lark-Signature"))
	if timestamp == "" || nonce == "" || provided == "" {
		return false
	}
	sum := sha256.Sum256([]byte(timestamp + nonce + encryptKey + string(body)))
	expected := fmt.Sprintf("%x", sum[:])
	if len(provided) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.ToLower(provided)), []byte(expected)) == 1
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
