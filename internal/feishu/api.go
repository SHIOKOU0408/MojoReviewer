package feishu

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultAPIBase   = "https://open.feishu.cn"
	tokenRefreshSkew = time.Minute
	maxReplyBytes    = 12000
)

// API 是飞书开放平台的最小客户端：租户令牌、回复文本。
// 不依赖 LuckyAgent gateway，也不持有审查状态。
type API struct {
	AppID     string
	AppSecret string
	BaseURL   string
	Client    *http.Client

	now func() time.Time

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

func (a *API) base() string {
	base := strings.TrimRight(strings.TrimSpace(a.BaseURL), "/")
	if base == "" {
		return defaultAPIBase
	}
	return base
}

func (a *API) client() *http.Client {
	if a.Client != nil {
		return a.Client
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (a *API) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

type tokenResponse struct {
	Code              int    `json:"code"`
	Msg               string `json:"msg"`
	TenantAccessToken string `json:"tenant_access_token"`
	Expire            int    `json:"expire"`
}

func (a *API) tenantToken(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != "" && a.clock().Before(a.tokenExpiry.Add(-tokenRefreshSkew)) {
		return a.token, nil
	}
	body, err := json.Marshal(map[string]string{
		"app_id":     strings.TrimSpace(a.AppID),
		"app_secret": strings.TrimSpace(a.AppSecret),
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base()+"/open-apis/auth/v3/tenant_access_token/internal", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("获取飞书令牌: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var parsed tokenResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("解析飞书令牌: %w", err)
	}
	if resp.StatusCode != http.StatusOK || parsed.Code != 0 || strings.TrimSpace(parsed.TenantAccessToken) == "" {
		return "", fmt.Errorf("飞书令牌失败: http %d code %d", resp.StatusCode, parsed.Code)
	}
	expire := parsed.Expire
	if expire <= 0 {
		expire = 3600
	}
	a.token = parsed.TenantAccessToken
	a.tokenExpiry = a.clock().Add(time.Duration(expire) * time.Second)
	return a.token, nil
}

// ReplyText 回复一条文本消息。messageID 为空时发到 chatID。
func (a *API) ReplyText(ctx context.Context, chatID, messageID, text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		text = " "
	}
	if len(text) > maxReplyBytes {
		text = text[:maxReplyBytes] + "\n…（已截断）"
	}
	content, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return err
	}
	payload := map[string]string{
		"msg_type": "text",
		"content":  string(content),
	}
	var path string
	if id := strings.TrimSpace(messageID); id != "" {
		path = "/open-apis/im/v1/messages/" + url.PathEscape(id) + "/reply"
	} else {
		chatID = strings.TrimSpace(chatID)
		if chatID == "" {
			return fmt.Errorf("飞书回复缺少 chat_id")
		}
		payload["receive_id"] = chatID
		path = "/open-apis/im/v1/messages?receive_id_type=chat_id"
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	token, err := a.tenantToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base()+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := a.client().Do(req)
	if err != nil {
		return fmt.Errorf("发送飞书消息: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var parsed struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("解析飞书发送结果: %w", err)
	}
	if resp.StatusCode != http.StatusOK || parsed.Code != 0 {
		return fmt.Errorf("飞书发送失败: http %d code %d", resp.StatusCode, parsed.Code)
	}
	return nil
}
