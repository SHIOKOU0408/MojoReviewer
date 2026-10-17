package feishu

// callbackEnvelope 是飞书事件订阅 2.0，也兼容 url_verification。
type callbackEnvelope struct {
	Schema    string         `json:"schema"`
	Header    callbackHeader `json:"header"`
	Event     messageEvent   `json:"event"`
	Type      string         `json:"type"`
	Token     string         `json:"token"`
	Challenge string         `json:"challenge"`
	Encrypt   string         `json:"encrypt"`
}

type callbackHeader struct {
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	Token     string `json:"token"`
	AppID     string `json:"app_id"`
}

type messageEvent struct {
	Sender  eventSender  `json:"sender"`
	Message eventMessage `json:"message"`
}

type eventSender struct {
	SenderID   eventUserID `json:"sender_id"`
	SenderType string      `json:"sender_type"`
}

type eventUserID struct {
	UnionID string `json:"union_id"`
	UserID  string `json:"user_id"`
	OpenID  string `json:"open_id"`
}

type eventMessage struct {
	MessageID   string `json:"message_id"`
	ChatID      string `json:"chat_id"`
	ChatType    string `json:"chat_type"`
	MessageType string `json:"message_type"`
	Content     string `json:"content"`
}
