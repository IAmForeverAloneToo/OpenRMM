package protocol

type EventLogSupport struct {
	System      string `json:"system"`
	Application string `json:"application"`
	// Channels reports readability of further well-known channels (capability
	// version 2); others can still be queried by name.
	Channels map[string]string `json:"channels,omitempty"`
}
type EventFilter struct {
	Channel  string `json:"channel"`
	From     int64  `json:"from"`
	To       int64  `json:"to"`
	Level    int    `json:"level"`
	Provider string `json:"provider"`
	EventID  int    `json:"event_id"`
	Before   uint64 `json:"before"`
	Limit    int    `json:"limit"`
	// XPath is an additional raw event XPath predicate such as
	// *[EventData[Data[@Name='LogonType']='10']] (capability version 2).
	XPath string `json:"xpath,omitempty"`
}
type EventQuery struct {
	ID     string      `json:"id"`
	Filter EventFilter `json:"filter"`
}
type EventDispatch struct {
	Query *EventQuery `json:"query"`
}
type WindowsEvent struct {
	RecordID      uint64 `json:"record_id"`
	EventID       uint32 `json:"event_id"`
	Level         int    `json:"level"`
	Provider      string `json:"provider"`
	Channel       string `json:"channel"`
	Time          int64  `json:"time"`
	Message       string `json:"message"`
	MessageStatus string `json:"message_status"`
	XML           string `json:"xml"`
	XMLTruncated  bool   `json:"xml_truncated"`
}
type EventResult struct {
	ID         string         `json:"id"`
	Outcome    string         `json:"outcome"`
	Events     []WindowsEvent `json:"events"`
	More       bool           `json:"more"`
	NextBefore uint64         `json:"next_before"`
	// Skipped counts matching events left out because they could not be read or
	// failed validation. Omitted by agents that predate it.
	Skipped int `json:"skipped,omitempty"`
}
