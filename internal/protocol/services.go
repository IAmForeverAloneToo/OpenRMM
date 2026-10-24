package protocol

type WindowsService struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	State       string `json:"state"`
	CanStart    bool   `json:"can_start"`
	CanStop     bool   `json:"can_stop"`
}
type Services struct {
	Items      []WindowsService `json:"items"`
	Visibility string           `json:"visibility"`
}
type ServiceAction struct {
	ID        string `json:"id"`
	Service   string `json:"service"`
	Action    string `json:"action"`
	ExpiresAt int64  `json:"expires_at"`
}
type ServiceDispatch struct {
	Action *ServiceAction `json:"action"`
}
type ServiceResult struct {
	ID      string `json:"id"`
	Outcome string `json:"outcome"`
	State   string `json:"state"`
}
