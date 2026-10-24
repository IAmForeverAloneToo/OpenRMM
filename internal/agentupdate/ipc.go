package agentupdate

import "github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"

type IPCRequest struct {
	Op      string                    `json:"op"`
	Job     *protocol.AgentUpgradeJob `json:"job,omitempty"`
	ID      string                    `json:"id,omitempty"`
	Version string                    `json:"version,omitempty"`
}
type IPCReply struct {
	Support *protocol.AgentUpgradeSupport `json:"support,omitempty"`
	Result  *protocol.AgentUpgradeResult  `json:"result,omitempty"`
	Error   string                        `json:"error,omitempty"`
}

func (b *Broker) Handle(r IPCRequest, pid uint32) IPCReply {
	switch r.Op {
	case "probe":
		if r.Job == nil && r.ID == "" && r.Version == "" {
			s := b.Probe()
			return IPCReply{Support: &s}
		}
	case "submit":
		if r.Job != nil && r.ID == "" && r.Version == "" {
			v := b.Submit(*r.Job)
			return IPCReply{Result: &v}
		}
	case "status":
		if r.Job == nil && r.Version == "" && protocol.ValidID(r.ID) {
			v := b.Status(r.ID)
			return IPCReply{Result: &v}
		}
	case "healthy":
		if r.Job == nil && r.ID == "" && Version(r.Version) {
			b.Healthy(pid, r.Version)
			return IPCReply{}
		}
	}
	return IPCReply{Error: "unavailable"}
}
