package protocol

type FileRoot struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Read  bool   `json:"read"`
	Write bool   `json:"write"`
}
type FileSupport struct {
	Roots []FileRoot `json:"roots"`
}
type FileJob struct {
	ID        string `json:"id"`
	Operation string `json:"operation"`
	Root      string `json:"root"`
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	Hash      string `json:"sha256"`
	Data      []byte `json:"data,omitempty"`
	ExpiresAt int64  `json:"expires_at"`
}
type FileEntry struct {
	Name      string `json:"name"`
	Directory bool   `json:"directory"`
	Size      int64  `json:"size"`
	Modified  int64  `json:"modified_at"`
}
type FileResult struct {
	ID      string      `json:"id"`
	Outcome string      `json:"outcome"`
	Entries []FileEntry `json:"entries,omitempty"`
	More    bool        `json:"more"`
	Size    int64       `json:"size"`
	Hash    string      `json:"sha256"`
	Data    []byte      `json:"data,omitempty"`
}
type FileDispatch struct {
	Job *FileJob `json:"job"`
}
