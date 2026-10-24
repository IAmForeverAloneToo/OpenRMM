package terminal

// Shell is a single live OS process tree. Implementations must bound output,
// terminate descendants on Close/parent death, and never restart a shell.
type Shell interface {
	Input([]byte) error
	Drain() ([]byte, bool)
	Close()
}
