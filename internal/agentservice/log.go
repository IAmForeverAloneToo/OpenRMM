// Package agentservice contains the Windows host for the existing agent loop.
package agentservice

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

const LogLimit = 1024 * 1024
const LogFiles = 3

// Log retains one active file and two backups. Its directory must be provisioned
// with service-only write access by the elevated installer.
type Log struct {
	mu    sync.Mutex
	path  string
	file  *os.File
	size  int64
	limit int64
}

func OpenLog(directory string) (*Log, error) {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("service log directory is unavailable")
	}
	l := &Log{path: filepath.Join(directory, "agent.log"), limit: LogLimit}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Log) open() error {
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("cannot open service log")
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return errors.New("cannot inspect service log")
	}
	l.file, l.size = file, info.Size()
	return nil
}

func (l *Log) rotate() error {
	if err := l.file.Close(); err != nil {
		return err
	}
	l.file = nil
	oldest := l.path + "." + strconv.Itoa(LogFiles-1)
	if err := os.Remove(oldest); err != nil && !os.IsNotExist(err) {
		return err
	}
	for i := LogFiles - 2; i >= 1; i-- {
		if err := os.Rename(l.path+"."+strconv.Itoa(i), l.path+"."+strconv.Itoa(i+1)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Rename(l.path, l.path+".1"); err != nil {
		return err
	}
	return l.open()
}

func (l *Log) Write(value []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return 0, os.ErrClosed
	}
	if int64(len(value)) > l.limit {
		return 0, errors.New("service log record exceeds limit")
	}
	if l.size+int64(len(value)) > l.limit {
		if err := l.rotate(); err != nil {
			return 0, errors.New("cannot rotate service log")
		}
	}
	n, err := l.file.Write(value)
	l.size += int64(n)
	if err == nil && n != len(value) {
		err = io.ErrShortWrite
	}
	return n, err
}

func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}
