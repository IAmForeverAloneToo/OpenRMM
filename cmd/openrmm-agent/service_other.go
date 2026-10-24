//go:build !windows

package main

func platformService([]string) (bool, int) { return false, 0 }
