package main

import (
	"testing"
	"time"
)

func TestBreakHmacSHA1(t *testing.T) {
	go spawn([]byte("We all live in a yellow submarine"))
	time.Sleep(time.Second)
}
