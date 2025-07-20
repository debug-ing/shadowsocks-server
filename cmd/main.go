package main

import (
	"errors"
	"io"
	"log"
	"net"
	"os"
	"shadowsocks-learn/core"
	"sync"
	"time"

	"shadowsocks-learn/socks"
)

func main() {
	cipher := "AEAD_CHACHA20_POLY1305"
	password := "your-password"

	ciph, err := core.PickCipher(cipher, nil, password)
	if err != nil {
		log.Fatal(err)
	}
	go func(addr string) {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return
		}
		for {
			c, err := l.Accept()
			if err != nil {
				continue
			}
			sc := ciph.StreamConn(c)
			tgt, err := socks.ReadAddr(sc)
			if err != nil {
				_, err = io.Copy(io.Discard, c)
				if err != nil {
				}
				return
			}
			rc, err := net.Dial("tcp", tgt.String())
			if err != nil {
				return
			}
			defer rc.Close()
			if err = stream(sc, rc); err != nil {
			}
		}
	}(":8488")
	for {

	}
}

func stream(left, right net.Conn) error {
	var err, err1 error
	var wg sync.WaitGroup
	var wait = 5 * time.Second
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err1 = io.Copy(right, left)
		right.SetReadDeadline(time.Now().Add(wait))
	}()
	_, err = io.Copy(left, right)
	left.SetReadDeadline(time.Now().Add(wait))
	wg.Wait()
	if err1 != nil && !errors.Is(err1, os.ErrDeadlineExceeded) { // requires Go 1.15+
		return err1
	}
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	return nil
}
