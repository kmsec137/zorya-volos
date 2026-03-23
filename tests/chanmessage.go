package main

import (
	"fmt"
	"os"
	"sync"
)

// Global mutex to simulate a "secure" gated entry to the channel
var lock sync.Mutex

func main() {
	// 1. Basic Argument Parsing
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go [secure|insecure] [message]")
		return
	}

	mode := os.Args[1]
	message := os.Args[2]

	// Create a string channel for communication
	ch := make(chan string)
	var wg sync.WaitGroup
	wg.Add(2)

	// 2. The Sender Goroutine
	go func() {
		defer wg.Done()
		if mode == "secure" {
			lock.Lock()
			fmt.Println("[Sender] Mutex LOCKED (Secure Mode)")
			ch <- message
			lock.Unlock()
			fmt.Println("[Sender] Mutex UNLOCKED")
		} else {
			fmt.Println("[Sender] Sending without Mutex (Insecure Mode)")
			ch <- message
		}
	}()

	// 3. The Receiver Goroutine
	go func() {
		defer wg.Done()
		receivedMsg := <-ch
		fmt.Printf("[Receiver] Got message: %s\n", receivedMsg)
	}()

	wg.Wait()
	fmt.Println("Program finished.")
}
