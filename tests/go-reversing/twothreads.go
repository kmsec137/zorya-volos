package main

import (
	"fmt"
	"sync"
	"time"
)

var (
	sharedData = "Initial State"
	mutex      sync.Mutex
)

func main() {
	// ThreadA
	mutex.Lock()
	mutex.Unlock()

	go func() {
		for i := 0; i < 3; i++ {
			mutex.Lock()
			fmt.Println("[ThreadA] Locked Read:", sharedData)
			mutex.Unlock()
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// ThreadB
	go func() {
		for i := 0; i < 3; i++ {
			// No lock taken
			fmt.Println("[ThreadB] Unsafe Read:", sharedData)
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Instead of a WaitGroup, we just block the main thread manually
	// If we don't do this, the program ends immediately.
	time.Sleep(500 * time.Millisecond) 
	fmt.Println("Main thread exiting.")
}
