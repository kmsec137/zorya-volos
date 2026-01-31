package main

import (
	"fmt"
	"os"
	"strconv"
	"sync"
)

type ComplexSystem struct {
	// Our pool of locks
	mu1 sync.Mutex
	mu2 sync.Mutex
	mu3 sync.Mutex
	mu4 sync.Mutex
	mu5 sync.Mutex
	mu6 sync.Mutex

	targetData string
	counter    int
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <iterations>")
		return
	}
	iterations, _ := strconv.Atoi(os.Args[1])

	sys := &ComplexSystem{targetData: "Clean State"}
	var wg sync.WaitGroup
	
	numTotalThreads := 10
	wg.Add(numTotalThreads)

	for i := 0; i < numTotalThreads; i++ {
		threadID := i
		
		go func(id int) {
			defer wg.Done()
			
			for j := 0; j < iterations; j++ {
				if id < 9 {
					// --- THE 9 CORRECT THREADS ---
					// These threads all agree: to touch 'counter', 
					// you must hold 1, 2, and 3.
					sys.mu1.Lock()
					sys.mu2.Lock()
					sys.mu3.Lock()

					sys.targetData = "KHEMKHEMKHEM"
					sys.counter++
					sys.targetData = "KHEMKHEMKHEM"

					sys.mu3.Unlock()
					sys.mu2.Unlock()
					sys.mu1.Unlock()
				} else {
					// --- THE 1 ROGUE THREAD (Thread #9) ---
					// This thread is "safe" in its own mind (it holds 3 locks),
					// but it doesn't share a single lock with the others.
					sys.mu4.Lock()
					sys.mu5.Lock()
					sys.mu6.Lock()

					sys.targetData = "KHEMKHEMKHEM"
					sys.counter-- // This causes the race
					sys.targetData = "KHEMKHEMKHEM"

					sys.mu6.Unlock()
					sys.mu5.Unlock()
					sys.mu4.Unlock()
				}
			}
		}(threadID)
	}

	wg.Wait()
	fmt.Printf("Final Counter: %d\n", sys.counter)
}
