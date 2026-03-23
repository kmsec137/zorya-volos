package main

import (
	"fmt"
	"os"
	"strconv"
	"sync"
)

func main() {
	// Need 3 user args: <char> <dummy_arg> <iterations>
	if len(os.Args) != 4 {
		fmt.Println("Usage: go run main.go <a|b|c|d> <any> <iterations>")
		return
	}

	mode := os.Args[1]
	iterations, _ := strconv.Atoi(os.Args[3])

	// Map char to number of threads/locks
	threadCount := 0
	switch mode {
	case "a": threadCount = 1
	case "b": threadCount = 2
	case "c": threadCount = 3
	case "d": threadCount = 4
	default:
		fmt.Println("First arg must be a, b, c, or d")
		return
	}

	fmt.Printf("Starting %d threads with %d iterations each...\n", threadCount, iterations)

	var wg sync.WaitGroup
	sharedCounter := 0

	// We create a slice of locks, one for each thread
	locks := make([]*sync.Mutex, threadCount)
	for i := 0; i < threadCount; i++ {
		locks[i] = &sync.Mutex{}
	}

	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		// Capture the loop variable for the goroutine
		threadID := i
		
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				// Each thread uses its OWN lock
				// This is a 'lockset violation' if they touch the same data
				locks[id].Lock()
				sharedCounter++
				locks[id].Unlock()
			}
		}(threadID)
	}

	wg.Wait()
	
	expected := threadCount * iterations
	fmt.Printf("Final Counter: %d (Expected: %d)\n", sharedCounter, expected)
	
	if sharedCounter != expected {
		fmt.Println("RACE CONDITION DETECTED: Locks were independent!")
	} else if threadCount > 1 {
		fmt.Println("Note: If this matched, it might just be lucky timing on your CPU.")
	}
}
