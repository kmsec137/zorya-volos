package main

import (
	"fmt"
	"os"
	"strconv"
	"sync"
)

var (
	sharedCounter int
	mu            sync.Mutex
	wg            sync.WaitGroup
)

func main() {
	// Basic check to ensure we have at least the mode and iterations
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <a|b> [extra_arg_for_lock] <iterations>")
		return
	}

	mode := os.Args[1]
	// If total args > 3 (prog + mode + iterations), we have an "extra" arg
	useLock := len(os.Args) > 3
	
	// Adjust index for iterations based on whether the extra arg is there
	iterIdx := 2
	if useLock {
		iterIdx = 3
	}
	iterations, _ := strconv.Atoi(os.Args[iterIdx])

	switch mode {
	case "a":
		fmt.Printf("Running Mode A (1 Thread). Lock Enabled: %v\n", useLock)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if useLock {
					mu.Lock()
					sharedCounter++
					mu.Unlock()
				} else {
					// STATICALLY CODED: Naked read/write
					sharedCounter++
				}
			}
		}()

	case "b":
		fmt.Printf("Running Mode B (2 Threads). Lock Enabled: %v\n", useLock)
		wg.Add(2)
		// Thread 1
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if useLock {
					mu.Lock()
					sharedCounter++
					mu.Unlock()
				} else {
					sharedCounter++
				}
			}
		}()
		// Thread 2
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if useLock {
					mu.Lock()
					sharedCounter++
					mu.Unlock()
				} else {
					sharedCounter++
				}
			}
		}()

	default:
		fmt.Println("Please choose mode 'a' or 'b'")
		return
	}

	wg.Wait()
	fmt.Printf("Final Counter: %d\n", sharedCounter)
}
