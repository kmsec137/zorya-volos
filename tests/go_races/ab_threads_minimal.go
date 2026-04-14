package main

import (
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
	if len(os.Args) < 3 {
		return
	}

	mode := os.Args[1]
	useLock := len(os.Args) > 3

	iterIdx := 2
	if useLock {
		iterIdx = 3
	}
	iterations, _ := strconv.Atoi(os.Args[iterIdx])

	switch mode {
	case "a":
		wg.Add(1)
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

	case "b":
		wg.Add(2)
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
		return
	}

	wg.Wait()
}
