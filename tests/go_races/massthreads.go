package main

import (
	"fmt"
	"os"     // Required for Args
	"strconv" // Required to convert strings to ints
	"sync"
)

type Database struct {
	mu      sync.Mutex
	records map[int]string
	queries int
}

func main() {
	// os.Args provides: [path/to/bin, arg1, arg2, arg3]
	if len(os.Args) < 4 {
		fmt.Println("Usage: go run main.go <safeCount> <lazyCount> <rogueCount>")
		return
	}

	// Convert string arguments to integers
	safeCount, _ := strconv.Atoi(os.Args[1])
	lazyCount, _ := strconv.Atoi(os.Args[2])
	rogueCount, _ := strconv.Atoi(os.Args[3])

	fmt.Printf("Starting: %d Safe, %d Lazy, %d Rogue\n", safeCount, lazyCount, rogueCount)

	db := &Database{
		records: make(map[int]string),
	}
	var wg sync.WaitGroup
	wg.Add(safeCount + lazyCount + rogueCount)

	// --- Safe Goroutines ---
	for i := 0; i < safeCount; i++ {
		id := i
		go func() {
			defer wg.Done()
			db.mu.Lock()
			db.records[id] = "Safe"
			db.queries++
			db.mu.Unlock()
		}()
	}

	// --- Lazy Goroutines ---
	for i := 0; i < lazyCount; i++ {
		id := i + 1000
		go func() {
			defer wg.Done()
			_ = db.queries // Unsafe read
			db.mu.Lock()
			db.records[id] = "Lazy"
			db.mu.Unlock()
		}()
	}

	// --- Rogue Goroutines ---
	for i := 0; i < rogueCount; i++ {
		id := i + 2000
		go func() {
			defer wg.Done()
			db.records[id] = "Rogue" // Total chaos
			db.queries--
		}()
	}

	wg.Wait()
	fmt.Println("Done.")
}
