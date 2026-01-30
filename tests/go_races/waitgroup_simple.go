package main

import (
	"fmt"
	"sync"
)

type SafeCounter struct {
	mu    sync.Mutex
	value int
}

func main() {
	sc := &SafeCounter{}
	var wg sync.WaitGroup

	// 9 Threads playing by the rules
	for i := 0; i < 9; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				sc.mu.Lock()
				sc.value++
				sc.mu.Unlock()
			}
		}()
	}

	// The 10th "Rogue" Thread: Accessing without a lock
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 100; j++ {
			sc.value++ // DATA RACE: This ignores the mutex entirely
		}
	}()

	wg.Wait()
	fmt.Printf("Final Value: %d\n", sc.value)
}
