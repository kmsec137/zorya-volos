package main

import (
	"sync"
)

type Config struct {
	Data int
}

func main() {
	var activeConfig *Config = &Config{Data: 0}
	var wg sync.WaitGroup
	mu := sync.Mutex{}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		id := i
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if id%2 == 0 {
					// Thread type A: Updates the pointer with a lock
					mu.Lock()
					activeConfig = &Config{Data: j} 
					mu.Unlock()
				} else {
					// Thread type B: Reads the pointer WITHOUT a lock
					// This is a race because 'activeConfig' is being changed
					_ = activeConfig.Data 
				}
			}
		}()
	}

	wg.Wait()
}
