package main

import (
	"runtime"
	"sync"
	"time"
)

func main() {
	// 1. runtime.newproc / newproc1
	// Spawning a goroutine is the classic "Fork" event for a Vector Clock.
	done := make(chan bool)
	ch := make(chan int, 1)

	go func() {
		// 2. runtime.chanrecv / chanrecv1 / chanrecv2
		// This node will block until the main thread sends data.
		val := <-ch
		println("Received:", val)

		// 3. runtime.lock / lock2
		// We use a Mutex to trigger the locking runtime symbols.
		mu := &sync.Mutex{}
		mu.Lock() 
		
		// Small sleep ensures that if another thread tried to lock, 
		// it would hit the 'slow path' (lock2).
		time.Sleep(10 * time.Millisecond) 
		
		// 4. runtime.unlock / unlock2
		mu.Unlock()

		done <- true
	}()

	// 5. runtime.chansend / chansend1 / chansend2
	// This creates a causal "Happens-Before" link from main -> goroutine.
	ch <- 42

	// Wait for the goroutine to finish its work
	<-done
	
	// Final yield to ensure all scheduler events are processed
	runtime.Gosched()
}
