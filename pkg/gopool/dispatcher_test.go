package gopool

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDispatcher(t *testing.T) {
	var wg sync.WaitGroup

	const maxJobs = 4
	const maxWorker = 2
	jobQueue := make(chan Job, maxJobs)
	dispatcher := NewDispatcher(jobQueue, maxWorker)
	dispatcher.Run()
	var count int64
	task1 := NewTask(func() {
		fmt.Println("aa")
		atomic.AddInt64(&count, int64(1))
	})
	task2 := NewTask(func() {
		fmt.Println("bb")
		atomic.AddInt64(&count, int64(1))
	})
	jobQueue <- task1
	jobQueue <- task2

	wg.Add(1)
	time.AfterFunc(time.Second, func() {
		if count != 2 {
			t.Errorf("Expected to run 2 tasks, found %v", count)
		}
		wg.Done()
	})
	wg.Wait()
}
