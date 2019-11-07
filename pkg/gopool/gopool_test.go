package gopool

import "testing"

func TestWorker(t *testing.T) {
	jobGotRun := false
	pool := make(chan chan Job, 1)
	worker := NewWorker(pool)
	worker.Start()
	job := NewTask(func() {
		jobGotRun = true
	})
	worker.JobChannel <- job
	if !jobGotRun {
		t.FailNow()
	}
}
