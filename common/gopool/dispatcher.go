package gopool

// Dispatcher listens JobQueue, picks up free worker from pool and relays new job to picked worker
type Dispatcher struct {
	// A pool of workers channels that are registered with the dispatcher
	jobQueue   <-chan Job
	maxWorkers int
	WorkerPool chan chan Job
}

// NewDispatcher creates a Dispatcher instance
func NewDispatcher(jobQueue <-chan Job, maxWorkers int) *Dispatcher {
	pool := MakeWorkerPool(maxWorkers)
	return &Dispatcher{WorkerPool: pool, maxWorkers: maxWorkers, jobQueue: jobQueue}
}

// Run runs workers and listen jobqueue
func (d *Dispatcher) Run() {
	// starting n number of workers
	for i := 0; i < d.maxWorkers; i++ {
		worker := NewWorker(d.WorkerPool)
		worker.Start()
	}

	go d.dispatch()
}

func (d *Dispatcher) dispatch() {
	for {
		select {
		case job := <-d.jobQueue:
			// a job request has been received
			go func(job Job) {
				// try to obtain a worker job channel that is available.
				// this will block until a worker is idle
				worker := <-d.WorkerPool

				// dispatch the job to the worker job channel
				worker <- job
			}(job)
		}
	}
}
