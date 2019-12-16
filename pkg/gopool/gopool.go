package gopool

// Job represents the job to can be runnable
type Job interface {
	Run()
}

// MakeWorkerPool creates new Job pool
func MakeWorkerPool(maxWorkers int) chan chan Job {
	return make(chan chan Job, maxWorkers)
}

// Worker represents the worker that executes the job
type Worker struct {
	WorkerPool chan chan Job
	JobChannel chan Job
	quit       chan bool
}

// NewWorker creates a worker
func NewWorker(workerPool chan chan Job) Worker {
	return Worker{
		WorkerPool: workerPool,
		JobChannel: make(chan Job),
		quit:       make(chan bool)}
}

// Start method starts the run loop for the worker, listening for a quit channel in
// case we need to stop it
func (w Worker) Start() {
	// register the current worker into the worker queue.
	w.WorkerPool <- w.JobChannel
	go func() {
		for {
			select {
			case job := <-w.JobChannel:
				// we have received a work request.
				job.Run()
				for job = range w.JobChannel {
					job.Run()
				}
				w.WorkerPool <- w.JobChannel
			case <-w.quit:
				// we have received a signal to stop
				return
			}
		}
	}()
}

// Stop signals the worker to stop listening for work requests.
func (w Worker) Stop() {
	go func() {
		w.quit <- true
	}()
}
