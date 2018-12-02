package gopool

// Task is simple impl. of Job interface
type Task struct {
	Job
	execFunc func()
}

// Run execute the execFunc
func (t *Task) Run() {
	t.execFunc()
}

// NewTask creates a new Task instance
func NewTask(execFunc func()) *Task {
	return &Task{
		execFunc: execFunc,
	}
}
