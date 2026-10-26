// The Go runtime leans on signals: it preempts goroutines with SIGURG, turns
// nil dereferences (SIGSEGV) into panics, and delivers os/signal
// notifications from its own handler.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

func fail(format string, args ...any) {
	fmt.Printf("FAILED: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	// With one P, the sleeping main goroutine only gets to run again if
	// the spinning goroutine (no function calls, so no cooperative
	// preemption points) is preempted asynchronously.
	runtime.GOMAXPROCS(1)
	var stop atomic.Bool
	var spins uint64
	done := make(chan struct{})
	go func() {
		for !stop.Load() {
			spins++
		}
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	stop.Store(true)
	<-done

	func() {
		defer func() {
			err, ok := recover().(runtime.Error)
			if !ok || !strings.Contains(err.Error(), "nil pointer dereference") {
				fail("recovered %v", err)
			}
		}()
		var p *int
		fmt.Println(*p)
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGUSR1)
	syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
	select {
	case s := <-c:
		if s != syscall.SIGUSR1 {
			fail("got %v", s)
		}
	case <-time.After(5 * time.Second):
		fail("no SIGUSR1")
	}
	fmt.Println("go signals ok", spins > 0)
}
