// Go's os/exec: run itself as a child (exit status, output, environment),
// pipe data through a child, and kill a child that doesn't finish.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "child":
			fmt.Printf("child K=%s\n", os.Getenv("K"))
			os.Exit(3)
		case "upper":
			b, _ := io.ReadAll(os.Stdin)
			os.Stdout.Write(bytes.ToUpper(b))
			return
		case "hang":
			time.Sleep(time.Hour)
		}
	}
	cmd := exec.Command(os.Args[0], "child")
	cmd.Env = []string{"K=go"}
	out, err := cmd.Output()
	code := -1
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	}
	fmt.Printf("output %q code %d\n", out, code)

	up := exec.Command(os.Args[0], "upper")
	up.Stdin = strings.NewReader("piped through go")
	out, err = up.Output()
	fmt.Printf("upper %q %v\n", out, err)

	hang := exec.Command(os.Args[0], "hang")
	if err := hang.Start(); err != nil {
		fmt.Println("start:", err)
		return
	}
	time.Sleep(20 * time.Millisecond)
	hang.Process.Kill()
	err = hang.Wait()
	fmt.Println("killed:", err)

	_, err = exec.Command("/no/such/program").Output()
	fmt.Println("missing:", err)
}
