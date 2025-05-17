package main

import (
	"context"
	"fmt"
	"os"
	"sort"

	cmdPkg "github.com/fornellas/blitzbuild/cmd"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s COMMAND [ARGS]\n", os.Args[0])
		os.Exit(1)
	}

	name := os.Args[1]
	args := os.Args[2:]

	cmd, err := cmdPkg.NewCmdPtraceFile(name, args, nil, "")
	if err != nil {
		fmt.Printf("NewCmdPtraceFile: %T: %s\n", err, err)
		os.Exit(1)
	}

	ctx := context.Background()
	fileMap, err := cmd.Run(ctx)
	if err != nil {
		fmt.Printf("CmdPtraceFile.Run: %T: %s\n", err, err)
		os.Exit(1)
	}

	files := make([]string, len(fileMap))
	i := 0
	for file := range fileMap {
		files[i] = file
		i++
	}
	sort.Strings(files)
	for _, file := range files {
		fmt.Printf("%s\n", file)
	}
}
