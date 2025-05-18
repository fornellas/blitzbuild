package main

import (
	"context"
	"fmt"
	"os"
	"sort"

	cmdPkg "github.com/fornellas/blitzbuild/pkg/cmd"
	"github.com/spf13/cobra"
)

var RunCmd = &cobra.Command{
	Use:   "run [FLAGS] -- CMD [ARGS]",
	Short: "Run command.",
	Long:  "TODO",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cobraCmd *cobra.Command, args []string) {
		name := args[0]
		args = args[1:]

		cmdPtraceFile, err := cmdPkg.NewCmdPtraceFile(name, args, nil, "")
		if err != nil {
			fmt.Printf("NewCmdPtraceFile: %T: %s\n", err, err)
			os.Exit(1)
		}

		ctx := context.Background()
		fileMap, err := cmdPtraceFile.Run(ctx)
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
	},
}

func init() {
	RootCmd.AddCommand(RunCmd)
}
