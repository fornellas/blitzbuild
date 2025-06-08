package main

import (
	"os"
	"path/filepath"

	cachePkg "github.com/fornellas/blitzbuild/pkg/cache"
	cmdPkg "github.com/fornellas/blitzbuild/pkg/cmd"
	"github.com/fornellas/blitzbuild/pkg/proc"
	"github.com/fornellas/resonance/log"
	"github.com/spf13/cobra"
)

var ignoreFsTypes []string
var defaultIgnoreFsTypes = []string{
	"devpts",
	"devtmpfs",
	"proc",
	"sysfs",
	"tmpfs",
}

var ignorePatterns []string
var defaultIgnorePatterns = []string{
	"**/.cache/**",
	"**/.git/**",
}

var RunCmd = &cobra.Command{
	Use:   "run [FLAGS] -- CMD [ARGS]",
	Short: "Run command.",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cobraCmd *cobra.Command, args []string) {
		ctx := cobraCmd.Context()
		logger := log.MustLogger(ctx)

		name := args[0]
		args = args[1:]
		var cmd cmdPkg.Cmd
		cmd, err := cmdPkg.NewCmdPtraceFile(name, args, nil, "")
		if err != nil {
			logger.Error("failed to create command", "err", err)
			os.Exit(1)
		}

		ctx, logger = log.MustWithAttrs(ctx, "cmd", cmd)

		cache, err := cachePkg.NewCmdCache()
		if err != nil {
			logger.Error("failed to create cache", "err", err)
			os.Exit(1)
		}

		isCacheHit, reason, err := cache.IsCacheHit(ctx, cmd)
		if err != nil {
			logger.Error("failed to query cache", "err", err)
			os.Exit(1)
		}

		if isCacheHit {
			logger.Info("Cache hit, not running", "reason", reason)
			return
		}

		logger.Info("Cache miss, running", "reason", reason)

		fileMap, err := cmd.Run(ctx)
		if err != nil {
			logger.Error("command failed", "err", err)
			os.Exit(1)
		}

		patterns := ignorePatterns
		logger.Debug("Loading mounts")
		mounts, err := proc.LoadMounts()
		if err != nil {
			logger.Error("failed to load mounts", "err", err)
			os.Exit(1)
		}
		ignoreFsTypesMap := map[string]bool{}
		for _, fsType := range ignoreFsTypes {
			ignoreFsTypesMap[fsType] = true
		}
		for _, mount := range mounts {
			if _, ok := ignoreFsTypesMap[mount.FSType]; ok {
				patterns = append(patterns, filepath.Join(mount.MountPoint, "**"))
			}
		}

		if err := cache.PutCmd(ctx, cmd, fileMap, patterns); err != nil {
			logger.Error("faild to put command in cache", "err", err)
			os.Exit(1)
		}

		logger.Debug("Success")
	},
}

func init() {
	RunCmd.Flags().StringSliceVar(
		&ignoreFsTypes, "ignore-fstypes", defaultIgnoreFsTypes,
		"filesystem types to ignore",
	)

	RunCmd.Flags().StringSliceVar(
		&ignorePatterns, "ignore-patterns", defaultIgnorePatterns,
		"file patterns to ignore",
	)
	if err := RunCmd.MarkFlagFilename("ignore-patterns"); err != nil {
		panic(err)
	}

	RootCmd.AddCommand(RunCmd)
}
