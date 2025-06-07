package main

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/bmatcuk/doublestar/v4"

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
		logger := log.MustLogger(cobraCmd.Context())

		cache, err := cachePkg.NewCache[map[string]time.Time]()
		if err != nil {
			logger.Error("failed to create cache", "err", err)
			os.Exit(1)
		}

		name := args[0]
		args = args[1:]
		cmdPtraceFile, err := cmdPkg.NewCmdPtraceFile(name, args, nil, "")
		if err != nil {
			logger.Error("failed to create command", "err", err)
			os.Exit(1)
		}
		key := cmdPtraceFile.Id()

		logger.Debug("Checking if cached")
		value, err := cache.Get(key)
		if err != nil {
			logger.Error("failed to get from cache", "err", err)
			os.Exit(1)
		}

		shouldRun := false
		if value != nil {
			logger.Debug("We have in cache, checking if any changes")
			for path, tim := range value {
				var stat_t syscall.Stat_t
				err := syscall.Stat(path, &stat_t)
				if err != nil {
					if errno, ok := err.(syscall.Errno); ok {
						if !(errno == syscall.ENOTDIR || errno == syscall.ENOENT) {
							logger.Error("failed to stat file", "err", err)
							os.Exit(1)
						}
					}
					if !tim.IsZero() {
						logger.Warn("file exists on cache, but does not exist now", "path", path)
						shouldRun = true
						break
					}
				} else {
					mtim := time.Unix(stat_t.Mtim.Sec, stat_t.Mtim.Nsec)
					ctim := time.Unix(stat_t.Ctim.Sec, stat_t.Ctim.Nsec)
					if tim.IsZero() {
						logger.Warn("file didn't exist on cache, but existis now", "path", path)
						shouldRun = true
						break
					} else if mtim.After(tim) || ctim.After(tim) {
						logger.Warn("file modified", "path", path)
						shouldRun = true
						break
					}
				}
			}
			if !shouldRun {
				logger.Debug("no file changes", "count", len(value))
			}
		} else {
			logger.Debug("Not in cache, running")
			shouldRun = true
		}

		if !shouldRun {
			logger.Info("Success (cached)")
			return
		}
		logger.Debug("Running")

		ctx := context.Background()
		fileMap, err := cmdPtraceFile.Run(ctx)
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

		logger.Debug("Stat files for caching")
		value = map[string]time.Time{}
		for path := range fileMap {
			ignore := false
			for _, pattern := range patterns {
				matched, err := doublestar.PathMatch(pattern, path)
				if err != nil {
					logger.Error("failed to match", "err", err)
					os.Exit(1)
				}
				if matched {
					ignore = true
					break
				}
			}
			if ignore {
				continue
			}

			var tim time.Time
			var stat_t syscall.Stat_t
			err := syscall.Stat(path, &stat_t)
			if err != nil {
				if errno, ok := err.(syscall.Errno); ok {
					if !(errno == syscall.ENOTDIR || errno == syscall.ENOENT) {
						logger.Error("failed to stat", "err", err, "path", path)
						os.Exit(1)
					}
				} else {
					logger.Error("failed to stat", "err", err, "path", path)
					os.Exit(1)
				}
			} else {
				tim = time.Unix(stat_t.Mtim.Sec, stat_t.Mtim.Nsec)
				ctim := time.Unix(stat_t.Ctim.Sec, stat_t.Ctim.Nsec)
				if ctim.After(tim) {
					tim = ctim
				}
			}
			value[path] = tim
		}
		if err := cache.Put(key, value); err != nil {
			logger.Error("faild to put to cache", "err", err)
			os.Exit(1)
		}

		logger.Debug("Success")

		return
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
