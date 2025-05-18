package main

import (
	"context"
	"fmt"
	"syscall"
	"time"

	cachePkg "github.com/fornellas/blitzbuild/pkg/cache"
	cmdPkg "github.com/fornellas/blitzbuild/pkg/cmd"
	"github.com/fornellas/resonance/log"
	"github.com/spf13/cobra"
)

var RunCmd = &cobra.Command{
	Use:   "run [FLAGS] -- CMD [ARGS]",
	Short: "Run command.",
	Long:  "TODO",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cobraCmd *cobra.Command, args []string) error {
		logger := log.MustLogger(cobraCmd.Context())

		cache, err := cachePkg.NewCache[map[string]time.Time]()
		if err != nil {
			return err
		}

		name := args[0]
		args = args[1:]
		cmdPtraceFile, err := cmdPkg.NewCmdPtraceFile(name, args, nil, "")
		if err != nil {
			return fmt.Errorf("failed to create command: %w", err)
		}
		key := cmdPtraceFile.Id()

		logger.Info("Checking if cached")
		value, err := cache.Get(key)
		if err != nil {
			return fmt.Errorf("failed to get from cache: %w", err)
		}

		shouldRun := false
		if value != nil {
			logger.Info("We have in cache, checking if any changes")
			for path, tim := range value {
				var stat_t syscall.Stat_t
				err := syscall.Stat(path, &stat_t)
				if err != nil {
					if errno, ok := err.(syscall.Errno); ok {
						if !(errno == syscall.ENOTDIR || errno == syscall.ENOENT) {
							return fmt.Errorf("failed to stat file: %w", err)
						}
					}
					if !tim.IsZero() {
						logger.Info("file exists on cache, but does not exist now", "path", path)
						shouldRun = true
						break
					}
				} else {
					mtim := time.Unix(stat_t.Mtim.Sec, stat_t.Mtim.Nsec)
					ctim := time.Unix(stat_t.Ctim.Sec, stat_t.Ctim.Nsec)
					if tim.IsZero() {
						logger.Info("file didn't exist on cache, but existis now", "path", path)
						shouldRun = true
						break
					} else if mtim.After(tim) || ctim.After(tim) {
						logger.Info("file modified", "path", path)
						shouldRun = true
						break
					}
				}
			}
			if !shouldRun {
				logger.Info("no file changes", "count", len(value))
			}
		} else {
			logger.Info("Not in cache, running")
			shouldRun = true
		}

		if !shouldRun {
			logger.Info("Success (cached)")
			return nil
		}
		logger.Info("Running")

		ctx := context.Background()
		fileMap, err := cmdPtraceFile.Run(ctx)
		if err != nil {
			return fmt.Errorf("command failed: %w", err)
		}

		logger.Info("Stat files for caching")
		value = map[string]time.Time{}
		for path := range fileMap {
			var tim time.Time
			var stat_t syscall.Stat_t
			err := syscall.Stat(path, &stat_t)
			if err != nil {
				if errno, ok := err.(syscall.Errno); ok {
					if !(errno == syscall.ENOTDIR || errno == syscall.ENOENT) {
						return fmt.Errorf("failed to stat: %w (errno %d)", err, errno)
					}
				} else {
					return fmt.Errorf("failed to stat: %w (%T)", err, err)
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
			return fmt.Errorf("faild to put to cache: %w", err)
		}

		logger.Info("Success")

		return nil
	},
}

func init() {
	RootCmd.AddCommand(RunCmd)
}
