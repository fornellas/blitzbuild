package cache

import (
	"bytes"
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/bmatcuk/doublestar"
	cmdPkg "github.com/fornellas/blitzbuild/pkg/cmd"
	"github.com/fornellas/resonance/log"
)

var statOkErrno = map[syscall.Errno]bool{
	syscall.ENOTDIR: true,
	syscall.ENOENT:  true,
	syscall.EACCES:  true,
}

type CmdFileInfo struct {
	StatErrno syscall.Errno
	Stat_t    *syscall.Stat_t
	OpenErrno syscall.Errno
	Sha512Sum []byte
}

type CmdFileInfoMap map[string]CmdFileInfo

type CmdCacheValue struct {
	Id          cmdPkg.Id
	FileInfoMap CmdFileInfoMap
}

type CmdCache struct {
	*Cache[cmdPkg.Id, *CmdCacheValue]
}

func NewCmdCache() (*CmdCache, error) {
	cache, err := NewCache[cmdPkg.Id, *CmdCacheValue]()
	if err != nil {
		return nil, err
	}

	return &CmdCache{
		Cache: cache,
	}, nil
}

func (c *CmdCache) IsCacheHit(ctx context.Context, cmd cmdPkg.Cmd) (bool, string, error) {
	logger := log.MustLogger(ctx)

	key := cmd.Id()

	logger.Debug("Checking if cached")
	cmdCacheValue, err := c.Get(key)
	if err != nil {
		return false, "", err
	}

	if cmdCacheValue != nil {
		logger.Debug("We have in cache, checking if any file changes")
		for path, fileInfo := range cmdCacheValue.FileInfoMap {
			var stat_t syscall.Stat_t
			err := syscall.Stat(path, &stat_t)
			if err != nil {
				if errno, ok := err.(syscall.Errno); ok {
					if fileInfo.StatErrno != syscall.Errno(0) {
						if errno == fileInfo.StatErrno {
							logger.Debug("same stat errno", "path", path, "errno", errno.Error())
							continue
						} else {
							return false, fmt.Sprintf("different stat errno: %#v: cached %#v, now %#v", path, fileInfo.StatErrno.Error(), errno.Error()), nil
						}
					} else {
						return false, fmt.Sprintf("file existed, now stat error: %#v: %#v", path, errno.Error()), nil
					}
				} else {
					return false, "", fmt.Errorf("failed to stat: %#v: %w", path, err)
				}
			} else {
				if fileInfo.StatErrno != syscall.Errno(0) {
					return false, fmt.Sprintf("different stat errno: %#v: cached %#v, now no error", path, fileInfo.StatErrno.Error()), nil
				}
				if stat_t.Dev != fileInfo.Stat_t.Dev {
					return false, fmt.Sprintf("file dev changed: %#v", path), nil
				}
				if stat_t.Ino != fileInfo.Stat_t.Ino {
					return false, fmt.Sprintf("file ino changed: %#v", path), nil
				}
				if stat_t.Mode != fileInfo.Stat_t.Mode {
					return false, fmt.Sprintf("file mode changed: %#v", path), nil
				}
				if stat_t.Uid != fileInfo.Stat_t.Uid {
					return false, fmt.Sprintf("file uid changed: %#v", path), nil
				}
				if stat_t.Gid != fileInfo.Stat_t.Gid {
					return false, fmt.Sprintf("file gid changed: %#v", path), nil
				}
				if stat_t.Rdev != fileInfo.Stat_t.Rdev {
					return false, fmt.Sprintf("file rdev changed: %#v", path), nil
				}
				if stat_t.Size != fileInfo.Stat_t.Size {
					return false, fmt.Sprintf("file size changed: %#v", path), nil
				}
				if stat_t.Mtim != fileInfo.Stat_t.Mtim || stat_t.Ctim != fileInfo.Stat_t.Ctim {
					if (stat_t.Mode & syscall.S_IFMT) == syscall.S_IFREG {
						logger.Debug("regular file mtim / ctim change, hashing", "path", path)
						hash := sha512.New()
						fd, err := syscall.Open(path, os.O_RDONLY, 0)
						if err != nil {
							if errno, ok := err.(syscall.Errno); ok {
								if fileInfo.OpenErrno != syscall.Errno(0) {
									if errno == fileInfo.OpenErrno {
										logger.Debug("same open errno", "path", path, "errno", errno.Error())
										continue
									} else {
										return false, fmt.Sprintf("different open errno: %#v: cached %#v, now %#v", path, fileInfo.OpenErrno.Error(), errno.Error()), nil
									}
								} else {
									return false, fmt.Sprintf("file was able to be opened before, now open error: %#v: %#v", path, errno.Error()), nil
								}
							} else {
								return false, "", fmt.Errorf("failed to open: %#v: %w", path, err)
							}
						} else {
							file := os.NewFile(uintptr(fd), path)
							if fileInfo.OpenErrno != syscall.Errno(0) {
								if err := file.Close(); err != nil {
									return false, "", err
								}
								return false, fmt.Sprintf("file failed to open before, now succeeds: %#v: cached %#v", path, fileInfo.OpenErrno.Error()), nil
							} else {
								if _, err := io.Copy(hash, file); err != nil {
									return false, "", fmt.Errorf("failed to hash file: %#v: %w", path, err)
								}
								if bytes.Equal(fileInfo.Sha512Sum, hash.Sum(nil)) {
									logger.Debug("no hash change", "path", path)
								} else {
									return false, fmt.Sprintf("hash change: %#v", path), nil
								}
							}
						}
					} else {
						logger.Debug("ignoring non-regular file mtim / ctim change", "path", path)
					}
				}
			}
		}
		return true, "no file changes", nil
	} else {
		return false, "not in cache", nil
	}
}

func (c *CmdCache) PutCmd(
	ctx context.Context,
	cmd cmdPkg.Cmd,
	fileMap map[string]bool,
	ignorePatterns []string,
) error {
	logger := log.MustLogger(ctx)

	logger.Debug("Stat files for caching")
	cmdCacheValue := &CmdCacheValue{
		Id:          cmd.Id(),
		FileInfoMap: CmdFileInfoMap{},
	}
	for path := range fileMap {
		ignore := false
		for _, pattern := range ignorePatterns {
			matched, err := doublestar.PathMatch(pattern, path)
			if err != nil {
				return fmt.Errorf("failed to match: %w", err)
			}
			if matched {
				ignore = true
				break
			}
		}
		if ignore {
			continue
		}

		cmdFileInfo := CmdFileInfo{}

		var stat_t syscall.Stat_t
		err := syscall.Stat(path, &stat_t)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok {
				if _, ok := statOkErrno[errno]; ok {
					cmdFileInfo.StatErrno = errno
				} else {
					return fmt.Errorf("failed to stat: %#v: %w", path, err)
				}
			} else {
				return fmt.Errorf("failed to stat: %#v: %w", path, err)
			}
		} else {
			cmdFileInfo.Stat_t = &stat_t

			if (stat_t.Mode & syscall.S_IFMT) == syscall.S_IFREG {
				hash := sha512.New()
				fd, err := syscall.Open(path, os.O_RDONLY, 0)
				if err != nil {
					if errno, ok := err.(syscall.Errno); ok {
						if _, ok := statOkErrno[errno]; ok {
							cmdFileInfo.OpenErrno = errno
						} else {
							return fmt.Errorf("failed to open: %#v: %w", path, err)
						}
					} else {
						return fmt.Errorf("failed to open: %#v: %w", path, err)
					}
				} else {
					file := os.NewFile(uintptr(fd), path)
					if _, err := io.Copy(hash, file); err != nil {
						return errors.Join(
							fmt.Errorf("failed to hash file: %#v: %w", path, err),
							file.Close(),
						)
					}
					if err := file.Close(); err != nil {
						return err
					}
				}
				cmdFileInfo.Sha512Sum = hash.Sum(nil)
			}
		}

		cmdCacheValue.FileInfoMap[path] = cmdFileInfo
	}

	if err := c.Put(cmd.Id(), cmdCacheValue); err != nil {
		return err
	}

	return nil
}
