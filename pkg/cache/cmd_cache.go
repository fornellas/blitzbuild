package cache

import (
	"time"

	cmdPkg "github.com/fornellas/blitzbuild/pkg/cmd"
)

type CmdFileInfo struct {
	Time      time.Time
	Sha512Sum []byte
}

type CmdFileInfoMap map[string]CmdFileInfo

type CmdCacheValue struct {
	Id          cmdPkg.Id
	FileInfoMap CmdFileInfoMap
}

func NewCmdCache() (*Cache[cmdPkg.Id, *CmdCacheValue], error) {
	cache, err := NewCache[cmdPkg.Id, *CmdCacheValue]()
	if err != nil {
		return nil, err
	}
	return cache, nil
}
