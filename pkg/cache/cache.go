package cache

import (
	"crypto/sha512"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Cache is a cache implementation that persists data to the filesystem.
type Cache[K ~string, V any] struct {
	cacheDir string
}

// NewPersistentCache creates a new persistent cache in the user's cache directory.
func NewCache[K ~string, V any]() (*Cache[K, V], error) {
	userCacheDir, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user cache directory: %w", err)
	}

	cacheDir := filepath.Join(userCacheDir, "blitzbuild")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return &Cache[K, V]{
		cacheDir: cacheDir,
	}, nil
}

func (c *Cache[K, V]) getFilePath(key K) string {
	hash := sha512.New()
	hash.Write([]byte(key))
	hashedKey := hex.EncodeToString(hash.Sum(nil))
	return filepath.Join(c.cacheDir, hashedKey)
}

// Put saves a value to the cache.
func (c *Cache[K, V]) Put(key K, value V) error {
	filePath := c.getFilePath(key)
	tempFilePath := filePath + "-temp"

	if _, err := os.Stat(filePath); err == nil {
		if err := os.Remove(filePath); err != nil {
			return fmt.Errorf("failed to remove existing cache file: %w", err)
		}
	}

	tempFile, err := os.OpenFile(tempFilePath, os.O_RDWR|os.O_TRUNC|os.O_CREATE, os.FileMode(0644))
	if err != nil {
		return fmt.Errorf("failed to open temp file: %w", err)
	}

	encoder := gob.NewEncoder(tempFile)
	if err = encoder.Encode(value); err != nil {
		err = fmt.Errorf("failed to encode value: %w", err)
		if err := os.Remove(tempFilePath); err != nil {
			err = errors.Join(err, fmt.Errorf("failed to remove temp file: %w", err))
		}
		return err
	}

	if err = tempFile.Close(); err != nil {
		err = fmt.Errorf("failed to close temp file: %w", err)
		if err := os.Remove(tempFilePath); err != nil {
			err = errors.Join(err, fmt.Errorf("failed to remove temp file: %w", err))
		}
		return err
	}

	if err = os.Rename(tempFilePath, filePath); err != nil {
		err = fmt.Errorf("failed to move temp file: %w", err)
		if err := os.Remove(tempFilePath); err != nil {
			err = errors.Join(err, fmt.Errorf("failed to remove temp file: %w", err))
		}
		return err
	}

	return nil
}

// Get retrieves a value from the cache.
func (c *Cache[K, V]) Get(key K) (value V, err error) {
	filePath := c.getFilePath(key)

	var file *os.File
	file, err = os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return value, nil
		}
		return value, fmt.Errorf("failed to open cache file: %w", err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()

	decoder := gob.NewDecoder(file)
	if err = decoder.Decode(&value); err != nil {
		return value, fmt.Errorf("failed to decode cached value: %w", err)
	}

	return value, nil
}
