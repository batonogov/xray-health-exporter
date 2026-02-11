package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatchConfigFile watches for config file changes and triggers reload.
func WatchConfigFile(ctx context.Context, tm *TunnelManager, configFile string, logger *slog.Logger) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}
	defer func() { _ = watcher.Close() }()

	absConfig, err := filepath.Abs(configFile)
	if err != nil {
		return fmt.Errorf("failed to resolve config path: %w", err)
	}

	configDir := filepath.Dir(absConfig)
	configName := filepath.Base(absConfig)

	if err := watcher.Add(configDir); err != nil {
		return fmt.Errorf("failed to watch config directory: %w", err)
	}

	var (
		fileWatchActive bool
		fileWatchMu     sync.Mutex
	)

	addFileWatch := func() {
		fileWatchMu.Lock()
		defer fileWatchMu.Unlock()

		if fileWatchActive {
			return
		}

		if _, err := os.Stat(absConfig); err != nil {
			if !os.IsNotExist(err) {
				logger.Error("Failed to stat config file", "file", absConfig, "error", err)
			}
			return
		}

		if err := watcher.Add(absConfig); err != nil {
			logger.Error("Failed to watch config file", "file", absConfig, "error", err)
			return
		}

		fileWatchActive = true
		logger.Debug("Watching config file", "file", absConfig)
	}

	removeFileWatch := func() {
		fileWatchMu.Lock()
		defer fileWatchMu.Unlock()

		if !fileWatchActive {
			return
		}

		if err := watcher.Remove(absConfig); err != nil {
			logger.Debug("Failed to remove config file watch", "file", absConfig, "error", err)
		}
		fileWatchActive = false
	}

	scheduleFileRewatch := func() {
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if _, err := os.Stat(absConfig); err == nil {
						addFileWatch()
						return
					}
				}
			}
		}()
	}

	addFileWatch()

	logger.Info("Watching for config changes", "file", absConfig)

	var debounceTimer *time.Timer
	debounceDuration := 1 * time.Second
	defer func() {
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}

			if event.Name == "" || filepath.Base(event.Name) != configName {
				continue
			}

			if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
				logger.Debug("Config file removed or renamed", "file", absConfig)
				removeFileWatch()
				scheduleFileRewatch()
				continue
			}

			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Chmod) {
				logger.Info("Config file changed", "file", event.Name)

				if debounceTimer != nil {
					debounceTimer.Stop()
				}

				debounceTimer = time.AfterFunc(debounceDuration, func() {
					if err := tm.Reload(absConfig); err != nil {
						logger.Error("Failed to reload config", "error", err)
					}
				})
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			logger.Error("File watcher error", "error", err)
		}
	}
}
