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

// WatchConfigFile watches for config file changes and triggers reload on the
// given TunnelManager. It watches the parent directory to handle file
// renames/removals gracefully. Blocks until ctx is canceled.
func WatchConfigFile(ctx context.Context, tm *TunnelManager, configFile string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %v", err)
	}
	defer watcher.Close()

	absConfig, err := filepath.Abs(configFile)
	if err != nil {
		return fmt.Errorf("failed to resolve config path: %v", err)
	}

	configDir := filepath.Dir(absConfig)
	configName := filepath.Base(absConfig)

	if err := watcher.Add(configDir); err != nil {
		return fmt.Errorf("failed to watch config directory: %v", err)
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
				slog.Error("failed to stat config file", "path", absConfig, "error", err)
			}
			return
		}

		if err := watcher.Add(absConfig); err != nil {
			slog.Error("failed to watch config file", "path", absConfig, "error", err)
			return
		}

		fileWatchActive = true
		slog.Debug("watching config file", "path", absConfig)
	}

	removeFileWatch := func() {
		fileWatchMu.Lock()
		defer fileWatchMu.Unlock()

		if !fileWatchActive {
			return
		}

		if err := watcher.Remove(absConfig); err != nil {
			slog.Debug("failed to remove config file watch", "path", absConfig, "error", err)
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

	slog.Info("watching for config changes", "path", absConfig)

	// Debounce timer to avoid multiple reloads
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
				slog.Debug("config file removed or renamed", "path", absConfig)
				removeFileWatch()
				scheduleFileRewatch()
				continue
			}

			// Check if it's a write or create event
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Chmod) {
				slog.Info("config file changed", "path", event.Name)

				// Reset debounce timer
				if debounceTimer != nil {
					debounceTimer.Stop()
				}

				debounceTimer = time.AfterFunc(debounceDuration, func() {
					if err := tm.reloadConfig(absConfig); err != nil {
						slog.Error("failed to reload config after file change", "error", err)
					}
				})
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			slog.Error("file watcher error", "error", err)
		}
	}
}

// WatchSubscriptions periodically reloads the configuration to refresh
// subscription-based tunnels. Blocks until ctx is canceled.
func WatchSubscriptions(ctx context.Context, tm *TunnelManager, configFile string) {
	tm.mu.RLock()
	cfg := tm.config
	tm.mu.RUnlock()

	if cfg == nil || len(cfg.Subscriptions) == 0 {
		return
	}

	// Find minimum update interval
	minInterval := 1 * time.Hour
	for _, sub := range cfg.Subscriptions {
		d, err := time.ParseDuration(sub.UpdateInterval)
		if err == nil && d < minInterval {
			minInterval = d
		}
	}

	ticker := time.NewTicker(minInterval)
	defer ticker.Stop()

	slog.Info("subscription watcher started", "interval", minInterval)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := tm.reloadConfig(configFile); err != nil {
				slog.Warn("subscription reload failed", "error", err)
			}
		}
	}
}
