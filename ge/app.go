package main

import (
	"context"
	"fmt"
	"runtime"
	"time"
)

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// Greet returns a greeting for the given name
func (a *App) Greet(name string) string {
	if name == "" {
		name = "User"
	}
	return fmt.Sprintf("Hello %s! MediaHub GE (Go + Wails) is operating normally.", name)
}

// GetSystemInfo returns system and runtime information
func (a *App) GetSystemInfo() map[string]string {
	return map[string]string{
		"os":        runtime.GOOS,
		"arch":      runtime.GOARCH,
		"goVersion": runtime.Version(),
		"engine":    "Wails v2",
		"status":    "Online",
		"time":      time.Now().Format("2006-01-02 15:04:05"),
	}
}

// Ping returns a simple pong message with timestamp
func (a *App) Ping() string {
	return fmt.Sprintf("pong (%s)", time.Now().Format("15:04:05"))
}

