// go build -tags "desktop,production" -ldflags="-w -s -H windowsgui" -o ge.exe .

package main

import (
	"embed"
	"os"
	"path/filepath"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

// Embedded static web frontend assets
//
//go:embed all:public
var assets embed.FS

// Main entry point for desktop application
func main() {
	// Initialize core application instance
	app := NewApp()

	// Resolve safe user data directory for WebView2
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	userDataPath := filepath.Join(cacheDir, "MediaHubGE_WebView2")

	// Configure and run Wails application
	err = wails.Run(&options.App{
		Title:  "MediaHub GE (Go + Wails)",
		Width:  1024,
		Height: 700,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 15, G: 23, B: 42, A: 1},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind: []interface{}{
			app,
		},
		Windows: &windows.Options{
			WebviewUserDataPath: userDataPath,
		},
	})

	// Handle fatal execution error
	if err != nil {
		println("Error:", err.Error())
	}
}
