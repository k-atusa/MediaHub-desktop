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

//go:embed all:public
var assets embed.FS

func main() {
	// Create an instance of the app structure
	app := NewApp()

	// Safe User Data Directory for WebView2
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	userDataPath := filepath.Join(cacheDir, "MediaHubGE_WebView2")

	// Create application with options
	err = wails.Run(&options.App{
		Title:  "MediaHub GE (Go + Wails)",
		Width:  1024,
		Height: 700,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 15, G: 23, B: 42, A: 1},
		OnStartup:        app.startup,
		Bind: []interface{}{
			app,
		},
		Windows: &windows.Options{
			WebviewUserDataPath: userDataPath,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
