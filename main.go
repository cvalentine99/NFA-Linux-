package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/options/windows"

	wailsapp "github.com/cvalentine99/nfa-linux/internal/wails"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Create application instance
	app := wailsapp.NewApp()

	// Create Wails application
	err := wails.Run(&options.App{
		Title:     "NFA-Linux | Network Forensics Analyzer",
		Width:     1600,
		Height:    900,
		MinWidth:  1200,
		MinHeight: 700,

		AssetServer: &assetserver.Options{
			Assets: assets,
		},

		BackgroundColour: &options.RGBA{R: 10, G: 10, B: 15, A: 1},

		OnStartup:  app.Startup,
		OnShutdown: app.Shutdown,

		Bind: []interface{}{
			app,
		},

		// Linux-specific options
		Linux: &linux.Options{
			Icon:                []byte{}, // Add icon bytes here
			WindowIsTranslucent: false,
			WebviewGpuPolicy:    linux.WebviewGpuPolicyNever, // Software rendering for NVIDIA Grace compatibility
			ProgramName:         "nfa-linux",
		},

		// macOS-specific options
		Mac: &mac.Options{
			TitleBar: &mac.TitleBar{
				TitlebarAppearsTransparent: true,
				HideTitle:                  false,
				HideTitleBar:               false,
				FullSizeContent:            true,
				UseToolbar:                 false,
				HideToolbarSeparator:       true,
			},
			Appearance:           mac.NSAppearanceNameDarkAqua,
			WebviewIsTransparent: true,
			WindowIsTranslucent:  false,
			About: &mac.AboutInfo{
				Title:   "NFA-Linux",
				Message: "Network Forensics Analyzer\n\nNext-generation packet analysis for digital forensics.",
			},
		},

		// Windows-specific options
		Windows: &windows.Options{
			WebviewIsTransparent:              false,
			WindowIsTranslucent:               false,
			DisableWindowIcon:                 false,
			DisableFramelessWindowDecorations: false,
			WebviewUserDataPath:               "",
			WebviewBrowserPath:                "",
			Theme:                             windows.Dark,
		},

		// Debug options
		Debug: options.Debug{
			OpenInspectorOnStartup: false,
		},
	})

	if err != nil {
		log.Fatal("Error:", err)
	}
}
