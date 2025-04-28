package main

import (
	"gofilter/app"
	"gofilter/gui"
	"io"
	"log"
)

type guiLogWriter struct {
	logChan chan<- string
}

func (w *guiLogWriter) Write(p []byte) (n int, err error) {
	select {
	case w.logChan <- string(p):
	default:
	}
	return len(p), nil
}

func main() {
	logChan := make(chan string, 100)

	guiWriter := &guiLogWriter{logChan: logChan}

	originalOutput := log.Writer()

	log.SetOutput(io.MultiWriter(originalOutput, guiWriter))

	log.Println("Log Forwarding Initialized.")

	appInstance := app.NewApp("eth0")
	guiInstance := gui.NewGUI(appInstance, logChan)
	guiInstance.ShowAndRun()

	log.Println("Application finished.")
}
