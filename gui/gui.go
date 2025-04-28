package gui

import (
	gofilterapp "gofilter/app"
	"log"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

const (
	windowWidth  = 800
	windowHeight = 700
	maxLogLines  = 200
)

type GUI struct {
	window          fyne.Window
	mainApp         *gofilterapp.App
	status          *widget.Label
	torStatus       *widget.Label
	startBtn        *widget.Button
	stopBtn         *widget.Button
	blockedList     *widget.List
	addTorBtn       *widget.Button
	removeTorBtn    *widget.Button
	addNormalBtn    *widget.Button
	removeNormalBtn *widget.Button
	logEntry        *widget.Entry
	logScroll       *container.Scroll
	logChan         <-chan string
	stopUpdatesChan chan struct{}
	stopLogChan     chan struct{}
	currentLogLines []string
}

func NewGUI(mainApp *gofilterapp.App, logChan <-chan string) *GUI {
	a := app.New()
	w := a.NewWindow("IP Filter")
	w.Resize(fyne.NewSize(windowWidth, windowHeight))

	return &GUI{
		window:          w,
		mainApp:         mainApp,
		logChan:         logChan,
		currentLogLines: make([]string, 0, maxLogLines+10),
	}
}

func (g *GUI) createUI() {
	g.status = widget.NewLabel("Status: Stopped")
	g.torStatus = widget.NewLabel("Tor: Inactive")

	g.startBtn = widget.NewButton("Start Monitoring", g.start)
	g.stopBtn = widget.NewButton("Stop Monitoring", g.stop)
	g.stopBtn.Disable()

	g.blockedList = widget.NewList(
		func() int { return len(g.mainApp.GetBlockedIPs()) },
		func() fyne.CanvasObject { return widget.NewLabel("template") },
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			ips := g.mainApp.GetBlockedIPs()
			if id >= 0 && id < len(ips) {
				obj.(*widget.Label).SetText(ips[id])
			} else {
				obj.(*widget.Label).SetText("")
			}
		},
	)

	g.logEntry = widget.NewMultiLineEntry()
	g.logEntry.Wrapping = fyne.TextWrapOff

	header := container.NewHBox(
		g.startBtn,
		g.stopBtn,
		layout.NewSpacer(),
		container.NewVBox(
			g.status,
			g.torStatus,
		),
	)

	listContainer := container.NewScroll(g.blockedList)
	g.logScroll = container.NewScroll(g.logEntry)

	split := container.NewVSplit(listContainer, g.logScroll)
	split.Offset = 0.6

	content := container.NewBorder(
		header, nil, nil, nil,
		split,
	)

	g.window.SetContent(content)
	g.window.SetCloseIntercept(func() {
		g.stop()
		g.window.Close()
	})
}

func (g *GUI) start() {
	g.startBtn.Disable()

	if err := g.mainApp.Initialize(); err != nil {
		log.Printf("Initialization Error: %v", err)
		if g.status != nil {
			g.status.SetText("Error: " + err.Error())
			g.status.Refresh()
		}
		g.startBtn.Enable()
		return
	}

	go func() {
		if err := g.mainApp.Run(); err != nil {
			log.Printf("Application Run Error: %v", err)
			g.updateStatusFromGoroutine("Error: " + err.Error())
			g.stop()
		}
	}()

	g.stopBtn.Enable()
	if g.status != nil {
		g.status.SetText("Status: Active Monitoring")
		g.status.Refresh()
	}
	if g.torStatus != nil {
		g.torStatus.SetText(torStatusText(g.mainApp.IsTorActive()))
		g.torStatus.Refresh()
	}
	if g.blockedList != nil {
		g.blockedList.Refresh()
	}

	g.stopUpdatesChan = make(chan struct{})
	go g.setupUpdates(g.stopUpdatesChan)

	g.stopLogChan = make(chan struct{})
	go g.runLogUpdater(g.stopLogChan)
}

func (g *GUI) stop() {
	g.mainApp.Shutdown()

	if g.stopUpdatesChan != nil {
		select {
		case <-g.stopUpdatesChan:
		default:
			close(g.stopUpdatesChan)
		}
		g.stopUpdatesChan = nil
	}
	if g.stopLogChan != nil {
		select {
		case <-g.stopLogChan:
		default:
			close(g.stopLogChan)
		}
		g.stopLogChan = nil
	}

	if g.startBtn != nil {
		g.startBtn.Enable()
	}
	if g.stopBtn != nil {
		g.stopBtn.Disable()
	}
	if g.status != nil {
		g.status.SetText("Status: Stopped")
		g.status.Refresh()
	}
	if g.torStatus != nil {
		g.torStatus.SetText("Tor: Inactive")
		g.torStatus.Refresh()
	}
	if g.blockedList != nil {
		g.blockedList.Refresh()
	}
}

func (g *GUI) setupUpdates(stopChan <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			g.updateStatusFromGoroutine("Status: Active Monitoring")
		case <-stopChan:
			return
		}
	}
}

func (g *GUI) runLogUpdater(stopChan <-chan struct{}) {
	for {
		select {
		case msg, ok := <-g.logChan:
			if !ok {
				return
			}
			trimmedMsg := strings.TrimSpace(msg)

			fyne.Do(func() {
				if g.logEntry != nil && g.logScroll != nil {

					g.currentLogLines = append(g.currentLogLines, trimmedMsg)
					if len(g.currentLogLines) > maxLogLines {
						removeCount := len(g.currentLogLines) - maxLogLines
						g.currentLogLines = g.currentLogLines[removeCount:]
					}
					logText := strings.Join(g.currentLogLines, "\n")
					g.logEntry.SetText(logText)

					g.logScroll.ScrollToBottom()

				} else {
				}
			})

		case <-stopChan:
			return
		}
	}
}

func (g *GUI) updateStatusFromGoroutine(text string) {
	fyne.Do(func() {
		if g.status != nil {
			g.status.SetText(text)
		}
		if g.torStatus != nil {
			g.torStatus.SetText(torStatusText(g.mainApp.IsTorActive()))
		}
		if g.blockedList != nil {
			g.blockedList.Refresh()
		}
	})
}

func torStatusText(active bool) string {
	if active {
		return "Tor: Active (Monitoring)"
	}
	return "Tor: Inactive"
}

func (g *GUI) ShowAndRun() {
	g.createUI()
	g.window.ShowAndRun()

	if g.stopUpdatesChan != nil {
		select {
		case <-g.stopUpdatesChan:
		default:
			close(g.stopUpdatesChan)
		}
	}
	if g.stopLogChan != nil {
		select {
		case <-g.stopLogChan:
		default:
			close(g.stopLogChan)
		}
	}
	log.Println("Application closing.")
}
