package main

import (
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Rep struct {
	IP        string
	StartPort int
	EndPort   int
	StartTime string
	Status    string
	Results   []ScanResult
}

func main() {
	// Парсинг флагов командной строки
	var (
		ips    = flag.String("ips", "", "IP-адреса для сканирования (через запятую)")
		ports  = flag.String("ports", "", "Диапазон портов (например, 80-1000)")
		output = flag.String("output", "scan_report.pdf", "Путь для сохранения PDF-отчета")
	)
	flag.Parse()

	if *ips == "" || *ports == "" {
		fmt.Println("Использование: go run . -ips=192.168.1.1 -ports=80-1000 -output=report.pdf")
		flag.PrintDefaults()
		return
	}

	// Создание и запуск сканера
	scanner := NewScanner()
	ipList := strings.Split(*ips, ",")
	fmt.Printf("Starting scan of %d IPs and %d ports...\n", len(ipList), scanner.EndPort-scanner.StartPort+1)
	results := scanner.Scan(*ips, *ports)

	// Создание отчета
	rep := Rep{
		IP:        *ips,
		StartPort: scanner.StartPort,
		EndPort:   scanner.EndPort,
		StartTime: time.Now().Format("2006-01-02 15:04:05"),
		Status:    "Завершено",
		Results:   results,
	}

	// Генерация PDF отчета
	fmt.Printf("Generating PDF report: %s\n", *output)
	if err := generatePDFReport(results, *output); err != nil {
		log.Printf("Ошибка при создании PDF отчета: %v", err)
	}

	// Создание веб-сервера
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Настройка шаблона
	funcMap := template.FuncMap{
		"split": strings.Split,
	}
	t := template.Must(template.New("index.html").Funcs(funcMap).ParseFiles("static/index.html"))
	e.Renderer = &Template{
		templates: t,
	}

	// Маршруты
	e.GET("/", func(c echo.Context) error {
		return c.Render(http.StatusOK, "index.html", rep)
	})

	// Запуск веб-сервера
	fmt.Println("Starting web server on port 8787...")
	e.Start(":8787")
}

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
} 