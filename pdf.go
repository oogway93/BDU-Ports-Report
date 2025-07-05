package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
)

func generatePDFReport(results []ScanResult, outputPath string) error {
	// Создаем PDF с поддержкой кириллицы
	pdf := gofpdf.New("P", "mm", "A4", "fonts")
	pdf.AddUTF8Font("DejaVu", "", "DejaVuSansCondensed.ttf")
	pdf.AddUTF8Font("DejaVu", "B", "DejaVuSansCondensed-Bold.ttf")
	
	// Добавляем первую страницу
	pdf.AddPage()
	
	// Устанавливаем шрифт с поддержкой кириллицы
	pdf.SetFont("DejaVu", "B", 16)
	
	// Заголовок отчета
	pdf.Cell(190, 10, "Отчет о сканировании портов")
	pdf.Ln(15)
	
	// Информация о времени сканирования
	pdf.SetFont("DejaVu", "", 11)
	pdf.Cell(190, 8, fmt.Sprintf("Время сканирования: %s", time.Now().Format("2006-01-02 15:04:05")))
	pdf.Ln(10)
	
	// Группируем результаты по IP
	ipMap := make(map[string][]ScanResult)
	for _, result := range results {
		if result.State == "open" {
			ipMap[result.IP] = append(ipMap[result.IP], result)
		}
	}
	
	// Для каждого IP
	for ip, ipResults := range ipMap {
		// Добавляем новую страницу для каждого IP (кроме первого)
		if ip != results[0].IP {
			pdf.AddPage()
		}

		// Заголовок IP
		pdf.SetFillColor(44, 62, 80) // #2c3e50
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont("DejaVu", "B", 14)
		pdf.Rect(10, pdf.GetY(), 190, 10, "F")
		pdf.Cell(190, 10, fmt.Sprintf("IP: %s", ip))
		pdf.Ln(15)
		
		// Сбрасываем цвета
		pdf.SetTextColor(0, 0, 0)
		
		// Для каждого открытого порта
		for _, result := range ipResults {
			// Информация о порте
			pdf.SetFillColor(248, 249, 250) // #f8f9fa
			pdf.SetFont("DejaVu", "B", 12)
			pdf.Rect(10, pdf.GetY(), 190, 10, "F")
			pdf.Cell(190, 10, fmt.Sprintf("Порт %d (%s)", result.Port, result.Service))
			pdf.Ln(15)
			
			// CVE уязвимости
			if len(result.CVEs) > 0 {
				pdf.SetFont("DejaVu", "B", 11)
				pdf.Cell(190, 8, "CVE уязвимости:")
				pdf.Ln(8)
				pdf.SetFont("DejaVu", "", 10)
				
				for _, cve := range result.CVEs {
					pdf.SetFillColor(255, 255, 255)
					pdf.Rect(15, pdf.GetY(), 180, 30, "F")
					pdf.SetX(15)
					pdf.Cell(180, 6, fmt.Sprintf("ID: %s", cve.ID))
					pdf.Ln(6)
					pdf.SetX(15)
					// Разбиваем длинное описание на строки
					description := splitLongText(pdf, cve.Description, 170)
					for _, line := range description {
						pdf.Cell(170, 6, line)
						pdf.Ln(6)
					}
					pdf.SetX(15)
					pdf.Cell(180, 6, fmt.Sprintf("Критичность: %s", cve.Severity))
					pdf.Ln(8)
				}
				pdf.Ln(4)
			}
			
			// MITRE ATT&CK
			if len(result.MITRE) > 0 {
				pdf.SetFont("DejaVu", "B", 11)
				pdf.Cell(190, 8, "MITRE ATT&CK:")
				pdf.Ln(8)
				pdf.SetFont("DejaVu", "", 10)
				
				for _, mitre := range result.MITRE {
					pdf.SetFillColor(255, 255, 255)
					pdf.Rect(15, pdf.GetY(), 180, 30, "F")
					pdf.SetX(15)
					pdf.Cell(180, 6, fmt.Sprintf("ID: %s - %s", mitre.ID, mitre.Name))
					pdf.Ln(6)
					pdf.SetX(15)
					description := splitLongText(pdf, mitre.Description, 170)
					for _, line := range description {
						pdf.Cell(170, 6, line)
						pdf.Ln(6)
					}
					pdf.SetX(15)
					pdf.Cell(180, 6, fmt.Sprintf("Тактика: %s", mitre.Tactic))
					pdf.Ln(8)
				}
				pdf.Ln(4)
			}
			
			// ФСТЭК БДУ
			if len(result.FSTEC) > 0 {
				pdf.SetFont("DejaVu", "B", 11)
				pdf.Cell(190, 8, "ФСТЭК БДУ:")
				pdf.Ln(8)
				pdf.SetFont("DejaVu", "", 10)
				
				for _, fstec := range result.FSTEC {
					pdf.SetFillColor(255, 255, 255)
					pdf.Rect(15, pdf.GetY(), 180, 30, "F")
					pdf.SetX(15)
					pdf.Cell(180, 6, fmt.Sprintf("ID: %s", fstec.ID))
					pdf.Ln(6)
					pdf.SetX(15)
					pdf.Cell(180, 6, fmt.Sprintf("Название: %s", fstec.Title))
					pdf.Ln(6)
					pdf.SetX(15)
					description := splitLongText(pdf, fstec.Description, 170)
					for _, line := range description {
						pdf.Cell(170, 6, line)
						pdf.Ln(6)
					}
					pdf.SetX(15)
					pdf.Cell(180, 6, fmt.Sprintf("Критичность: %s", fstec.Severity))
					pdf.Ln(8)
				}
				pdf.Ln(4)
			}
			
			pdf.Ln(10)
		}
	}
	
	// Сохраняем PDF
	return pdf.OutputFileAndClose(outputPath)
}

// splitLongText разбивает длинный текст на строки заданной ширины
func splitLongText(pdf *gofpdf.Fpdf, text string, width float64) []string {
	var lines []string
	currentLine := ""
	words := strings.Fields(text)
	
	for _, word := range words {
		// Проверяем, поместится ли слово в текущую строку
		testLine := currentLine
		if testLine != "" {
			testLine += " "
		}
		testLine += word
		
		// Получаем ширину строки в единицах PDF
		lineWidth := pdf.GetStringWidth(testLine)
		
		if lineWidth > width {
			// Если строка слишком длинная, добавляем текущую строку в результат
			if currentLine != "" {
				lines = append(lines, currentLine)
				currentLine = word
			} else {
				// Если слово само по себе слишком длинное, разбиваем его
				lines = append(lines, word)
				currentLine = ""
			}
		} else {
			currentLine = testLine
		}
	}
	
	// Добавляем последнюю строку
	if currentLine != "" {
		lines = append(lines, currentLine)
	}
	
	return lines
} 