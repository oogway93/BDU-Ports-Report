package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
)

func generatePDFReport(results []ScanResult, outputPath string) error {
	// Create PDF with Cyrillic support
	pdf := gofpdf.New("P", "mm", "A4", "fonts")
	pdf.AddUTF8Font("DejaVu", "", "DejaVuSansCondensed.ttf")
	pdf.AddUTF8Font("DejaVu", "B", "DejaVuSansCondensed-Bold.ttf")

	// Add first page
	pdf.AddPage()

	// Set Cyrillic-compatible font
	pdf.SetFont("DejaVu", "B", 16)

	// Report title
	pdf.Cell(190, 10, "Port Scan Report")
	pdf.Ln(15)

	// Scan time information
	pdf.SetFont("DejaVu", "", 11)
	pdf.Cell(190, 8, fmt.Sprintf("Scan time: %s", time.Now().Format("2006-01-02 15:04:05")))
	pdf.Ln(10)

	// Group results by IP
	ipMap := make(map[string][]ScanResult)
	for _, result := range results {
		if result.State == "open" {
			ipMap[result.IP] = append(ipMap[result.IP], result)
		}
	}

	// For each IP
	for ip, ipResults := range ipMap {
		// Add new page for each IP (except first)
		if ip != results[0].IP {
			pdf.AddPage()
		}

		// IP header
		pdf.SetFillColor(44, 62, 80) // #2c3e50
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont("DejaVu", "B", 14)
		pdf.Rect(10, pdf.GetY(), 190, 10, "F")
		pdf.Cell(190, 10, fmt.Sprintf("IP: %s", ip))
		pdf.Ln(15)

		// Reset colors
		pdf.SetTextColor(0, 0, 0)

		// For each open port
		for _, result := range ipResults {
			// Port information
			pdf.SetFillColor(248, 249, 250) // #f8f9fa
			pdf.SetFont("DejaVu", "B", 12)
			pdf.Rect(10, pdf.GetY(), 190, 10, "F")
			pdf.Cell(190, 10, fmt.Sprintf("Port %d (%s)", result.Port, result.Service))
			pdf.Ln(15)

			// CVE vulnerabilities
			if len(result.CVEs) > 0 {
				pdf.SetFont("DejaVu", "B", 11)
				pdf.Cell(190, 8, "CVE Vulnerabilities:")
				pdf.Ln(8)
				pdf.SetFont("DejaVu", "", 10)

				for _, cve := range result.CVEs {
					pdf.SetFillColor(255, 255, 255)
					pdf.Rect(15, pdf.GetY(), 180, 30, "F")
					pdf.SetX(15)
					pdf.Cell(180, 6, fmt.Sprintf("ID: %s", cve.ID))
					pdf.Ln(6)
					pdf.SetX(15)
					// Split long description into lines
					description := splitLongText(pdf, cve.Description, 170)
					for _, line := range description {
						pdf.Cell(170, 6, line)
						pdf.Ln(6)
					}
					pdf.SetX(15)
					pdf.Cell(180, 6, fmt.Sprintf("Severity: %s", cve.Severity))
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
					pdf.Cell(180, 6, fmt.Sprintf("Tactic: %s", mitre.Tactic))
					pdf.Ln(8)
				}
				pdf.Ln(4)
			}

			// FSTEC BDU
			if len(result.FSTEC) > 0 {
				pdf.SetFont("DejaVu", "B", 11)
				pdf.Cell(190, 8, "FSTEC BDU:")
				pdf.Ln(8)
				pdf.SetFont("DejaVu", "", 10)

				for _, fstec := range result.FSTEC {
					pdf.SetFillColor(255, 255, 255)
					pdf.Rect(15, pdf.GetY(), 180, 30, "F")
					pdf.SetX(15)
					pdf.Cell(180, 6, fmt.Sprintf("ID: %s", fstec.ID))
					pdf.Ln(6)
					pdf.SetX(15)
					pdf.Cell(180, 6, fmt.Sprintf("Title: %s", fstec.Title))
					pdf.Ln(6)
					pdf.SetX(15)
					description := splitLongText(pdf, fstec.Description, 170)
					for _, line := range description {
						pdf.Cell(170, 6, line)
						pdf.Ln(6)
					}
					pdf.SetX(15)
					pdf.Cell(180, 6, fmt.Sprintf("Severity: %s", fstec.Severity))
					pdf.Ln(8)
				}
				pdf.Ln(4)
			}

			pdf.Ln(3)
			pdf.SetFont("DejaVu", "B", 11)
			pdf.Cell(190, 8, "Commands for vulnerability detection:")
			pdf.Ln(8)
			pdf.SetFont("DejaVu", "", 10)
			counter := 1
			for _, command := range result.PenTestCommands {
				pdf.SetX(15)
				description := splitLongText(pdf, fmt.Sprintf("%d. %s", counter, command), 170)
				for _, line := range description {
					pdf.Cell(170, 6, line)
					pdf.Ln(6)
				}
				counter++
			}
			pdf.Ln(3)
		}
	}

	// Save PDF
	return pdf.OutputFileAndClose(outputPath)
}

// splitLongText splits long text into lines of specified width
func splitLongText(pdf *gofpdf.Fpdf, text string, width float64) []string {
	var lines []string
	currentLine := ""
	words := strings.Fields(text)

	for _, word := range words {
		// Check if word fits in current line
		testLine := currentLine
		if testLine != "" {
			testLine += " "
		}
		testLine += word

		// Get line width in PDF units
		lineWidth := pdf.GetStringWidth(testLine)

		if lineWidth > width {
			// If line is too long, add current line to result
			if currentLine != "" {
				lines = append(lines, currentLine)
				currentLine = word
			} else {
				// If word itself is too long, split it
				lines = append(lines, word)
				currentLine = ""
			}
		} else {
			currentLine = testLine
		}
	}

	// Add last line
	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return lines
}
