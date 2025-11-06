package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var alertsLimit int
var alertsSeverity string

var alertsCmd = &cobra.Command{
	Use:   "alerts",
	Short: "Show recent alerts",
	Run: func(cmd *cobra.Command, args []string) {
		storagePath := "/var/lib/secrds/events.json"
		if customPath := os.Getenv("SECRDS_STORAGE"); customPath != "" {
			storagePath = customPath
		}

		data, err := os.ReadFile(storagePath)
		if err != nil {
			fmt.Printf("No alerts found (storage file not found: %v)\n", err)
			return
		}

		var storageData struct {
			Alerts []struct {
				IP         string    `json:"ip"`
				ThreatType string    `json:"threat_type"`
				Count      uint64    `json:"count"`
				Timestamp  time.Time `json:"timestamp"`
				Severity   string    `json:"severity,omitempty"`
				Details    string    `json:"details,omitempty"`
				Score      float64   `json:"score,omitempty"`
			} `json:"alerts"`
		}

		if err := json.Unmarshal(data, &storageData); err != nil {
			fmt.Printf("Failed to parse storage file: %v\n", err)
			return
		}

		alerts := storageData.Alerts
		if len(alerts) == 0 {
			fmt.Println("No recent alerts")
			return
		}

		// Filter by severity if specified
		if alertsSeverity != "" {
			filtered := []struct {
				IP         string    `json:"ip"`
				ThreatType string    `json:"threat_type"`
				Count      uint64    `json:"count"`
				Timestamp  time.Time `json:"timestamp"`
				Severity   string    `json:"severity,omitempty"`
				Details    string    `json:"details,omitempty"`
				Score      float64   `json:"score,omitempty"`
			}{}
			for _, alert := range alerts {
				if alert.Severity == alertsSeverity {
					filtered = append(filtered, alert)
				}
			}
			alerts = filtered
			if len(alerts) == 0 {
				fmt.Printf("No alerts found with severity: %s\n", alertsSeverity)
				return
			}
		}

		// Show newest first
		start := len(alerts) - alertsLimit
		if start < 0 {
			start = 0
		}

		fmt.Printf("Recent alerts (showing %d of %d):\n\n", alertsLimit, len(storageData.Alerts))
		for i := len(alerts) - 1; i >= start; i-- {
			alert := alerts[i]
			
			// Severity indicator
			severityIcon := "⚠️"
			severityText := alert.Severity
			if severityText == "" {
				severityText = "UNKNOWN"
			} else {
				switch alert.Severity {
				case "CRITICAL":
					severityIcon = "🚨"
				case "HIGH":
					severityIcon = "🔴"
				case "MEDIUM":
					severityIcon = "🟠"
				case "LOW":
					severityIcon = "🟡"
				}
			}
			
			fmt.Printf("%s [%s] %s\n", severityIcon, severityText, alert.ThreatType)
			fmt.Printf("  Time:   %s\n", alert.Timestamp.Format("2006-01-02 15:04:05 UTC"))
			fmt.Printf("  IP:     %s\n", alert.IP)
			fmt.Printf("  Count:  %d\n", alert.Count)
			
			if alert.Score > 0 {
				fmt.Printf("  Score:  %.1f\n", alert.Score)
			}
			
			if alert.Details != "" {
				fmt.Printf("  Details: %s\n", alert.Details)
			}
			
			fmt.Println()
		}
	},
}

func init() {
	alertsCmd.Flags().IntVarP(&alertsLimit, "limit", "l", 10, "Number of alerts to show")
	alertsCmd.Flags().StringVarP(&alertsSeverity, "severity", "s", "", "Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)")
	rootCmd.AddCommand(alertsCmd)
}

