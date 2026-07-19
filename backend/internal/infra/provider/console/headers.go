package console

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

var (
	chromiumVersionPattern = regexp.MustCompile(`(?i)\b(?:chrome|chromium|crios)/(\d{2,3})(?:\.\d+)*`)
	edgeVersionPattern     = regexp.MustCompile(`(?i)\b(?:edg|edga|edgios)/(\d{2,3})(?:\.\d+)*`)
)

// applyChromiumClientHints keeps the HTTP headers aligned with the Chromium
// TLS profile used by the Console transport. Non-Chromium User-Agents do not
// receive synthetic hints, avoiding contradictory browser fingerprints.
func applyChromiumClientHints(header http.Header, userAgent string) {
	lower := strings.ToLower(userAgent)
	brand := "Google Chrome"
	match := chromiumVersionPattern.FindStringSubmatch(userAgent)
	if edge := edgeVersionPattern.FindStringSubmatch(userAgent); len(edge) == 2 {
		brand, match = "Microsoft Edge", edge
	} else if strings.Contains(lower, "chromium/") {
		brand = "Chromium"
	}
	if len(match) != 2 {
		return
	}
	version := match[1]
	header.Set("Sec-Ch-Ua", fmt.Sprintf(`"%s";v="%s", "Chromium";v="%s", "Not(A:Brand";v="24"`, brand, version, version))

	platform := ""
	switch {
	case strings.Contains(lower, "windows"):
		platform = "Windows"
	case strings.Contains(lower, "mac os x") || strings.Contains(lower, "macintosh"):
		platform = "macOS"
	case strings.Contains(lower, "android"):
		platform = "Android"
	case strings.Contains(lower, "iphone") || strings.Contains(lower, "ipad"):
		platform = "iOS"
	case strings.Contains(lower, "linux"):
		platform = "Linux"
	}
	header.Set("Sec-Ch-Ua-Mobile", "?0")
	if strings.Contains(lower, "mobile") || platform == "Android" || platform == "iOS" {
		header.Set("Sec-Ch-Ua-Mobile", "?1")
	}
	header.Set("Sec-Ch-Ua-Model", "")
	if platform != "" {
		header.Set("Sec-Ch-Ua-Platform", strconv.Quote(platform))
	}

	arch := ""
	switch {
	case strings.Contains(lower, "aarch64") || strings.Contains(lower, "arm64") || strings.Contains(lower, " arm"):
		arch = "arm"
	case strings.Contains(lower, "x86_64") || strings.Contains(lower, "x64") || strings.Contains(lower, "win64") || strings.Contains(lower, "intel"):
		arch = "x86"
	}
	if arch != "" {
		header.Set("Sec-Ch-Ua-Arch", arch)
		header.Set("Sec-Ch-Ua-Bitness", "64")
	}
}
