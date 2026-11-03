package backup

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
)

// ValidateURL checks that an endpoint URL has an acceptable scheme and valid host.
func ValidateURL(rawURL string) (*url.URL, error) {
	clean := strings.TrimSpace(rawURL)
	if clean == "" {
		return nil, errors.New("URL darf nicht leer sein")
	}

	u, err := url.Parse(clean)
	if err != nil {
		return nil, fmt.Errorf("ungültige URL: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("nicht unterstütztes Protokoll %q (nur HTTP und HTTPS erlaubt)", u.Scheme)
	}

	if u.Host == "" {
		return nil, errors.New("Host-Name in URL fehlt")
	}

	return u, nil
}

// TestWebDAV verifies connection and credentials against a WebDAV server.
func TestWebDAV(ctx context.Context, client *http.Client, rawURL, user, pass string) error {
	u, err := ValidateURL(rawURL)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "PROPFIND", u.String(), strings.NewReader(
		`<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/></D:prop></D:propfind>`,
	))
	if err != nil {
		return err
	}
	req.Header.Set("Depth", "0")
	req.Header.Set("Content-Type", "application/xml")
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}

	resp, err := client.Do(req)
	if err != nil {
		// Fallback test: try OPTIONS or HEAD
		reqHead, errHead := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
		if errHead == nil {
			if user != "" || pass != "" {
				reqHead.SetBasicAuth(user, pass)
			}
			respHead, errHeadDo := client.Do(reqHead)
			if errHeadDo == nil {
				defer respHead.Body.Close()
				if respHead.StatusCode < 400 || respHead.StatusCode == http.StatusMethodNotAllowed {
					return nil
				}
			}
		}
		return fmt.Errorf("Verbindung zu WebDAV fehlgeschlagen: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("WebDAV-Authentifizierung fehlgeschlagen (HTTP %d)", resp.StatusCode)
	}

	// 207 Multi-Status, 200 OK, 204 No Content, 405 Method Not Allowed (endpoint exists)
	if resp.StatusCode != http.StatusMultiStatus && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusMethodNotAllowed {
		return fmt.Errorf("WebDAV Server meldet unerwarteten Status: HTTP %d", resp.StatusCode)
	}

	return nil
}

// UploadWebDAV uploads a backup file via HTTP PUT to the WebDAV target.
func UploadWebDAV(ctx context.Context, client *http.Client, rawURL, user, pass, filename, localFilePath string) (int64, error) {
	u, err := ValidateURL(rawURL)
	if err != nil {
		return 0, err
	}

	f, err := os.Open(localFilePath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return 0, err
	}

	// Append filename to base URL path cleanly
	targetURL := strings.TrimRight(u.String(), "/") + "/" + filename

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, targetURL, f)
	if err != nil {
		return 0, err
	}
	req.ContentLength = stat.Size()
	req.Header.Set("Content-Type", "application/x-sqlite3")
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("WebDAV Upload fehlgeschlagen: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, fmt.Errorf("WebDAV Upload abgewiesen: HTTP %d (%s)", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return stat.Size(), nil
}

type propfindMultiStatus struct {
	XMLName   xml.Name           `xml:"multistatus"`
	Responses []propfindResponse `xml:"response"`
}

type propfindResponse struct {
	Href string `xml:"href"`
}

// PruneWebDAV deletes older radius-backup-*.db files exceeding retention count.
func PruneWebDAV(ctx context.Context, client *http.Client, rawURL, user, pass string, retention int) error {
	if retention <= 0 {
		return nil
	}

	u, err := ValidateURL(rawURL)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "PROPFIND", u.String(), strings.NewReader(
		`<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/></D:prop></D:propfind>`,
	))
	if err != nil {
		return err
	}
	req.Header.Set("Depth", "1")
	req.Header.Set("Content-Type", "application/xml")
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMultiStatus {
		return nil // Server does not support PROPFIND or directory listing
	}

	var ms propfindMultiStatus
	dec := xml.NewDecoder(io.LimitReader(resp.Body, 512*1024))
	if err := dec.Decode(&ms); err != nil {
		return nil
	}

	var backupFiles []string
	for _, r := range ms.Responses {
		cleanHref := strings.TrimRight(r.Href, "/")
		base := path.Base(cleanHref)
		if strings.HasPrefix(base, "radius-backup-") && strings.HasSuffix(base, ".db") {
			backupFiles = append(backupFiles, base)
		}
	}

	sort.Strings(backupFiles)

	if len(backupFiles) > retention {
		toDelete := backupFiles[:len(backupFiles)-retention]
		for _, file := range toDelete {
			delURL := strings.TrimRight(u.String(), "/") + "/" + file
			delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, delURL, nil)
			if err == nil {
				if user != "" || pass != "" {
					delReq.SetBasicAuth(user, pass)
				}
				delResp, err := client.Do(delReq)
				if err == nil {
					_ = delResp.Body.Close()
				}
			}
		}
	}

	return nil
}
