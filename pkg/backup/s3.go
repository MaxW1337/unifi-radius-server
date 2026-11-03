package backup

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// SignS3Request signs an HTTP request with AWS Signature Version 4.
func SignS3Request(req *http.Request, region, accessKey, secretKey, payloadHash string, t time.Time) {
	if region == "" {
		region = "us-east-1"
	}
	service := "s3"

	dateOnly := t.Format("20060102")
	amzDate := t.Format("20060102T150405Z")

	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)

	// Host header
	host := req.URL.Host
	if req.Host != "" {
		host = req.Host
	}

	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalQuery := req.URL.RawQuery

	// Canonical headers must be sorted by lower-case key
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		host, payloadHash, amzDate)
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	)

	reqHash := sha256Hex([]byte(canonicalRequest))
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateOnly, region, service)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", amzDate, credentialScope, reqHash)

	signingKey := getSignatureKey(secretKey, dateOnly, region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credentialScope, signedHeaders, signature)

	req.Header.Set("Authorization", authHeader)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func getSignatureKey(key, dateStamp, regionName, serviceName string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+key), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(regionName))
	kService := hmacSHA256(kRegion, []byte(serviceName))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

// TestS3 checks connectivity to the S3 bucket using a HEAD request.
func TestS3(ctx context.Context, client *http.Client, endpoint, bucket, accessKey, secretKey string) error {
	u, err := ValidateURL(endpoint)
	if err != nil {
		return err
	}

	b := strings.TrimSpace(bucket)
	if b == "" {
		return errors.New("S3 Bucket-Name darf nicht leer sein")
	}

	// Target URL: http(s)://endpoint/bucket
	bucketURL := strings.TrimRight(u.String(), "/") + "/" + b

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, bucketURL, nil)
	if err != nil {
		return err
	}

	emptyPayloadHash := sha256Hex(nil)
	SignS3Request(req, "us-east-1", accessKey, secretKey, emptyPayloadHash, time.Now().UTC())

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("S3 Verbindung fehlgeschlagen: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("S3 Authentifizierung abgelehnt: HTTP %d (AccessKey/SecretKey prüfen)", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("S3 Bucket %q wurde nicht gefunden (HTTP 404)", b)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("S3 Server meldet Fehler: HTTP %d", resp.StatusCode)
	}

	return nil
}

// UploadS3 uploads a backup file to an S3-compatible bucket with path-style URL.
func UploadS3(ctx context.Context, client *http.Client, endpoint, bucket, prefix, accessKey, secretKey, filename, localFilePath string) (int64, error) {
	u, err := ValidateURL(endpoint)
	if err != nil {
		return 0, err
	}

	b := strings.TrimSpace(bucket)
	if b == "" {
		return 0, errors.New("S3 Bucket-Name darf nicht leer sein")
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

	// Calculate SHA256 of file for AWS SigV4
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return 0, fmt.Errorf("SHA256 Hash-Berechnung fehlgeschlagen: %w", err)
	}
	payloadHash := hex.EncodeToString(h.Sum(nil))

	// Rewind file for upload
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}

	// Key with optional prefix
	key := filename
	if cleanPrefix := strings.Trim(prefix, "/"); cleanPrefix != "" {
		key = cleanPrefix + "/" + filename
	}

	s3URL := strings.TrimRight(u.String(), "/") + "/" + b + "/" + url.PathEscape(key)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, s3URL, f)
	if err != nil {
		return 0, err
	}

	req.ContentLength = stat.Size()
	req.Header.Set("Content-Type", "application/x-sqlite3")

	SignS3Request(req, "us-east-1", accessKey, secretKey, payloadHash, time.Now().UTC())

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("S3 Upload fehlgeschlagen: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, fmt.Errorf("S3 Upload abgewiesen: HTTP %d (%s)", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return stat.Size(), nil
}

