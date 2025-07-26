/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/containerd/log"
)

// S3Config holds S3 configuration
type S3Config struct {
	AccessKey string
	SecretKey string
	Region    string
	Bucket    string
	Endpoint  string
}

// S3Client is a simple S3 client using AWS Signature Version 4
type S3Client struct {
	config     S3Config
	httpClient *http.Client
}

// NewS3Client creates a new S3 client
func NewS3Client(cfg S3Config) (*S3Client, error) {
	// Ensure endpoint is properly formatted
	endpoint := cfg.Endpoint
	if endpoint != "" && !strings.HasPrefix(endpoint, "http") {
		endpoint = "https://" + endpoint
	}
	cfg.Endpoint = endpoint

	log.L.WithFields(log.Fields{
		"endpoint": endpoint,
		"bucket":   cfg.Bucket,
		"region":   cfg.Region,
	}).Info("Creating S3 client for snapshot storage")

	return &S3Client{
		config:     cfg,
		httpClient: &http.Client{Timeout: 5 * time.Minute},
	}, nil
}

// Upload uploads data to S3
func (c *S3Client) Upload(ctx context.Context, key string, data []byte) error {
	// Use virtual host style: https://bucket.endpoint/key
	host := strings.Replace(c.config.Endpoint, "https://", "", 1)
	host = strings.Replace(host, "http://", "", 1)
	url := fmt.Sprintf("https://%s.%s/%s", c.config.Bucket, host, key)

	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add AWS Signature V4
	if err := c.signRequest(req, data); err != nil {
		return fmt.Errorf("failed to sign request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	log.G(ctx).WithField("key", key).Info("Successfully uploaded to S3")
	return nil
}

// Download downloads data from S3
func (c *S3Client) Download(ctx context.Context, key string) ([]byte, error) {
	// Use virtual host style: https://bucket.endpoint/key
	host := strings.Replace(c.config.Endpoint, "https://", "", 1)
	host = strings.Replace(host, "http://", "", 1)
	url := fmt.Sprintf("https://%s.%s/%s", c.config.Bucket, host, key)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add AWS Signature V4
	if err := c.signRequest(req, nil); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(body))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	log.G(ctx).WithFields(log.Fields{
		"key":  key,
		"size": len(data),
	}).Info("Successfully downloaded from S3")
	return data, nil
}

// signRequest adds AWS Signature Version 4 to the request
func (c *S3Client) signRequest(req *http.Request, payload []byte) error {
	// AWS Signature Version 4 signing process
	now := time.Now().UTC()
	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))

	if payload != nil {
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(payload)))
		req.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(sha256Hash(payload)))
	} else {
		req.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(sha256Hash([]byte{})))
	}

	// Create canonical request
	canonicalHeaders := c.canonicalHeaders(req)
	signedHeaders := c.signedHeaders(req)
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		req.URL.Path,
		req.URL.RawQuery,
		canonicalHeaders,
		signedHeaders,
		req.Header.Get("X-Amz-Content-Sha256"),
	)

	// Create string to sign
	dateStamp := now.Format("20060102")
	credentialScope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, c.config.Region)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		req.Header.Get("X-Amz-Date"),
		credentialScope,
		hex.EncodeToString(sha256Hash([]byte(canonicalRequest))),
	)

	// Calculate signature
	signingKey := c.getSigningKey(dateStamp)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	// Add authorization header
	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.config.AccessKey,
		credentialScope,
		signedHeaders,
		signature,
	)
	req.Header.Set("Authorization", authHeader)

	return nil
}

func (c *S3Client) canonicalHeaders(req *http.Request) string {
	var headers []string
	for k, v := range req.Header {
		lowerKey := strings.ToLower(k)
		if lowerKey == "host" || strings.HasPrefix(lowerKey, "x-amz-") {
			headers = append(headers, fmt.Sprintf("%s:%s", lowerKey, strings.TrimSpace(v[0])))
		}
	}
	sort.Strings(headers)
	return strings.Join(headers, "\n") + "\n"
}

func (c *S3Client) signedHeaders(req *http.Request) string {
	var headers []string
	for k := range req.Header {
		lowerKey := strings.ToLower(k)
		if lowerKey == "host" || strings.HasPrefix(lowerKey, "x-amz-") {
			headers = append(headers, lowerKey)
		}
	}
	sort.Strings(headers)
	return strings.Join(headers, ";")
}

func (c *S3Client) getSigningKey(dateStamp string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+c.config.SecretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(c.config.Region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// LoadS3Config loads S3 configuration from environment
func LoadS3Config() *S3Config {
	cfg := &S3Config{
		AccessKey: os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		Region:    os.Getenv("AWS_REGION"),
		Bucket:    os.Getenv("AWS_BUCKET"),
		Endpoint:  os.Getenv("AWS_ENDPOINT_URL"),
	}

	return cfg
}
