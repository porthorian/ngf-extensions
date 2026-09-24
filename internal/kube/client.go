package kube

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
)

type Config struct {
	Namespace   string
	GatewayName string
	PolicyName  string
}

type Metadata struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace,omitempty"`
	UID             string            `json:"uid,omitempty"`
	ResourceVersion string            `json:"resourceVersion,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
}

type ConfigMap struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   Metadata          `json:"metadata"`
	Data       map[string]string `json:"data"`
}

type Pod struct {
	Metadata Metadata `json:"metadata"`
	Status   struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

type PodList struct {
	Items []Pod `json:"items"`
}

type Snippet struct {
	Context string `json:"context"`
	Value   string `json:"value"`
}

type SnippetsPolicy struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Spec       struct {
		TargetRefs []map[string]string `json:"targetRefs"`
		Snippets   []Snippet           `json:"snippets"`
	} `json:"spec"`
}

type APIError struct {
	Status int
	Body   string
}

func (e APIError) Error() string {
	return fmt.Sprintf("Kubernetes API status %d: %s", e.Status, e.Body)
}

func IsNotFound(err error) bool {
	var apiErr APIError
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound
}

func IsConflict(err error) bool {
	var apiErr APIError
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusConflict
}

type Client struct {
	base       string
	tokenPath  string
	http       *http.Client
	streamHTTP *http.Client
	config     Config
}

func NewClient(config Config) (*Client, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("Kubernetes service host or port is absent")
	}
	ca, err := os.ReadFile(serviceAccountDir + "/ca.crt")
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid Kubernetes service CA")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	return &Client{
		config:     config,
		base:       "https://" + host + ":" + port,
		tokenPath:  serviceAccountDir + "/token",
		http:       &http.Client{Transport: transport, Timeout: 10 * time.Second},
		streamHTTP: &http.Client{Transport: transport},
	}, nil
}

func (c *Client) request(ctx context.Context, client *http.Client, method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return nil, err
	}
	token, err := os.ReadFile(c.tokenPath)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		defer response.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return nil, APIError{Status: response.StatusCode, Body: string(data)}
	}
	return response, nil
}

func (c *Client) JSON(ctx context.Context, method, path string, body, into any) error {
	response, err := c.request(ctx, c.http, method, path, body)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if into == nil {
		return nil
	}
	return json.NewDecoder(response.Body).Decode(into)
}

func ConfigMapPath(namespace, name string) string {
	return "/api/v1/namespaces/" + url.PathEscape(namespace) + "/configmaps/" + url.PathEscape(name)
}

func PolicyPath(namespace, name string) string {
	return "/apis/gateway.nginx.org/v1alpha1/namespaces/" + url.PathEscape(namespace) + "/snippetspolicies/" + url.PathEscape(name)
}

func (c *Client) GetConfigMap(ctx context.Context, namespace, name string) (ConfigMap, error) {
	var result ConfigMap
	err := c.JSON(ctx, http.MethodGet, ConfigMapPath(namespace, name), nil, &result)
	return result, err
}

func (c *Client) CreateConfigMap(ctx context.Context, cm ConfigMap) error {
	return c.JSON(ctx, http.MethodPost, "/api/v1/namespaces/"+url.PathEscape(cm.Metadata.Namespace)+"/configmaps", cm, nil)
}

func (c *Client) UpdateConfigMap(ctx context.Context, cm ConfigMap) error {
	return c.JSON(ctx, http.MethodPut, ConfigMapPath(cm.Metadata.Namespace, cm.Metadata.Name), cm, nil)
}

func (c *Client) ListGatewayPods(ctx context.Context) ([]Pod, error) {
	query := url.Values{}
	query.Set("labelSelector", "gateway.networking.k8s.io/gateway-name="+c.config.GatewayName)
	var result PodList
	err := c.JSON(ctx, http.MethodGet, "/api/v1/namespaces/"+url.PathEscape(c.config.Namespace)+"/pods?"+query.Encode(), nil, &result)
	if err != nil {
		return nil, err
	}
	var running []Pod
	for _, pod := range result.Items {
		if pod.Status.Phase == "Running" && pod.Metadata.UID != "" {
			running = append(running, pod)
		}
	}
	return running, nil
}

func (c *Client) GetPolicy(ctx context.Context) (SnippetsPolicy, error) {
	var result SnippetsPolicy
	err := c.JSON(ctx, http.MethodGet, PolicyPath(c.config.Namespace, c.config.PolicyName), nil, &result)
	return result, err
}

func (c *Client) CreatePolicy(ctx context.Context, policy SnippetsPolicy) error {
	return c.JSON(ctx, http.MethodPost, "/apis/gateway.nginx.org/v1alpha1/namespaces/"+url.PathEscape(c.config.Namespace)+"/snippetspolicies", policy, nil)
}

func (c *Client) UpdatePolicy(ctx context.Context, policy SnippetsPolicy) error {
	return c.JSON(ctx, http.MethodPut, PolicyPath(c.config.Namespace, c.config.PolicyName), policy, nil)
}

func (c *Client) FollowLogs(ctx context.Context, podName string, since time.Time, onOpen, onClose func(), onLine func([]byte)) error {
	query := url.Values{}
	query.Set("container", "nginx")
	query.Set("follow", "true")
	query.Set("timestamps", "true")
	query.Set("sinceTime", since.UTC().Format(time.RFC3339Nano))
	path := "/api/v1/namespaces/" + url.PathEscape(c.config.Namespace) + "/pods/" + url.PathEscape(podName) + "/log?" + query.Encode()
	response, err := c.request(ctx, c.streamHTTP, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	onOpen()
	defer onClose()
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 64*1024), 256*1024)
	for scanner.Scan() {
		onLine(bytes.Clone(scanner.Bytes()))
	}
	return scanner.Err()
}
