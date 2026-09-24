# ngf-extensions

Optional extensions for [NGINX Gateway Fabric](https://github.com/nginx/nginx-gateway-fabric). The first component is a timed IP ban controller. The repository is licensed under Apache-2.0.

## Timed bans

The controller reads structured NGINX access logs from every pod for one configured Gateway. It counts 401 responses for a configured host and path prefix, and 429 responses only when NGINX reports `limit_req_status=REJECTED`. It aggregates across pods, deduplicates request IDs on log reconnect, and adds individual public IPs to a generated Gateway `SnippetsPolicy`. Active ban expiries persist in a ConfigMap. A separate allowlist ConfigMap prevents automatic bans; it does not affect a separate manual deny policy.

Defaults are 120 401s in five minutes or 30 qualifying 429s in one minute, a 15 minute ban, 30 second reconciliation, and a maximum of 200 active bans. The controller ignores private, loopback, link-local, and shared `100.64.0.0/10` addresses. The NGINX access log must contain `client_ip`, `host`, `path`, `status`, `limit_req_status`, and `request_id` JSON fields. It must log the gateway-observed client address and a path without query strings. The Gateway must support `SnippetsPolicy`, with snippets enabled.

The image is `ghcr.io/porthorian/ngf-extensions`. Run its `timed-ban-controller` subcommand. The chart is published as `oci://ghcr.io/porthorian/charts/ngf-extensions` and is disabled by default. To enable it:

```yaml
timedBan:
  enabled: true
  gatewayName: public-gateway
  targetHost: api.example.com
  pathPrefix: /v1
  allowlist:
    cidrs:
      - 203.0.113.10/32
```

Set `allowlist.existingConfigMap` to read a separately managed ConfigMap with an `allow-cidrs` key instead. The chart then leaves that ConfigMap untouched. Set `image.digest` to pin an image. The chart creates a Deployment, ServiceAccount, namespace-scoped Role and RoleBinding, and an optional PodMonitor. The controller alone creates and updates its state ConfigMap and generated `SnippetsPolicy`. Do not manage those two objects with Helm or GitOps.

Metrics are exposed on port 9090 at `/metrics`, with `/healthz` and `/readyz`. The metrics include active bans, active log watchers, additions by reason, and the last successful reconciliation timestamp. NGINX Open Source does not provide per-IP request metrics; this controller uses access logs for detection.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
helm lint chart
helm template test chart --namespace gateway-system --set timedBan.enabled=true --set timedBan.gatewayName=public-gateway --set timedBan.targetHost=api.example.com
```
