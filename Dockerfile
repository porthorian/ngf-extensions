FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /ngf-extensions ./cmd/ngf-extensions

FROM scratch
COPY --from=build /ngf-extensions /ngf-extensions
USER 65532:65532
ENTRYPOINT ["/ngf-extensions"]
