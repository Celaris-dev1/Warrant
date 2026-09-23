FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /warrantd ./cmd/warrantd

FROM gcr.io/distroless/static-debian12
COPY --from=build /warrantd /warrantd
COPY examples /etc/warrant
EXPOSE 8430 8431
ENTRYPOINT ["/warrantd"]
