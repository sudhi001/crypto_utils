go test -coverprofile=coverage.out  ./... && go tool cover -html=coverage.out && rm coverage.out     
GOPROXY=proxy.golang.org go list -m github.com/sudhi001/crypto_utils@v0.1.0                 