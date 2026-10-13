.PHONY: lint test test_decode test_go test_yaegi bench bench_go bench_yaegi vendor clean

export GO111MODULE=on

default: lint test

lint:
	go vet

# Decodes .traefik.yml with the mapstructure settings Traefik uses. A separate
# module, so the plugin itself stays standard-library only for Yaegi.
test: test_decode test_go test_yaegi
	cd decodetest && go test ./...
	go test -v -cover ./...

test_yaegi:
	yaegi test -v .

# Benchmarks under both runtimes. Traefik runs this plugin through the Yaegi
# interpreter, so bench_go measures the algorithm and bench_yaegi measures
# what production actually pays; interpreted costs are not proportional to
# compiled ones (see readme.md, "Performance").
bench: bench_go bench_yaegi

bench_go:
	go test -run '^$$' -bench=. -benchmem ./...

bench_yaegi:
	yaegi test -run '^$$' -bench=. -benchmem .

vendor:
	go mod vendor

clean:
	rm -rf ./vendor
