.PHONY: lint test bench bench_go bench_yaegi yaegi_test vendor clean

export GO111MODULE=on

default: lint test

lint:
	golangci-lint run

test:
	go test -v -cover ./...

# Benchmarks under both runtimes. Traefik runs this plugin through the Yaegi
# interpreter, so bench_go measures the algorithm and bench_yaegi measures
# what production actually pays; interpreted costs are not proportional to
# compiled ones (see readme.md, "Performance").
bench: bench_go bench_yaegi

bench_go:
	go test -run '^$$' -bench=. -benchmem ./...

bench_yaegi:
	yaegi test -run '^$$' -bench=. -benchmem .

yaegi_test:
	yaegi test -v .

vendor:
	go mod vendor

clean:
	rm -rf ./vendor
