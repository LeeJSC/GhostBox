BINARY=ghostbox

all: build

build:
	go build -o $(BINARY) ./cmd

install:
	go install ./cmd

clean:
	rm -f $(BINARY)
