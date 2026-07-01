BINARY := go-traceroute

.PHONY: all build cap_net_raw install-cap clean

all: build

build:
	go build -o $(BINARY) ./...

cap_net_raw: build
	sudo setcap cap_net_raw+ep ./$(BINARY)

install-cap: cap_net_raw

clean:
	rm -f $(BINARY)
