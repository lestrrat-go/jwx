stdlib:
	go test -bench . -benchmem | tee stdlib.txt

goccy:
	go test -bench . -benchmem -tags jwx_goccy | tee goccy.txt

asmbase64:
	go test -bench . -benchmem -tags jwx_asmbase64 | tee asmbase64.txt

