stdlib:
	go test -bench . -benchmem -count 5 -timeout 60m | tee stdlib.txt

goccy:
	go test -bench . -benchmem -count 5 -timeout 60m -tags jwx_goccy | tee goccy.txt

asmbase64:
	go test -bench . -benchmem -count 5 -timeout 60m -tags jwx_asmbase64 | tee asmbase64.txt

goccy-asmbase64:
	go test -bench . -benchmem -count 5 -timeout 60m -tags jwx_goccy,jwx_asmbase64 | tee goccy-asmbase64.txt

benchstat:
	benchstat stdlib.txt goccy.txt
