stdlib:
	go test -bench . -benchmem -count 5 -timeout 60m | tee stdlib.txt

goccy:
	go test -bench . -benchmem -count 5 -timeout 60m -tags jwx_goccy | tee goccy.txt

benchstat:
	benchstat stdlib.txt goccy.txt
