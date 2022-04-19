package main

import (
	"GOscan/module/searchEngine"
	"fmt"
)

func main() {
	query_str := "title=\"Vigor 300B\" || title=\"Vigor 2960\" || title=\"Vigor 2960\" || title=\"Vigor 3900\""
	for page := 0; page < 3; page++ {
		email := ""
		key := ""
		url := searchEngine.Fofa_api(query_str, email, key, 1)
		data := searchEngine.Getfofainfo(url)
		fmt.Println(data)
	}
}
