package POC

import (
	"github.com/gookit/color"
	"net/http"
	"strings"
)

type Returnre struct {
	Flag    bool
	Target  string
	Bannner string
	Pocname string
}

//定义一个攻击接口
type attack interface {
	Attack(targets string, client *http.Client) Returnre
}

//在这里维护POC接口map，一一对应的关系
var PluginList map[string]attack = map[string]attack{
	"IceWarp WebClient": IceWarp_WebClient_basic_command_injection{},
}

//攻击匹配
func Attackmatch(target string, banner string, client *http.Client) Returnre {
	var temp Returnre
	for finp, POC := range PluginList {
		if strings.Contains(finp, banner) {
			temp = POC.Attack(target, client)
			if temp.Flag == true {
				color.RGBStyleFromString("237,64,35").Println("[+] Send Payload to ", target, " | Banner: "+banner+"| match: True")
				return temp
			} else {
				color.RGBStyleFromString("195,195,195").Println("[+] Send Payload to ", target, " | Banner: "+banner+" | match: False")
				return temp
			}
		}
	}
	color.RGBStyleFromString("195,195,195").Println("[+] Send Payload to ", target, " | Banner: "+banner+" | match: don't have poc")
	temp.Bannner = banner
	temp.Pocname = ""
	temp.Flag = false
	return temp
}
