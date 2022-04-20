package POC

import (
	"github.com/gookit/color"
	"strings"
)

//定义一个攻击接口
type attack interface {
	Attack(targets string) bool
}

//在这里维护POC接口map，一一对应的关系
var PluginList map[string]attack = map[string]attack{
	"IceWarp WebClient": IceWarp_WebClient_basic_command_injection{},
}

//攻击匹配
func Attackmatch(target string, banner string) {
	for finp, POC := range PluginList {
		if strings.Contains(finp, banner) {
			flag := POC.Attack(target)
			if flag == true {
				color.RGBStyleFromString("237,64,35").Println("[+] Send Payload to ", target, " | Banner: "+banner+" | match: True")
			} else {
				color.RGBStyleFromString("195,195,195").Println("[+] Send Payload to ", target, " | Banner: "+banner+" | match: False")
			}
		}
	}
}
