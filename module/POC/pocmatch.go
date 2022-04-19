package POC

import (
	"encoding/json"
	"fmt"
	"github.com/gookit/color"
	"io/ioutil"
	"strings"
)

type Packjson struct {
	Fingerprint []Fingerprint
}

type Fingerprint struct {
	Cms string
	POC string
}

var (
	Pocfingerprint *Packjson
)

func LoadPocfingerprint(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println(err)
		return err
	}
	var config Packjson
	err = json.Unmarshal(data, &config)
	if err != nil {
		return err
	}
	Pocfingerprint = &config
	return nil
}

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
				color.RGBStyleFromString("237,64,35").Println("[+] Send Payload to ", target, " | banner: "+banner+" | match: True")
			} else {
				color.RGBStyleFromString("195,195,195").Println("[+] Send Payload to ", target, " | banner: "+banner+" | match: False")
			}
		}
	}
}
