package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
)

type apnicData struct { //建立了一个apnic结构，结构包括一个字符串，一个IP地址和一个整型
	startIp string
	mask    net.IP
	maskNum int
}

var ( //全局变量   platform为字符串    metric为整型
	platform string
	metric   int
)

func init() { //定义了一个有指定名字“p”，默认值为“openvpn”，用法说明标签为“Target.....”的string标签，参数&platform指向一个存储标签解析值的string变量
	flag.StringVar(&platform, "p", "openvpn", "Target platforms, it can be openvpn, mac, linux,win, android. openvpn by default.")
	//定义了一个有指定名字“m”，默认值为5，用法说明标签为“Metric.....”的int标签，参数&mertic指向一个存储标签解析值的int变量
	flag.IntVar(&metric, "m", 5, "Metric setting for the route rules")
}

func main() {
	router := map[string]func([]apnicData){ //创建map类的容器router，router内一个字符串对应一个apnicData的数组
		"openvpn": generate_open,
		"linux":   generate_linux,
		"mac":     generate_mac,
		"win":     generate_win,
		"android": generate_android,
	}

	flag.Parse()                             //从参数os.Args[1:]中解析命令行标签。 这个方法调用时间点必须在FlagSet的所有标签都定义之后，程序访问这些标签之前。
	if fun := router[platform]; fun != nil { //fun为函数generate_open、linux、mac、win、android中的一种，由输入的参数所决定  假设用的是open
		data := fetch_ip_data() //data为函数返回的anpicData结构数组results
		fun(data)               //假设用的mac设备，则将data数组传递给函数generate_mac
	} else {
		fmt.Printf("Platform %s is not supported.\n", platform)
	}
}

func generate_open(data []apnicData) {
	fp := safeCreateFile("routes.txt")
	defer fp.Close()         //最后当函数关闭之前将创建的文件关闭
	for _, v := range data { //遍历数组data，将内容放入v  route_item是格式为route 首地址(string型) mask(net.ip型的String方法将其转为字符串) mertic(int)
		route_item := fmt.Sprintf("route %s %s net_gateway %d\n", v.startIp, v.mask.String(), metric)
		fp.WriteString(route_item) //每次循环都将route_item写入到生成的文件中
	}
	fmt.Printf("Usage: Append the content of the newly created routes.txt to your openvpn config file, and also add 'max-routes %d', which takes a line, to the head of the file.\n", len(data)+20)
}

func generate_linux(data []apnicData) {
	upfile := safeCreateFile("ip-pre-up") //创建2个文件
	downfile := safeCreateFile("ip-down")
	defer upfile.Close() //函数返回前都会关闭2个文件
	defer downfile.Close()

	upfile.WriteString(linux_upscript_header) //给2个文件写入一开始设置的2段字符串
	downfile.WriteString(linux_downscript_header)

	for _, v := range data {
		upstr := fmt.Sprintf("route add -net %s netmask %s gw $OLDGW\n", v.startIp, v.mask.String())
		upfile.WriteString(upstr)
		dnstr := fmt.Sprintf("route del -net %s netmask %s\n", v.startIp, v.mask.String())
		downfile.WriteString(dnstr)
	}
	downfile.WriteString("rm /tmp/vpn_oldgw\n")

	fmt.Println("For pptp only, please copy the file ip-pre-up to the folder/etc/ppp, please copy the file ip-down to the folder /etc/ppp/ip-down.d.")
}

func generate_mac(data []apnicData) {
	upfile := safeCreateFile("ip-up")
	downfile := safeCreateFile("ip-down")
	defer upfile.Close()
	defer downfile.Close()

	upfile.WriteString(mac_upscript_header)
	downfile.WriteString(mac_downscript_header)

	for _, v := range data {
		upstr := fmt.Sprintf("route add %s/%d \"${OLDGW}\"\n", v.startIp, v.maskNum)
		upfile.WriteString(upstr)
		dnstr := fmt.Sprintf("route delete %s/%d ${OLDGW}\n", v.startIp, v.maskNum)
		downfile.WriteString(dnstr)
	}
	downfile.WriteString("\n\nrm /tmp/pptp_oldgw\n")

	fmt.Println("For pptp on mac only, please copy ip-up and ip-down to the /etc/ppp folder, don't forget to make them executable with the chmod command.")
}

func generate_win(data []apnicData) {
	upfile := safeCreateFile("vpnup.bat")
	downfile := safeCreateFile("vpndown.bat")
	defer upfile.Close()
	defer downfile.Close()

	upfile.WriteString(ms_upscript_header)
	upfile.WriteString("ipconfig /flushdns\n\n")
	downfile.WriteString("@echo off\n")

	for _, v := range data {
		upstr := fmt.Sprintf("route add %s mask %s %%gw%% metric %d\n", v.startIp, v.mask.String(), metric)
		upfile.WriteString(upstr)
		dnstr := fmt.Sprintf("route delete %s\n", v.startIp)
		downfile.WriteString(dnstr)
	}

	fmt.Println("For pptp on windows only, run vpnup.bat before dialing to vpn, and run vpndown.bat after disconnected from the vpn.")
}

func generate_android(data []apnicData) {
	upfile := safeCreateFile("vpnup.sh")
	downfile := safeCreateFile("vpndown.sh")
	defer upfile.Close()
	defer downfile.Close()

	upfile.WriteString(android_upscript_header)
	downfile.WriteString(android_downscript_header)

	for _, v := range data {
		upstr := fmt.Sprintf("route add -net %s netmask %s gw $OLDGW\n", v.startIp, v.mask.String())
		upfile.WriteString(upstr)
		dnstr := fmt.Sprintf("route del -net %s netmask %s\n", v.startIp, v.mask.String())
		downfile.WriteString(dnstr)
	}

	fmt.Println("Old school way to call up/down script from openvpn client. use the regular openvpn 2.1 method to add routes if it's possible")
}

func fetch_ip_data() []apnicData {
	// fetch data from apnic
	fmt.Println("Fetching data from apnic.net, it might take a few minutes, please wait...") //输出等待
	url := "http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"                   //url设为字符串变量
	resp, err := http.Get(url)                                                               //向apnic发送get请求
	if err != nil {                                                                          //若返回的err参数不为空，则进行输出错误处理，并退出
		fmt.Println(err.Error())
		os.Exit(-1)
	}
	defer resp.Body.Close() //在返回函数钱关闭resp.Body
	//正则表达式：将( 和 ) 之间的表达式定义为“组”（group），并且将匹配这个表达式的字符保存到一个临时区域（一个正则表达式中最多可以保存9个），它们可以用 \1 到\9 的符号来引用。
	br := bufio.NewReader(resp.Body) //resp.Body为io.Reader型，br为*Reader型
	var reg = regexp.MustCompile(reg_comp)
	//设置正则表达是，符合｀｀内的表达式
	results := make([]apnicData, 0) //创建一个名为results的apnicData数组
	for {                           //死循环
		line, isPrefix, err := br.ReadLine() //读一行文本，将内容赋给line
		if err != nil {                      //如果有报错
			if err != io.EOF { //如果错误信息不是读到文件末
				fmt.Println(err.Error()) //输出错误信息
				os.Exit(-1)              //退出
			}
			break //如果是读到尾部，退出循环
		}

		if isPrefix { //如果一行内容超出上限
			fmt.Println("You should not see this!") //输出“你不该看到这个”
			return results                          //返回results
		}

		matches := reg.FindStringSubmatch(string(line)) //matches是一个字符串数组，返回了符合之前正则表达式里面的完整匹配项和子匹配项（每个（）所符合的内容）
		if len(matches) != 6 {                          //如果matches的长度不等于6则跳过本次循环
			continue
		}

		starting_ip := matches[2] //首地址为第三个读出的内容，即第二个子匹配项的ip地址，以字符串形式赋给starting_ip
		//fmt.Printf("%s %v %d\n", starting_ip, imask, imaskNum)
		//下面对抓取出来的ip地址进行判断是否为私有地址
		if Ispravite(starting_ip) {
			continue
		}
		num_ip, _ := strconv.Atoi(matches[3])                              //ip的数量为第四个读出，即第三个子匹配项的内容，将其转为int形式赋给num_ip
		imask := UintToIP(0xffffffff ^ uint32(num_ip-1))                   //将ip数量－1，并于ffffffff相减。得到的结果放给函数UintToIP，返回结果给imask
		imaskNum := 32 - int(math.Log2(float64(num_ip)))                   //将num_ip转为64位float进行Log2（）的运算，再转回int，用32去减，所得结果为imask数量
		results = append(results, apnicData{starting_ip, imask, imaskNum}) //将所得到的首地址、imask、imask数量构成一个apnicData结构加到results
	}
	return results //将最后得到的apnicData结构数组results返回
}

func Ispravite(starting_ip string) bool {
	val_ip := []byte(starting_ip) //当前位置ip的值,首先将ip地址转为［］byte型
	pos_ip := 0                   //循环取出ip地址每一段时所在的位置
	first_ip_byte := [3]byte{}    //第一段ip地址的值（［］byte）
	second_ip_byte := [3]byte{}   //第二段ip地址的值（［］byte）
	var first_ip_int int          //第一段ip地址的值（int）
	var second_ip_int int         //第二段ip地址的值（int）
	var f []byte
	var s []byte
	for i := 0; val_ip[pos_ip] >= '0' && val_ip[pos_ip] <= '9'; pos_ip++ {
		first_ip_byte[i] = val_ip[pos_ip]
		f = append(f, first_ip_byte[i])
		i++
	}
	pos_ip++
	for i := 0; val_ip[pos_ip] >= '0' && val_ip[pos_ip] <= '9'; pos_ip++ {
		second_ip_byte[i] = val_ip[pos_ip]
		s = append(s, second_ip_byte[i])
		i++
	}
	first_ip_int, _ = strconv.Atoi(string(f))
	second_ip_int, _ = strconv.Atoi(string(s))
	if first_ip_int == 10 {
		return true
	}
	if first_ip_int == 172 {
		if second_ip_int >= 16 && second_ip_int <= 31 {
			return true
		}
	}
	if first_ip_int == 192 {
		if second_ip_int == 168 {
			return true
		}
	}
	return false
}

func UintToIP(ip uint32) net.IP {
	result := make(net.IP, 4)
	binary.BigEndian.PutUint32([]byte(result), ip)
	return result
}

func safeCreateFile(name string) *os.File {
	fp, err := os.Create(name) //创建一个文件
	if err != nil {            //如果有错误
		fmt.Println(err.Error()) //输出错误并退出程序
		os.Exit(-1)
	}
	return fp //返回这个文件
}

var linux_upscript_header string = `#!/bin/bash
export PATH="/bin:/sbin:/usr/sbin:/usr/bin"
OLDGW=$(ip route show | grep '^default' | sed -e 's/default via \\([^ ]*\\).*/\\1/')
if [ $OLDGW == '' ]; then
    exit 0
fi
if [ ! -e /tmp/vpn_oldgw ]; then
    echo $OLDGW > /tmp/vpn_oldgw
fi
`

var linux_downscript_header string = `#!/bin/bash
export PATH="/bin:/sbin:/usr/sbin:/usr/bin"
OLDGW=$(cat /tmp/vpn_oldgw)
`

var mac_upscript_header string = `#!/bin/sh
export PATH="/bin:/sbin:/usr/sbin:/usr/bin"
OLDGW=$(netstat -nr | grep '^default' | grep -v 'ppp' | sed 's/default *\\([0-9\.]*\\) .*/\\1/' | awk '{if($1){print $1}}')
if [ ! -e /tmp/pptp_oldgw ]; then
    echo "${OLDGW}" > /tmp/pptp_oldgw
fi
dscacheutil -flushcache
route add 10.0.0.0/8 "${OLDGW}"
route add 172.16.0.0/12 "${OLDGW}"
route add 192.168.0.0/16 "${OLDGW}"
`

var mac_downscript_header string = `#!/bin/sh
export PATH="/bin:/sbin:/usr/sbin:/usr/bin"
if [ ! -e /tmp/pptp_oldgw ]; then
        exit 0
fi
ODLGW=$(cat /tmp/pptp_oldgw)
route delete 10.0.0.0/8 "${OLDGW}"
route delete 172.16.0.0/12 "${OLDGW}"
route delete 192.168.0.0/16 "${OLDGW}"
`

var ms_upscript_header string = `for /F "tokens=3" %%* in ('route print ^| findstr "\\<0.0.0.0\\>"') do set "gw=%%*"\n`

var android_upscript_header string = `#!/bin/sh
alias nestat='/system/xbin/busybox netstat'
alias grep='/system/xbin/busybox grep'
alias awk='/system/xbin/busybox awk'
alias route='/system/xbin/busybox route'
OLDGW=$(netstat -rn | grep ^0\.0\.0\.0 | awk '{print $2}')
`

var android_downscript_header string = `#!/bin/sh
alias route='/system/xbin/busybox route'
`
var reg_comp string = `apnic\|(AU|BR|CK|CO|DE|ES|FJ|FM|GB|GN|GU|KE|KI|MH|MP|MU|NC|NE|NF|NI|NR|NU|NZ|PF|PG|PN|PW|SB|SE|SI|SN|TK|TO|TV|US|VU|WF|WS|ZA)+\|ipv4\|([0-9|\.]{1,15})\|(\d+)\|(\d+)\|([a-z]+)`
