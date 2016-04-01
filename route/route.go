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

const (
	classA_StartIp = uint32(184549376)
	classB_StartIp = uint32(2886729728)
	classC_StartIp = uint32(3232235520)
	classA_EndIp   = uint32(184549376)
	classB_EndIp   = uint32(2887778304)
	classC_EndIp   = uint32(3232301056)
)

var ( //全局变量   platform为字符串    metric为整型 region为字符串
	platform string
	metric   int
	region   string
)

func init() { //定义了一个有指定名字“p”，默认值为“openvpn”，用法说明标签为“Target.....”的string标签，参数&platform指向一个存储标签解析值的string变量
	flag.StringVar(&platform, "p", "openvpn", "Target platforms, it can be openvpn, mac, linux,win, android. openvpn by default.")
	//定义了一个有指定名字“m”，默认值为5，用法说明标签为“Metric.....”的int标签，参数&mertic指向一个存储标签解析值的int变量
	flag.IntVar(&metric, "m", 5, "Metric setting for the route rules")
	flag.StringVar(&region, "r", "not-asia", "Target regions,it can be not-asia,asia,china.not-asia by default ")
}

func main() {
	router := map[string]func([]apnicData){ //创建map类的容器router，router内一个字符串对应一个apnicData的数组
		"openvpn": generate_open,
		"linux":   generate_linux,
		"mac":     generate_mac,
		"win":     generate_win,
		"android": generate_android,
		"routeos": generate_routeos,
	}
	area := map[string]string{
		"not-asia": reg_comp_na,
		"asia":     reg_comp_as,
		"china":    reg_comp_cn,
	}
	flag.Parse()                             //从参数os.Args[1:]中解析命令行标签。 这个方法调用时间点必须在FlagSet的所有标签都定义之后，程序访问这些标签之前。
	if fun := router[platform]; fun != nil { //fun为函数generate_open、linux、mac、win、android中的一种，由输入的参数所决定  假设用的是open
		data := fetch_ip_data(area) //data为函数返回的anpicData结构数组results
		fun(data)                   //假设用的mac设备，则将data数组传递给函数generate_mac
	} else {
		fmt.Printf("Platform %s is not supported.\n", platform)
	}
}

// remove address list use `/ip firewall address-list remove [/ip firewall address-list find list="chnroutes"]`
/*
/ip firewall address-list add list=chnroutes address=10.0.0.0/8
/ip firewall address-list add list=chnroutes address=172.16.0.0/12
/ip firewall address-list add list=chnroutes address=192.168.0.0/16
*/

func generate_routeos(data []apnicData) {
	fp := safeCreateFile("routes.txt")
	defer fp.Close()         //最后当函数关闭之前将创建的文件关闭
	for _, v := range data { //遍历数组data，将内容放入v  route_item是格式为route 首地址(string型) mask(net.ip型的String方法将其转为字符串) mertic(int)
		route_item := fmt.Sprintf("/ip firewall address-list add list=%s address=%s/%d\n", region, v.startIp, v.maskNum)
		fp.WriteString(route_item) //每次循环都将route_item写入到生成的文件中
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

func fetch_ip_data(area map[string]string) []apnicData {
	// fetch data from apnic
	fmt.Println("Fetching data from apnic.net, it might take a few minutes, please wait...") //输出等待
	url := "http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"                   //url设为字符串变量
	resp, err := http.Get(url)                                                               //向apnic发送get请求
	if err != nil {                                                                          //若返回的err参数不为空，则进行输出错误处理，并退出
		fmt.Println(err.Error())
		os.Exit(-1)
	}
	results := make([]apnicData, 0) //创建一个名为results的apnicData数组
	defer resp.Body.Close()         //在返回函数钱关闭resp.Body
	//正则表达式：将( 和 ) 之间的表达式定义为“组”（group），并且将匹配这个表达式的字符保存到一个临时区域（一个正则表达式中最多可以保存9个），它们可以用 \1 到\9 的符号来引用。
	br := bufio.NewReader(resp.Body) //resp.Body为io.Reader型，br为*Reader型
	if region != "not-asia" {
		var reg = regexp.MustCompile(area[region]) //设置正则表达是，符合｀｀内的表达式
		for {                                      //死循环
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
			starting_ip := matches[2]   //首地址为第三个读出的内容，即第二个子匹配项的ip地址，以字符串形式赋给starting_ip
			if Ispravite(starting_ip) { //下面对抓取出来的ip地址进行判断是否为私有地址
				continue
			}
			num_ip, _ := strconv.Atoi(matches[3])                              //ip的数量为第四个读出，即第三个子匹配项的内容，将其转为int形式赋给num_ip
			imask := UintToIP(0xffffffff ^ uint32(num_ip-1))                   //将ip数量－1，并于ffffffff相减。得到的结果放给函数UintToIP，返回结果给imask
			imaskNum := 32 - int(math.Log2(float64(num_ip)))                   //将num_ip转为64位float进行Log2（）的运算，再转回int，用32去减，所得结果为imask数量
			results = append(results, apnicData{starting_ip, imask, imaskNum}) //将所得到的首地址、imask、imask数量构成一个apnicData结构加到results
		}
	} else if region == "not-asia" {
		cur_StartIp := uint32(0)                   //当前的首地址
		cur_EndIp := uint32(0)                     //当前的末地址
		last_Ip := uint32(0)                       //由于最后一次循环是由搜到的Ip作为末地址，并没有遍历0.0.0.0～255.255.255.255，所以设置一个变量用于记录循环时最后一个搜到Ip的末地址，以此来进行遍历
		var reg = regexp.MustCompile(area[region]) //设置正则表达是，符合｀｀内的表达式
		com_pro := 0                               //上次循环时所处的地址段,0表示在10.0.0.0之前，1表示在10.0.0.0和172.16.0.0之间，2表示在172.16.0.0和192.168.0.0之间，4表示在192.168.0.0之后
		com_cur := 0                               //本次循环时首地址的地址段
		for {                                      //死循环
			cur_StartIp = last_Ip
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
			matches := reg.FindStringSubmatch(string(line)) //not-asia的匹配项为asia，但是在国籍中加上了CN
			if len(matches) != 6 {                          //如果matches的长度不等于6则跳过本次循环
				continue
			}
			if Ispravite(matches[2]) { //下面对抓取出来的ip地址进行判断是否为私有地址，因为对跨越私有段有额外处理，所以依旧进行该判定
				continue
			}
			fetch_ip := matches[2] //首地址为第三个读出的内容，即第二个子匹配项的ip地址，以字符串形式赋给starting_ip
			switch privateclass(fetch_ip) {
			case "n": //classA之前
				com_cur = 0
			case "a": //classA之后
				com_cur = 1
			case "b": //classB之后
				com_cur = 2
			case "c": //classC之后
				com_cur = 3
			}
			val_Ip := changeIpToInt(fetch_ip)
			x, _ := strconv.Atoi(matches[3])
			last_Ip = val_Ip + uint32(x)      //该变量为循环时抓去到的亚洲IP首地址＋ip数，为下次循环时的开始地址
			if com_pro == 0 && com_cur == 1 { //对2个变量进行判定，如果出现一个变量在私有地址的右边，一个在左边则说明这次循环跨越私有段，对此进行额外的操作。
				cur_EndIp = classA_StartIp
				num_ip := cur_EndIp - cur_StartIp
				starting_ip := getStartingIp(cur_StartIp)
				imask := UintToIP(0xffffffff ^ uint32(num_ip-1)) //将ip数量－1，并于ffffffff相减。得到的结果放给函数UintToIP，返回结果给imask
				imaskNum := 32 - int(math.Log2(float64(num_ip))) //将num_ip转为64位float进行Log2（）的运算，再转回int，用32去减，所得结果为imask数量
				results = append(results, apnicData{starting_ip, imask, imaskNum})
				cur_StartIp = classA_EndIp
			}
			if com_pro == 1 && com_cur == 2 {
				cur_EndIp = classB_StartIp
				num_ip := cur_EndIp - cur_StartIp
				starting_ip := getStartingIp(cur_StartIp)
				imask := UintToIP(0xffffffff ^ uint32(num_ip-1)) //将ip数量－1，并于ffffffff相减。得到的结果放给函数UintToIP，返回结果给imask
				imaskNum := 32 - int(math.Log2(float64(num_ip))) //将num_ip转为64位float进行Log2（）的运算，再转回int，用32去减，所得结果为imask数量
				results = append(results, apnicData{starting_ip, imask, imaskNum})
				cur_StartIp = classB_EndIp
			}
			if com_pro == 2 && com_cur == 3 {
				cur_EndIp = classC_StartIp
				num_ip := cur_EndIp - cur_StartIp
				starting_ip := getStartingIp(cur_StartIp)
				imask := UintToIP(0xffffffff ^ uint32(num_ip-2)) //将ip数量－1，并于ffffffff相减。得到的结果放给函数UintToIP，返回结果给imask
				imaskNum := 32 - int(math.Log2(float64(num_ip))) //将num_ip转为64位float进行Log2（）的运算，再转回int，用32去减，所得结果为imask数量
				results = append(results, apnicData{starting_ip, imask, imaskNum})
				cur_StartIp = classC_EndIp
			}
			cur_EndIp = val_Ip
			num_ip := cur_EndIp - cur_StartIp
			if num_ip == 0 { //如果相邻2次读取的IP连续，会导致减法后保留一个ip_num为0的无用项，所以跳过本次循环
				com_pro = com_cur //本次的结果不保留，但是对上次循环地址进行更新
				continue
			}
			starting_ip := getStartingIp(cur_StartIp)
			imask := UintToIP(0xffffffff ^ uint32(num_ip-1))
			imaskNum := 32 - int(math.Log2(float64(num_ip)))
			results = append(results, apnicData{starting_ip, imask, imaskNum}) //将所得到的首地址、imask、imask数量构成一个apnicData结构加到results
			com_pro = com_cur                                                  //循环结束时将上次循环的地址段更新，以此来和下次循环的地址段进行比较判定
		}
		starting_ip := getStartingIp(last_Ip)
		num_ip := 4294967295 - last_Ip - 1
		imask := UintToIP(0xffffffff ^ uint32(num_ip-1))
		imaskNum := 32 - int(math.Log2(float64(num_ip)))
		results = append(results, apnicData{starting_ip, imask, imaskNum})
	}
	return results //将最后得到的apnicData结构数组results返回
}

func getStartingIp(cur_StartIp uint32) string {
	first_int := int(cur_StartIp / uint32(0x1000000))
	second_int := int((cur_StartIp - uint32(first_int*0x1000000)) / uint32(0x10000))
	third_int := int((cur_StartIp - uint32(first_int*0x1000000+second_int*0x10000)) / uint32(0x100))
	fourth_int := int(cur_StartIp - uint32(first_int*0x1000000) - uint32(second_int*0x10000) - uint32(third_int*0x100))
	first_string := strconv.Itoa(first_int)
	second_string := strconv.Itoa(second_int)
	third_string := strconv.Itoa(third_int)
	fourth_string := strconv.Itoa(fourth_int)
	starting_ip := first_string + "." + second_string + "." + third_string + "." + fourth_string
	return starting_ip
}
func changeIpToInt(starting_ip string) uint32 { //将ip地址由点分十进制转为一个整数
	var val_Ip uint32
	val_ip := []byte(starting_ip) //当前位置ip的值,首先将ip地址转为［］byte型
	lenIp := len(starting_ip)
	pos_ip := 0                 //循环取出ip地址每一段时所在的位置
	first_ip_byte := [3]byte{}  //第一段ip地址的值（［］byte）
	second_ip_byte := [3]byte{} //第二段ip地址的值（［］byte）
	third_ip_byte := [3]byte{}  //第三段ip地址的值（［］byte）
	fourth_ip_byte := [3]byte{} //第四段ip地址的值（［］byte）
	var first_ip_int int        //第一段ip地址的值（int）
	var second_ip_int int       //第二段ip地址的值（int）
	var third_ip_int int        //第三段ip地址的值（int）
	var fourth_ip_int int       //第四段ip地址的值（int）
	first := make([]byte, 0, 3)
	second := make([]byte, 0, 3)
	third := make([]byte, 0, 3)
	fourth := make([]byte, 0, 3)
	for i := 0; val_ip[pos_ip] >= '0' && val_ip[pos_ip] <= '9'; pos_ip++ {
		first_ip_byte[i] = val_ip[pos_ip]
		first = append(first, first_ip_byte[i])
		i++
	}
	pos_ip++
	for i := 0; val_ip[pos_ip] >= '0' && val_ip[pos_ip] <= '9'; pos_ip++ {
		second_ip_byte[i] = val_ip[pos_ip]
		second = append(second, second_ip_byte[i])
		i++
	}
	pos_ip++
	for i := 0; val_ip[pos_ip] >= '0' && val_ip[pos_ip] <= '9'; pos_ip++ {
		third_ip_byte[i] = val_ip[pos_ip]
		third = append(third, third_ip_byte[i])
		i++
	}
	pos_ip++
	for i := 0; val_ip[pos_ip] >= '0' && val_ip[pos_ip] <= '9'; {
		fourth_ip_byte[i] = val_ip[pos_ip]
		fourth = append(fourth, fourth_ip_byte[i])
		i++
		pos_ip++
		if pos_ip == lenIp {
			break
		}
	}
	first_ip_int, _ = strconv.Atoi(string(first))
	second_ip_int, _ = strconv.Atoi(string(second))
	third_ip_int, _ = strconv.Atoi(string(third))
	fourth_ip_int, _ = strconv.Atoi(string(fourth))
	val_Ip = uint32(first_ip_int*0x1000000 + second_ip_int*0x10000 + third_ip_int*0x100 + fourth_ip_int)
	return val_Ip
}
func privateclass(starting_ip string) string { //ip地址为0.0.0.0～10.0.0.0返回n
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
	x := first_ip_int*0x100 + second_ip_int //将首段与第二段看成一个4位16进制整数，通过该整数判断ip地址在哪个私有IP范围下
	if x < 2560 {
		return "n" //ip地址为0.0.0.0～10.0.0.0返回n
	}
	if x > 2560 && x < 44048 {
		return "a" //10.0.0.0～172.16.0.0 返回a
	}
	if x > 44048 && x < 49320 {
		return "b" //172.16.0.0～192.168.0.0 返回b
	}
	if x > 49320 {
		return "c" //192.168.0.0以后的返回c
	}
	return "n"
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
var reg_comp_na string = `apnic\|(MN|KP|KR|JP|VN|LA|KH|TH|MM|MY|SG|ID|BN|PH|TL|IN|BD|BT|NP|PK|LK|MV|SA|AE|TR|LB|IQ|IR|AF|CN)+\|ipv4\|([0-9|\.]{1,15})\|(\d+)\|(\d+)\|([a-z]+)`
var reg_comp_as string = `apnic\|(MN|KP|KR|JP|VN|LA|KH|TH|MM|MY|SG|ID|BN|PH|TL|IN|BD|BT|NP|PK|LK|MV|SA|AE|TR|LB|IQ|IR|AF)+\|ipv4\|([0-9|\.]{1,15})\|(\d+)\|(\d+)\|([a-z]+)`
var reg_comp_cn string = `apnic\|(CN)+\|ipv4\|([0-9|\.]{1,15})\|(\d+)\|(\d+)\|([a-z]+)`
