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
	startIP string
	mask    net.IP
	maskNum int
}

const (
	classAStartIP = uint32(0xA000000)
	classBStartIP = uint32(0XAC100000)
	classCStartIP = uint32(0xC0A80000)
	classAEndIP   = uint32(0xB000000)
	classBEndIP   = uint32(0xAC200000)
	classCEndIP   = uint32(0xC0A90000)
	constN        = "N"
)

var ( //全局变量   platform为字符串    metric为整型 region为字符串
	platform string
	metric   int
	region   string
	numCIDR  [32]uint32
)

func init() {
	numCIDR[0] = 1 //初始化CIDR的每个单元的IP数
	for i := uint32(1); i < 32; i++ {
		v := uint32(1)
		v = v << i
		numCIDR[i] = v
	}
}

func main() {
	flag.StringVar(&platform, "p", "openvpn", "Target platforms, it can be openvpn, mac, linux,win, android. openvpn by default.")
	flag.IntVar(&metric, "m", 5, "Metric setting for the route rules")
	flag.StringVar(&region, "r", "not-asia", "Target regions,it can be not-asia,asia,china.not-asia by default ")
	router := map[string]func([]apnicData){ //创建map类的容器router，router内一个字符串对应一个apnicData的数组
		"openvpn": generateOpen,
		"linux":   generateLinux,
		"mac":     generateMac,
		"win":     generateWin,
		"android": generateAndroid,
		"routeos": generateRouteos,
	}
	area := map[string]string{
		"not-asia": regCompNa,
		"asia":     regCompAs,
		"china":    regCompCn,
	}
	flag.Parse()                             //从参数os.Args[1:]中解析命令行标签。 这个方法调用时间点必须在FlagSet的所有标签都定义之后，程序访问这些标签之前。
	if fun := router[platform]; fun != nil { //fun为函数generateOpen、linux、mac、win、android中的一种，由输入的参数所决定  假设用的是open
		data := fetchIPData(area) //data为函数返回的anpicData结构数组results
		fun(data)                 //假设用的mac设备，则将data数组传递给函数generateMac
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

func generateRouteos(data []apnicData) {
	fp := safeCreateFile("routes.txt")
	defer fp.Close()         //最后当函数关闭之前将创建的文件关闭
	for _, v := range data { //遍历数组data，将内容放入v  routeItem是格式为route 首地址(string型) mask(net.ip型的String方法将其转为字符串) mertic(int)
		routeItem := fmt.Sprintf("/ip firewall address-list add list=%s address=%s/%d\n", region, v.startIP, v.maskNum)
		fp.WriteString(routeItem) //每次循环都将routeItem写入到生成的文件中
	}
}

func generateOpen(data []apnicData) {
	fp := safeCreateFile("routes.txt")
	defer fp.Close()         //最后当函数关闭之前将创建的文件关闭
	for _, v := range data { //遍历数组data，将内容放入v  routeItem是格式为route 首地址(string型) mask(net.ip型的String方法将其转为字符串) mertic(int)
		routeItem := fmt.Sprintf("route %s %s net_gateway %d\n", v.startIP, v.mask.String(), metric)
		fp.WriteString(routeItem) //每次循环都将routeItem写入到生成的文件中
	}
	fmt.Printf("Usage: Append the content of the newly created routes.txt to your openvpn config file, and also add 'max-routes %d', which takes a line, to the head of the file.\n", len(data)+20)
}

func generateLinux(data []apnicData) {
	upfile := safeCreateFile("ip-pre-up") //创建2个文件
	downfile := safeCreateFile("ip-down")
	defer upfile.Close() //函数返回前都会关闭2个文件
	defer downfile.Close()

	upfile.WriteString(linuxUpscriptHeader) //给2个文件写入一开始设置的2段字符串
	downfile.WriteString(linuxDownscriptHeader)

	for _, v := range data {
		upstr := fmt.Sprintf("route add -net %s netmask %s gw $OLDGW\n", v.startIP, v.mask.String())
		upfile.WriteString(upstr)
		dnstr := fmt.Sprintf("route del -net %s netmask %s\n", v.startIP, v.mask.String())
		downfile.WriteString(dnstr)
	}
	downfile.WriteString("rm /tmp/vpn_oldgw\n")

	fmt.Println("For pptp only, please copy the file ip-pre-up to the folder/etc/ppp, please copy the file ip-down to the folder /etc/ppp/ip-down.d.")
}

func generateMac(data []apnicData) {
	upfile := safeCreateFile("ip-up")
	downfile := safeCreateFile("ip-down")
	defer upfile.Close()
	defer downfile.Close()

	upfile.WriteString(macUpscriptHeader)
	downfile.WriteString(macDownscriptHeader)

	for _, v := range data {
		upstr := fmt.Sprintf("route add %s/%d \"${OLDGW}\"\n", v.startIP, v.maskNum)
		upfile.WriteString(upstr)
		dnstr := fmt.Sprintf("route delete %s/%d ${OLDGW}\n", v.startIP, v.maskNum)
		downfile.WriteString(dnstr)
	}
	downfile.WriteString("\n\nrm /tmp/pptp_oldgw\n")

	fmt.Println("For pptp on mac only, please copy ip-up and ip-down to the /etc/ppp folder, don't forget to make them executable with the chmod command.")
}

func generateWin(data []apnicData) {
	upfile := safeCreateFile("vpnup.bat")
	downfile := safeCreateFile("vpndown.bat")
	defer upfile.Close()
	defer downfile.Close()

	upfile.WriteString(msUpscriptHeader)
	upfile.WriteString("ipconfig /flushdns\n\n")
	downfile.WriteString("@echo off\n")

	for _, v := range data {
		upstr := fmt.Sprintf("route add %s mask %s %%gw%% metric %d\n", v.startIP, v.mask.String(), metric)
		upfile.WriteString(upstr)
		dnstr := fmt.Sprintf("route delete %s\n", v.startIP)
		downfile.WriteString(dnstr)
	}

	fmt.Println("For pptp on windows only, run vpnup.bat before dialing to vpn, and run vpndown.bat after disconnected from the vpn.")
}

func generateAndroid(data []apnicData) {
	upfile := safeCreateFile("vpnup.sh")
	downfile := safeCreateFile("vpndown.sh")
	defer upfile.Close()
	defer downfile.Close()

	upfile.WriteString(androidUpscriptHeader)
	downfile.WriteString(androidDownscriptHeader)

	for _, v := range data {
		upstr := fmt.Sprintf("route add -net %s netmask %s gw $OLDGW\n", v.startIP, v.mask.String())
		upfile.WriteString(upstr)
		dnstr := fmt.Sprintf("route del -net %s netmask %s\n", v.startIP, v.mask.String())
		downfile.WriteString(dnstr)
	}

	fmt.Println("Old school way to call up/down script from openvpn client. use the regular openvpn 2.1 method to add routes if it's possible")
}

func getResultsExceptNotAsia(resp *http.Response, br *bufio.Reader, area map[string]string) (results []apnicData) {
	var reg = regexp.MustCompile(area[region]) //设置正则表达是，符合｀｀内的表达式
	var proStartingIP string
	var proNumIP int
	for { //死循环
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
		startingIP := matches[2]   //首地址为第三个读出的内容，即第二个子匹配项的ip地址，以字符串形式赋给startingIP
		if isPravite(startingIP) { //下面对抓取出来的ip地址进行判断是否为私有地址
			continue
		}
		if len(results) == 0 {
			proNumIP, _ = strconv.Atoi(matches[3])
			proStartingIP = startingIP
		}
		numIP, _ := strconv.Atoi(matches[3]) //ip的数量为第四个读出，即第三个子匹配项的内容，将其转为int形式赋给numIP
		temIP := changeIPToInt(proStartingIP) + uint32(proNumIP)
		startingIPInt := changeIPToInt(startingIP)
		if needcombine(temIP, startingIPInt, uint32(proNumIP+numIP)) {
			results[len(results)-1] = getApnicData(proStartingIP, uint32(numIP+proNumIP))
			proNumIP = proNumIP + numIP
		} else {
			results = append(results, getApnicData(startingIP, uint32(numIP))) //将所得到的首地址、imask、imask数量构成一个apnicData结构加到results
			proStartingIP = startingIP
			proNumIP = numIP
		}
	}
	return results
}

func fetchIPData(area map[string]string) []apnicData {
	// fetch data from apnic
	fmt.Println("Fetching data from apnic.net, it might take a few minutes, please wait...") //输出等待
	url := "http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"                   //url设为字符串变量
	resp, err := http.Get(url)                                                               //向apnic发送get请求
	if err != nil {                                                                          //若返回的err参数不为空，则进行输出错误处理，并退出
		fmt.Println(err.Error())
		os.Exit(-1)
	}
	var results []apnicData //创建一个名为results的apnicData数组
	defer resp.Body.Close() //在返回函数钱关闭resp.Body
	//正则表达式：将( 和 ) 之间的表达式定义为“组”（group），并且将匹配这个表达式的字符保存到一个临时区域（一个正则表达式中最多可以保存9个），它们可以用 \1 到\9 的符号来引用。
	br := bufio.NewReader(resp.Body) //resp.Body为io.Reader型，br为*Reader型
	if region != "not-asia" {
		results = getResultsExceptNotAsia(resp, br, area)
		return results
	}
	curStartIP := uint32(0)                    //当前的首地址
	curEndIP := uint32(0)                      //当前的末地址
	lastIP := uint32(0)                        //由于最后一次循环是由搜到的Ip作为末地址，并没有遍历0.0.0.0～255.255.255.255，所以设置一个变量用于记录循环时最后一个搜到Ip的末地址，以此来进行遍历
	var reg = regexp.MustCompile(area[region]) //设置正则表达是，符合｀｀内的表达式
	comPro := 0                                //上次循环时所处的地址段,0表示在10.0.0.0之前，1表示在10.0.0.0和172.16.0.0之间，2表示在172.16.0.0和192.168.0.0之间，4表示在192.168.0.0之后
	comCur := 0                                //本次循环时首地址的地址段
	for {
		curStartIP = lastIP
		line, isPrefix, err := br.ReadLine()
		if err != nil {
			if err != io.EOF {
				fmt.Println(err.Error())
				os.Exit(-1)
			}
			break
		}
		if isPrefix {
			fmt.Println("You should not see this!")
			return results
		}
		matches := reg.FindStringSubmatch(string(line)) //not-asia的匹配项为not-asia
		if judge(matches) {
			continue
		}
		fetchIP := matches[2]
		comCur = privateclass(fetchIP)
		valIP := changeIPToInt(fetchIP)
		x, _ := strconv.Atoi(matches[3])
		lastIP = valIP + uint32(x) //该变量为循环时抓去到的亚洲IP首地址＋ip数，为下次循环时的开始地址
		classStartIP, class := getClass(comPro, comCur)
		if class != constN { //对2个变量进行判定，如果出现一个变量在私有地址的右边，一个在左边则说明这次循环跨越私有段，对此进行额外的操作。
			results, curStartIP, curEndIP, _, _ = getPrivateResult(curStartIP, classStartIP, results, class, 0, 0)
		}
		curEndIP = valIP
		numIP := curEndIP - curStartIP
		if numIP == 0 { //如果相邻2次读取的IP连续，会导致减法后保留一个ip_num为0的无用项，所以跳过本次循环
			comPro = comCur //本次的结果不保留，但是对上次循环地址进行更新
			continue
		}
		results, curStartIP, curEndIP, comPro, comCur = getPrivateResult(curStartIP, valIP, results, constN, comPro, comCur)
	}
	results = lastDeal(lastIP, results)
	return results
}

func judge(matches []string) bool {
	if len(matches) != 6 {
		return true
	}
	if isPravite(matches[2]) { //下面对抓取出来的ip地址进行判断是否为私有地址，因为对跨越私有段有额外处理，所以依旧进行该判定
		return true
	}
	return false
}

func getClass(comPro int, comCur int) (uint32, string) {
	class := constN
	var classStartIP uint32
	if comPro == 0 && comCur == 1 { //对2个变量进行判定，如果出现一个变量在私有地址的右边，一个在左边则说明这次循环跨越私有段，对此进行额外的操作。
		class = "A"
		classStartIP = classAStartIP
	}
	if comPro == 1 && comCur == 2 {
		class = "B"
		classStartIP = classBStartIP
	}
	if comPro == 2 && comCur == 3 {
		class = "C"
		classStartIP = classCStartIP
	}
	return classStartIP, class
}

func lastDeal(lastIP uint32, results []apnicData) []apnicData {
	startingIP := getStartingIP(lastIP)
	numIP := 0xFFFFFFFF - lastIP + 1
	if matchCIDR(numIP) {
		results = append(results, getApnicData(startingIP, numIP))
	} else {
		for {
			cNumIP := findMaxCIDR(numIP)
			numIP = numIP - cNumIP
			results = append(results, getApnicData(startingIP, cNumIP))
			startingIP = getStartingIP(changeIPToInt(startingIP) + cNumIP)
			if matchCIDR(numIP) {
				results = append(results, getApnicData(startingIP, numIP))
				break
			}
		}
	}
	return results
}

func getPrivateResult(curStartIP uint32, valIP uint32, results []apnicData, class string, comPro int, comCur int) ([]apnicData, uint32, uint32, int, int) {
	var classEndIP uint32
	switch class {
	case "A":
		classEndIP = classAEndIP
	case "B":
		classEndIP = classBEndIP
	case "C":
		classEndIP = classCEndIP
	}
	curEndIP := valIP
	numIP := curEndIP - curStartIP
	if matchCIDR(numIP) {
		startingIP := getStartingIP(curStartIP)
		results = append(results, getApnicData(startingIP, numIP))
		if class != constN {
			curStartIP = classEndIP
		} else {
			comPro = comCur
		}
	} else {
		startingIP := getStartingIP(curStartIP)
		for {
			cNumIP := findMaxCIDR(numIP)
			numIP = numIP - cNumIP
			results = append(results, getApnicData(startingIP, cNumIP))
			startingIP = getStartingIP(changeIPToInt(startingIP) + cNumIP)
			if matchCIDR(numIP) {
				results = append(results, getApnicData(startingIP, numIP))
				if class != constN {
					curStartIP = classEndIP
				} else {
					comPro = comCur
				}
				break
			}
		}
	}
	return results, curStartIP, curEndIP, comPro, comCur
}

func findMaxCIDR(numIP uint32) uint32 {
	if numIP == 0 {
		return 0
	}
	for i, v := range numCIDR {
		if v > numIP {
			return numCIDR[i-1]
		}
	}
	return numCIDR[31]
}
func matchCIDR(numIP uint32) bool {
	for _, v := range numCIDR {
		if numIP == v {
			return true
		}
	}
	return false
}

func needcombine(temIP, startingIPInt, numIP uint32) bool {
	need := false
	if temIP == startingIPInt {
		for _, v := range numCIDR {
			if numIP == v {
				need = true
			}
		}
		return need
	}
	return false
}
func getStartingIP(curStartIP uint32) string {
	firstInt := int(curStartIP / uint32(0x1000000))
	secondInt := int((curStartIP - uint32(firstInt*0x1000000)) / uint32(0x10000))
	thirdInt := int((curStartIP - uint32(firstInt*0x1000000+secondInt*0x10000)) / uint32(0x100))
	fourthInt := int(curStartIP - uint32(firstInt*0x1000000) - uint32(secondInt*0x10000) - uint32(thirdInt*0x100))
	firstString := strconv.Itoa(firstInt)
	secondString := strconv.Itoa(secondInt)
	thirdString := strconv.Itoa(thirdInt)
	fourthString := strconv.Itoa(fourthInt)
	startingIP := firstString + "." + secondString + "." + thirdString + "." + fourthString
	return startingIP
}
func getApnicData(startingIP string, numIP uint32) apnicData {
	imask := uintToIP(0xffffffff ^ (numIP - 1))
	imaskNum := 32 - int(math.Log2(float64(numIP)))
	data := apnicData{startingIP, imask, imaskNum}
	return data
}
func changeIPToInt(startingIP string) uint32 { //将ip地址由点分十进制转为一个整数
	var ip uint32
	valIP := []byte(startingIP) //当前位置ip的值,首先将ip地址转为［］byte型
	lenIP := len(startingIP)
	posIP := 0                //循环取出ip地址每一段时所在的位置
	firstIPByte := [3]byte{}  //第一段ip地址的值（［］byte）
	secondIPByte := [3]byte{} //第二段ip地址的值（［］byte）
	thirdIPByte := [3]byte{}  //第三段ip地址的值（［］byte）
	fourthIPByte := [3]byte{} //第四段ip地址的值（［］byte）
	var firstIPInt int        //第一段ip地址的值（int）
	var secondIPInt int       //第二段ip地址的值（int）
	var thirdIPInt int        //第三段ip地址的值（int）
	var fourthIPInt int       //第四段ip地址的值（int）
	first := make([]byte, 0, 3)
	second := make([]byte, 0, 3)
	third := make([]byte, 0, 3)
	fourth := make([]byte, 0, 3)
	for i := 0; valIP[posIP] >= '0' && valIP[posIP] <= '9'; posIP++ {
		firstIPByte[i] = valIP[posIP]
		first = append(first, firstIPByte[i])
		i++
	}
	posIP++
	for i := 0; valIP[posIP] >= '0' && valIP[posIP] <= '9'; posIP++ {
		secondIPByte[i] = valIP[posIP]
		second = append(second, secondIPByte[i])
		i++
	}
	posIP++
	for i := 0; valIP[posIP] >= '0' && valIP[posIP] <= '9'; posIP++ {
		thirdIPByte[i] = valIP[posIP]
		third = append(third, thirdIPByte[i])
		i++
	}
	posIP++
	for i := 0; valIP[posIP] >= '0' && valIP[posIP] <= '9'; {
		fourthIPByte[i] = valIP[posIP]
		fourth = append(fourth, fourthIPByte[i])
		i++
		posIP++
		if posIP == lenIP {
			break
		}
	}
	firstIPInt, _ = strconv.Atoi(string(first))
	secondIPInt, _ = strconv.Atoi(string(second))
	thirdIPInt, _ = strconv.Atoi(string(third))
	fourthIPInt, _ = strconv.Atoi(string(fourth))
	ip = uint32(firstIPInt*0x1000000 + secondIPInt*0x10000 + thirdIPInt*0x100 + fourthIPInt)
	return ip
}
func privateclass(startingIP string) int { //ip地址为0.0.0.0～10.0.0.0返回n

	x := changeIPToInt(startingIP) //将首段与第二段看成一个4位16进制整数，通过该整数判断ip地址在哪个私有IP范围下
	if x > classAStartIP && x < classBStartIP {
		return 1 //10.0.0.0～172.16.0.0 返回a
	}
	if x > classBStartIP && x < classCStartIP {
		return 2 //172.16.0.0～192.168.0.0 返回b
	}
	if x > classCStartIP {
		return 3 //192.168.0.0以后的返回c
	}
	return 0
}

func isPravite(startingIP string) bool {
	valIP := []byte(startingIP) //当前位置ip的值,首先将ip地址转为［］byte型
	posIP := 0                  //循环取出ip地址每一段时所在的位置
	firstIPByte := [3]byte{}    //第一段ip地址的值（［］byte）
	secondIPByte := [3]byte{}   //第二段ip地址的值（［］byte）
	var firstIPInt int          //第一段ip地址的值（int）
	var secondIPInt int         //第二段ip地址的值（int）
	var f []byte
	var s []byte
	for i := 0; valIP[posIP] >= '0' && valIP[posIP] <= '9'; posIP++ {
		firstIPByte[i] = valIP[posIP]
		f = append(f, firstIPByte[i])
		i++
	}
	posIP++
	for i := 0; valIP[posIP] >= '0' && valIP[posIP] <= '9'; posIP++ {
		secondIPByte[i] = valIP[posIP]
		s = append(s, secondIPByte[i])
		i++
	}
	firstIPInt, _ = strconv.Atoi(string(f))
	secondIPInt, _ = strconv.Atoi(string(s))
	return checkPravite(firstIPInt, secondIPInt)
}

func checkPravite(firstIPInt int, secondIPInt int) bool {
	if firstIPInt == 10 || (firstIPInt == 172 && secondIPInt >= 16 && secondIPInt <= 31) || (firstIPInt == 192 && secondIPInt == 168) {
		return true
	}
	return false
}
func uintToIP(ip uint32) net.IP {
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

var linuxUpscriptHeader = `#!/bin/bash
export PATH="/bin:/sbin:/usr/sbin:/usr/bin"
OLDGW=$(ip route show | grep '^default' | sed -e 's/default via \\([^ ]*\\).*/\\1/')
if [ $OLDGW == '' ]; then
    exit 0
fi
if [ ! -e /tmp/vpn_oldgw ]; then
    echo $OLDGW > /tmp/vpn_oldgw
fi
`

var linuxDownscriptHeader = `#!/bin/bash
export PATH="/bin:/sbin:/usr/sbin:/usr/bin"
OLDGW=$(cat /tmp/vpn_oldgw)
`

var macUpscriptHeader = `#!/bin/sh
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

var macDownscriptHeader = `#!/bin/sh
export PATH="/bin:/sbin:/usr/sbin:/usr/bin"
if [ ! -e /tmp/pptp_oldgw ]; then
        exit 0
fi
ODLGW=$(cat /tmp/pptp_oldgw)
route delete 10.0.0.0/8 "${OLDGW}"
route delete 172.16.0.0/12 "${OLDGW}"
route delete 192.168.0.0/16 "${OLDGW}"
`

var msUpscriptHeader = `for /F "tokens=3" %%* in ('route print ^| findstr "\\<0.0.0.0\\>"') do set "gw=%%*"\n`

var androidUpscriptHeader = `#!/bin/sh
alias nestat='/system/xbin/busybox netstat'
alias grep='/system/xbin/busybox grep'
alias awk='/system/xbin/busybox awk'
alias route='/system/xbin/busybox route'
OLDGW=$(netstat -rn | grep ^0\.0\.0\.0 | awk '{print $2}')
`

var androidDownscriptHeader = `#!/bin/sh
alias route='/system/xbin/busybox route'
`
var regCompNa = `apnic\|(MN|KP|KR|JP|VN|LA|KH|TH|MM|MY|SG|ID|BN|PH|TL|IN|BD|BT|NP|PK|LK|MV|SA|AE|TR|LB|IQ|IR|AF|TW|CN)+\|ipv4\|([0-9|\.]{1,15})\|(\d+)\|(\d+)\|([a-z]+)`
var regCompAs = `apnic\|(MN|KP|KR|JP|VN|LA|KH|TH|MM|MY|SG|ID|BN|PH|TL|IN|BD|BT|NP|PK|LK|MV|SA|AE|TR|LB|IQ|IR|AF|TW)+\|ipv4\|([0-9|\.]{1,15})\|(\d+)\|(\d+)\|([a-z]+)`
var regCompCn = `apnic\|(CN)+\|ipv4\|([0-9|\.]{1,15})\|(\d+)\|(\d+)\|([a-z]+)`
