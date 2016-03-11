// route_test.go
package main

import (
	"os"
	"regexp"
	"testing"
)

func TestIspravite(t *testing.T) {
	class_a := "10.1.1.5"
	class_b := "172.25.255.1"
	class_c := "192.168.65.5"
	pub := "1.0.5.255"
	if Ispravite(class_a) == false {
		t.Log("class A:", class_a, "should be pravite")
		t.Fail()
	}
	if Ispravite(class_b) == false {
		t.Log("class B:", class_b, "should be pravite")
		t.Fail()
	}
	if Ispravite(class_c) == false {
		t.Log("class C:", class_c, "should be pravite")
		t.Fail()
	}
	if Ispravite(pub) == true {
		t.Log("pub:", pub, "should be public")
		t.Fail()
	}
}

func TestIsNotInAsia(t *testing.T) {
	a := "apnic|CN|ipv4|1.0.8.0|2048|20110412|allocated"
	b := "apnic|JP|ipv4|1.0.16.0|4096|20110412|allocated"
	c := "apnic|AU|ipv4|1.0.0.0|256|20110811|assigned"
	var reg = regexp.MustCompile(reg_comp)
	matches := reg.FindStringSubmatch(a)
	if matches != nil {
		t.Fail()
	}
	matches = reg.FindStringSubmatch(b)
	if matches != nil {
		t.Fail()
	}
	matches = reg.FindStringSubmatch(c)
	if matches == nil {
		t.Fail()
	}
}

func TestSafeCreateFile(t *testing.T) {
	n := "Helloword"
	safeCreateFile(n)
	_, err := os.Stat(n)
	if err != nil {
		t.Log("Don't create the file")
		t.Fail()
	}

}
