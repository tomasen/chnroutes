// route_test.go
package main

import (
	"os"
	"regexp"
	"testing"
)

func TestIspravite(t *testing.T) {
	classA := "10.1.1.5"
	classB := "172.25.255.1"
	classC := "192.168.65.5"
	pub := "1.0.5.255"
	if !Ispravite(classA) {
		t.Log("class A:", classA, "should be pravite")
		t.Fail()
	}
	if !Ispravite(classB) {
		t.Log("class B:", classB, "should be pravite")
		t.Fail()
	}
	if !Ispravite(classC) {
		t.Log("class C:", classC, "should be pravite")
		t.Fail()
	}
	if Ispravite(pub) {
		t.Log("pub:", pub, "should be public")
		t.Fail()
	}
}

func TestIsInAsia(t *testing.T) {
	b := "apnic|JP|ipv4|1.0.16.0|4096|20110412|allocated"
	c := "apnic|AU|ipv4|1.0.0.0|256|20110811|assigned"
	var reg = regexp.MustCompile(reg_comp_as)
	matches := reg.FindStringSubmatch(b)
	if matches == nil {
		t.Fail()
	}
	matches = reg.FindStringSubmatch(c)
	if matches != nil {
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
