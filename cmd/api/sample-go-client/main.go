package main

func main() {
	var silkworm Silkworm

	LoadSilkworm(&silkworm, "execute_cpp.so")

	silkworm.Init()
	silkworm.Fini()
}
