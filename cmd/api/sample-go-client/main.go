package main

func main() {
	var silkworm Silkworm

	LoadSilkworm(&silkworm, "libsilkworm_api.so")

	silkworm.Init()
	//silkworm.AddSnapshot()
	silkworm.Fini()
}
