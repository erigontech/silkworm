package main

func main() {
	var silkworm Silkworm

	LoadSilkworm(&silkworm, "libsilkworm_api.dylib")

	silkworm.Init()
	//silkworm.AddSnapshot()
	silkworm.Fini()
}
