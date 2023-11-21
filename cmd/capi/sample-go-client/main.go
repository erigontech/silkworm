package main

func main() {
	var silkworm Silkworm

	LoadSilkworm(&silkworm, "libsilkworm_capi.dylib")

	silkworm.Init()
	//silkworm.AddSnapshot()
	silkworm.Fini()
}
