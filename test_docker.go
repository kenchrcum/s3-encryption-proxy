package main; import ("os/exec"; "fmt"); func main() { cmd := exec.Command("docker", "version"); err := cmd.Run(); fmt.Println("Docker available:", err == nil) }
