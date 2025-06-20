
package main

import (
	"fmt"
	"os"

	"recon-toolkit/cmd"
)

func main() {
	banner := `
██████╗ ████████╗██╗  ██╗    ███████╗██╗     ██╗████████╗███████╗
██╔══██╗╚══██╔══╝██║ ██╔╝    ██╔════╝██║     ██║╚══██╔══╝██╔════╝
██████╔╝   ██║   █████╔╝     █████╗  ██║     ██║   ██║   █████╗  
██╔══██╗   ██║   ██╔═██╗     ██╔══╝  ██║     ██║   ██║   ██╔══╝  
██║  ██║   ██║   ██║  ██╗    ███████╗███████╗██║   ██║   ███████╗
╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝    ╚══════╝╚══════╝╚═╝   ╚═╝   ╚══════╝

Professional Penetration Testing Framework v3.0
For authorized security assessments only
`
	
	fmt.Println(banner)
	
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}