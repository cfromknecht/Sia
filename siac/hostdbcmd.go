package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/NebulousLabs/Sia/api"
	"github.com/NebulousLabs/Sia/types"
)

var (
	hostdbCmd = &cobra.Command{
		Use:   "hostdb",
		Short: "List active hosts on the network",
		Long:  "List active hosts on the network",
		Run:   wrap(hostdbhostscmd),
	}
)

func hostdbhostscmd() {
	info := new(api.ActiveHosts)
	err := getAPI("/renter/hosts/active", info)
	if err != nil {
		fmt.Println("Could not fetch host list:", err)
		return
	}
	if len(info.Hosts) == 0 {
		fmt.Println("No known active hosts")
		return
	}
	fmt.Println("Active hosts:")
	for _, host := range info.Hosts {
		fmt.Printf("\t%v - %v SC / GB / Mo\n", host.NetAddress, host.Price.Mul(types.NewCurrency64(4320e9)).Div(types.SiacoinPrecision))
	}
}
