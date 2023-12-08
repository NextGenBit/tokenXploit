# tokenXploit

tokenXploit is a minimalist software tool developed using Go, specifically tailored for Windows platforms. This software extracts access tokens from process IDs (PIDs) on Windows systems, and uses CreateProcessAsUserW in the background to run a process with the access token.

It redirects the standard output of the spawned process back to the main program.

The software is designed to run with SYSTEM privileges
