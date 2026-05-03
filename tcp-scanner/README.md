# Tcp-scanner

Here's my implementation of a tcp-scanner i used **rust** as the language as well as _tokio_ and _clap_ for the application

##How does it work

It's a pretty simple application it parses ports you want it to check and then checks whether it can connect to them as in TCP SYN connect, if it can the port will be flagged as open,

It relies on timeout of 5 seconds for the response from the target machine service on any given port.
If your scan consists of _21,22,80,443_ ports it will try to fetch the banner
##Parsing
The application contains great parsing system so you can put single numbers (ex. 80 ) list of numbers (23,24,25) and ranges (100-1200) all in one command.
`tcp-scanner -p 20,23,24,30-35,21,22` will scan ports 20,21,22,23,24,30,31,32,33,34,35
It is capable of 256 concurrect connections thanks to threading and semaphore

##Ping scan
It also contains ping scan _-i or --isup_ to check whether target host is up

##Output options
Tcp-scanner can retrieve and respond in normal plaintext (no options needed) and in json (`-j or --json`)

##Why no stealth scan

Stealth scan is easily detected by modern ids and ips so implementation of it consisting of race condition with kernel and forcing user to run it with sudo is in my opinion worthless, and would take to much time for little effort

##Installation

`git clone --no-checkout --sparse --filter=blob:none https://github.com/Lukidere/security-toolkit.git
cd security-toolkit
git sparse-checkout set tcp-scanner
git checkout
cd tcp-scanner
chmod +x install.sh
./install.sh
`
