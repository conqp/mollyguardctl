# mollyguardctl
A suite to mollyguard your server to prevent accidental shutdowns, reboots, suspends etc. and to auto-decrypt a potential LUKS root volume on boot. 

## Configuration
`mollyguardctl` is configured via `/etc/mollyguardctl.json`.  
The JSON-object expects the following key, all of which are optional:

* `units`: A list of systemd units to mask. Defaults to: `["halt.target", "hibernate.target", "poweroff.target", "reboot.target", "shutdown.target", "suspend.target", "suspend-then-hibernate.target"]`
* `systemctl`: The systemctl binary to use. Defaults to: `/usr/bin/systemctl`
* `cryptsetup`: The cryptsetup binary to use. Defaults to: `/usr/bin/cryptsetup`
* `luks`: A list of `["<device>", "<keyfile>", <keysize>]` or `["<device>", "<keyfile>"]` to configure auto-decryption for the respective LUKS volume. `keysize` defaults to 2048.

## Usage
Start and enable `mollyguard.service`. On systems with */* encrypted also start and enable `clear-luks-autodecrypt-key.service`.  
To reboot the system use `mollyguardctl reboot`.
