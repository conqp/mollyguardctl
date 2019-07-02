# mollyguardctl
A suite to mollyguard your server to prevent accidental shutdowns, reboots, suspends etc. and to auto-decrypt a potential LUKS root volume on boot. 

## Configuration
`mollyguardctl` is configured via `/etc/mollyguardctl.conf`.

### Section `MollyGuard`
* `units` A space-seperated list of systemd units to mask. Defaults to the default units (see below). 
* `hostname` Specifies whether to prompt for the host name. Defaults to: `true`.
* `systemctl` The systemctl binary to use. Defaults to `/usr/bin/systemctl`.
* `cryptsetup` The cryptsetup binary to use. Defaults to `/usr/bin/cryptsetup`.

### Section `LUKS`
The section `LUKS` is used to configure auto-decryption for the respective LUKS volume after reboot.

* `device` The LUKS device to auto-decrypt after reboot.
* `keyfile` The LUKS key file to populate with random bytes.
* `keysize` The size of the LUKS key file. Defaults to 2048.

You will need the kernel parameters `cryptdevice=` and `keyfile=` to be set accordingly for this to work.

### Units masked by default
If not configured otherwise the following units will be masked by mollyguardctl:

* `halt.target`
* `hibernate.target`
* `poweroff.target`
* `reboot.target`
* `shutdown.target`
* `suspend.target`
* `suspend-then-hibernate.target`

## Usage
Start and enable `mollyguard.service`. On systems with */* encrypted also start and enable `clear-luks-autodecrypt-key.service`.  
To reboot the system then, use `mollyguardctl reboot`.
