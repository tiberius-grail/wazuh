# Wazuh Agent for NixOS

A NixOS flake for the Wazuh SIEM agent. Forked from [paulvictor/wazuh.nix](https://github.com/paulvictor/wazuh.nix) with enhancements.

## Features

- Pre-built with GCC 14 (avoids GCC 15 incompatible-pointer-types build errors)
- `agentName` option for custom agent naming (e.g., `username-hostname`)
- SSL certificate authentication support
- Automatic `/var/ossec` directory creation fix
- `WorkingDirectory` fix for agent-auth service
- Only re-registers agent when `client.keys` doesn't exist

## Usage

Add to your flake inputs:

```nix
{
  inputs = {
    wazuh = {
      url = "github:tiberius-grail/wazuh";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
}
```

Import the module and configure:

```nix
{ config, ... }:
{
  imports = [ inputs.wazuh.nixosModules.wazuh-agent ];

  # Add the overlay for the wazuh-agent package
  nixpkgs.overlays = [ inputs.wazuh.overlays.default ];

  services.wazuh-agent = {
    enable = true;
    managerIP = "192.168.1.100";
    managerPort = 1514;
    agentName = "myuser-myhost";  # Optional: defaults to hostname

    # Optional: SSL certificate authentication
    ssl = {
      enable = true;
      rootCA = /path/to/rootCA.pem;
      cert = /path/to/sslagent.cert;
      key = /path/to/sslagent.key;
    };

    # Standard wazuh config
    config = ''
      <ossec_config>
        <client>
          <server>
            <address>192.168.1.100</address>
            <port>1514</port>
            <protocol>tcp</protocol>
          </server>
        </client>
      </ossec_config>
    '';
  };
}
```

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable` | bool | `false` | Enable the Wazuh agent |
| `managerIP` | string | required | IP/hostname of the Wazuh manager |
| `managerPort` | int | `1514` | Manager port for agent traffic |
| `agentName` | string | `null` | Agent name (alphanumeric, hyphens, underscores only) |
| `ssl.enable` | bool | `false` | Enable SSL certificate authentication |
| `ssl.rootCA` | path | - | Path to root CA certificate |
| `ssl.cert` | path | - | Path to agent SSL certificate |
| `ssl.key` | path | - | Path to agent SSL private key |
| `config` | string | `null` | Complete ossec.conf configuration |
| `extraConfig` | string | `""` | Extra config appended to ossec.conf |

## Re-registering an Agent

To re-register with a new name or after manager changes:

```bash
sudo rm /var/ossec/etc/client.keys
sudo systemctl restart wazuh-agent-auth
```

## License

Same as upstream [wazuh/wazuh](https://github.com/wazuh/wazuh) - GPLv2.
