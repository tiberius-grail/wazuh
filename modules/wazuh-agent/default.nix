{
  config,
  lib,
  pkgs,
  ...
}:
with lib;
let
  wazuhUser = "wazuh";
  wazuhGroup = wazuhUser;
  stateDir = "/var/ossec";
  cfg = config.services.wazuh-agent;
  pkg = config.services.wazuh-agent.package;
  agentAuthPassword = config.services.wazuh-agent.agentAuthPassword;

  generatedConfig =
    if !(builtins.isNull cfg.config)
    then cfg.config
    else import ./generate-agent-config.nix {
      cfg = config.services.wazuh-agent;
      inherit pkgs;
    };

  preStart = ''
    ${concatMapStringsSep "\n"
      (dir:
        "[ -d ${stateDir}/${dir} ] || cp -Rv --no-preserve=ownership ${pkg}/${dir} ${stateDir}/${dir}")
        [ "queue" "var" "wodles" "logs" "lib" "tmp" "agentless" "active-response" "etc" ]
     }

    chown -R ${wazuhUser}:${wazuhGroup} ${stateDir}

    find ${stateDir} -type d -exec chmod 770 {} \;
    find ${stateDir} -type f -exec chmod 750 {} \;

    # Generate and copy ossec.config
    cp ${pkgs.writeText "ossec.conf" generatedConfig} ${stateDir}/etc/ossec.conf

    ${lib.optionalString
      (!(isNull agentAuthPassword))
      "echo ${agentAuthPassword} >> ${stateDir}/etc/authd.pass"}

  '';

  daemons =
    ["wazuh-modulesd" "wazuh-logcollector" "wazuh-syscheckd" "wazuh-agentd" "wazuh-execd"];

  mkService = d:
    {
      description = "${d}";
      wants = ["wazuh-agent-auth.service"];

      partOf = [ "wazuh.target" ];
      path = cfg.path ++ [ "/run/current-system/sw/bin" "/run/wrappers/bin" ];
      environment = {
        WAZUH_HOME = stateDir;
      };

      serviceConfig = {
        Type = "exec";
        User = wazuhUser;
        Group = wazuhGroup;
        WorkingDirectory = "${stateDir}/";
        CapabilityBoundingSet = [ "CAP_SETGID" ];

        ExecStart =
          if (d != "wazuh-modulesd")
          then "/run/wrappers/bin/${d} -f -c ${stateDir}/etc/ossec.conf"
          else "/run/wrappers/bin/${d} -f";
      };
    };

  # Build agent-auth command with optional args
  agentAuthCmd = let
    baseCmd = "${pkg}/bin/agent-auth -m ${cfg.managerIP}";
    nameArg = optionalString (cfg.agentName != null) " -A ${cfg.agentName}";
    sslArgs = optionalString cfg.ssl.enable
      " -v ${stateDir}/etc/rootCA.pem -x ${stateDir}/etc/sslagent.cert -k ${stateDir}/etc/sslagent.key";
  in baseCmd + nameArg + sslArgs;

in {
  options = {
    services.wazuh-agent = {
      enable = lib.mkEnableOption "Wazuh agent";

      managerIP = lib.mkOption {
        type = lib.types.nonEmptyStr;
        description = ''
          The IP address or hostname of the manager.
        '';
        example = "192.168.1.2";
      };

      managerPort = lib.mkOption {
        type = lib.types.port;
        description = ''
          The port the manager is listening on to receive agent traffic.
        '';
        example = 1514;
        default = 1514;
      };

      agentName = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "myuser-myhost";
        description = ''
          The agent name to register with the Wazuh manager.
          If null, defaults to the system hostname.
          Only alphanumeric characters, hyphens, and underscores are allowed.
        '';
      };

      ssl = {
        enable = lib.mkEnableOption "SSL certificate authentication for agent registration";

        rootCA = lib.mkOption {
          type = lib.types.str;
          description = "Path to the root CA certificate for verifying the manager";
          example = "/path/to/rootCA.pem";
        };

        cert = lib.mkOption {
          type = lib.types.str;
          description = "Path to the agent SSL certificate";
          example = "/path/to/sslagent.cert";
        };

        key = lib.mkOption {
          type = lib.types.str;
          description = "Path to the agent SSL private key";
          example = "/path/to/sslagent.key";
        };
      };

      package = lib.mkPackageOption pkgs "wazuh-agent" {};

      path = lib.mkOption {
        type = lib.types.listOf lib.types.path;
        default = [];
        example = lib.literalExpression "[ pkgs.util-linux pkgs.coreutils_full pkgs.nettools ]";
        description = "List of derivations to put in wazuh-agent's path.";
      };

      config = lib.mkOption {
        type = lib.types.nullOr lib.types.nonEmptyStr;
        default = null;
        description = ''
          Complete configuration for ossec.conf
        '';
      };

      agentAuthPassword = lib.mkOption {
        type = lib.types.nullOr lib.types.nonEmptyStr;
        default = null;
        description = ''
          Password for the auth service
        '';
      };

      extraConfig = lib.mkOption {
        type = lib.types.lines;
        description = ''
          Extra configuration values to be appended to the bottom of ossec.conf.
        '';
        default = "";
        example = ''
          <!-- The added ossec_config root tag is required -->
          <ossec_config>
            <!-- Extra configuration options as needed -->
          </ossec_config>
        '';
      };
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion =
          with cfg; (config == null) -> (extraConfig != null);
        message = "extraConfig cannot be set when config is set";
      }
      {
        assertion =
          !cfg.ssl.enable || (cfg.ssl.rootCA != null && cfg.ssl.cert != null && cfg.ssl.key != null);
        message = "ssl.rootCA, ssl.cert, and ssl.key must all be set when ssl.enable is true";
      }
    ];
    users.users.${wazuhUser} = {
      isSystemUser = true;
      group = wazuhGroup;
      description = "Wazuh agent user";
      home = stateDir;
      extraGroups = ["systemd-journal" "systemd-network"]; # To read journal entries
    };

    users.groups.${wazuhGroup} = {};

    systemd.tmpfiles.rules = [
      "d ${stateDir} 0750 ${wazuhUser} ${wazuhGroup} -"
      "d ${stateDir}/tmp 0750 ${wazuhUser} ${wazuhGroup} 1d"
    ];

    systemd.targets.multi-user.wants = [ "wazuh.target" ];
    systemd.targets.wazuh.wants = forEach daemons (d: "${d}.service" );

    systemd.services =
      listToAttrs
        (map
          (daemon: nameValuePair daemon (mkService daemon))
          daemons) //
      {
        wazuh-agent-auth = {
          description = "Sets up wazuh agent auth";
          after = [ "setup-pre-wazuh.service" "network.target" "network-online.target" ]
            ++ optional cfg.ssl.enable "wazuh-certs-setup.service";
          wants = [ "setup-pre-wazuh.service" "network-online.target" ]
            ++ optional cfg.ssl.enable "wazuh-certs-setup.service";
          before = map (d: "${d}.service") daemons;
          environment = {
            WAZUH_HOME = stateDir;
          };

          unitConfig = {
            # Only run if not already registered
            ConditionPathExists = "!${stateDir}/etc/client.keys";
          };

          serviceConfig = {
            Type = "oneshot";
            User = wazuhUser;
            Group = wazuhGroup;
            WorkingDirectory = stateDir;
            ExecStart = agentAuthCmd;
          };
        };

        setup-pre-wazuh = {
          description = "Sets up wazuh's directory structure";
          wantedBy = ["wazuh-agent-auth.service"];
          before = ["wazuh-agent-auth.service"];
          serviceConfig = {
            Type = "oneshot";
            User = wazuhUser;
            Group = wazuhGroup;
            ExecStart =
              let
                script = pkgs.writeShellApplication { name = "wazuh-prestart"; text = preStart; };
              in "${script}/bin/wazuh-prestart";
            ExecStartPre = let
              # Create base directory with root permissions
              createDir = pkgs.writeShellScript "create-ossec-dir" ''
                mkdir -p ${stateDir}
                chown ${wazuhUser}:${wazuhGroup} ${stateDir}
              '';
            in "+${createDir}";
          };
        };

        # SSL certificate setup service
        wazuh-certs-setup = mkIf cfg.ssl.enable {
          description = "Setup Wazuh SSL certificates";
          wantedBy = [ "multi-user.target" ];
          wants = [ "setup-pre-wazuh.service" ];
          after = [ "setup-pre-wazuh.service" ];
          before = [ "wazuh-agent-auth.service" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = pkgs.writeShellScript "wazuh-certs-setup" ''
              # Wait for /var/ossec/etc to exist
              while [ ! -d ${stateDir}/etc ]; do sleep 1; done
              cp ${cfg.ssl.rootCA} ${stateDir}/etc/rootCA.pem
              cp ${cfg.ssl.cert} ${stateDir}/etc/sslagent.cert
              cp ${cfg.ssl.key} ${stateDir}/etc/sslagent.key
              chmod 640 ${stateDir}/etc/rootCA.pem ${stateDir}/etc/sslagent.cert ${stateDir}/etc/sslagent.key
              chown ${wazuhUser}:${wazuhGroup} ${stateDir}/etc/rootCA.pem ${stateDir}/etc/sslagent.cert ${stateDir}/etc/sslagent.key
            '';
          };
        };
      };

    security.wrappers =
      listToAttrs
        (forEach daemons
          (d:
            nameValuePair
              d
              {
                setgid = true;
                setuid = true;
                owner = wazuhUser;
                group = wazuhGroup;
                source = "${pkg}/bin/${d}";
              }
          )
        );
  };
}
