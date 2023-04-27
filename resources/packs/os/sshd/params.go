package sshd

import (
	"strings"

	"go.mondoo.com/cnquery/llx"
	"go.mondoo.com/cnquery/resources/packs/core"
)

type ContextInfo struct {
	File  core.File
	Range llx.RangeData
}

type RangeContext struct {
	Ranges []ContextInfo
	Files  map[string]core.File
}

func (r RangeContext) AddRange(other RangeContext) {
	for i := range other.Files {
		f := other.Files[i]
		id := f.MqlResource().Id
		if _, ok := r.Files[id]; !ok {
			r.Files[id] = f
		}
	}

	// The offset is the tail end of the current ranges.
	// All ranges are always added as 1 line-range (start to end line)
	// per range in order. So we can simply go to the last range and
	// grab the second line (the end of the range).
	var offset int
	if len(r.Ranges) != 0 {
		last := r.Ranges[len(r.Ranges)-1]
		lines, _ := last.Range.ExtractNext()
		offset = int(lines[1])
	}

	for i := range other.Ranges {
		cur := other.Ranges[i]
		next := ContextInfo{
			File:  cur.File,
			Range: cur.Range.Offset(offset),
		}
		r.Ranges = append(r.Ranges, next)
	}
}

func (r RangeContext) OfLine(line uint32) *ContextInfo {
	for i := range r.Ranges {
		cur := r.Ranges[i]
		if cur.Range.ContainsLine(line) {
			return &cur
		}
	}

	return nil
}

func Params(content string, contentCtx RangeContext) (map[string]string, map[string]ContextInfo, error) {
	params := map[string]string{}
	ctx := map[string]ContextInfo{}

	lines := strings.Split(content, "\n")
	for lineIdx, textLine := range lines {
		l, err := ParseLine([]rune(textLine))
		if err != nil {
			return nil, nil, err
		}

		k := l.key
		if k == "" {
			continue
		}

		// handle lower case entries and use proper ssh camel case
		if sshKey, ok := SSH_Keywords[strings.ToLower(k)]; ok {
			k = sshKey
		}

		// check if we have an entry already
		if val, ok := params[k]; ok {
			params[k] = val + "," + l.args
		} else {
			params[k] = l.args
		}
		if fileCtx := contentCtx.OfLine(uint32(lineIdx)); fileCtx != nil {
			ctx[k] = ContextInfo{
				File: fileCtx.File,
				// FIXME: adjust this with the offset of the content in the file
				Range: llx.NewRange().AddLine(uint32(lineIdx)),
			}
		}
	}

	return params, ctx, nil
}

var SSH_Keywords = map[string]string{
	"acceptenv":                       "AcceptEnv",
	"addressfamily":                   "AddressFamily",
	"allowagentforwarding":            "AllowAgentForwarding",
	"allowgroups":                     "AllowGroups",
	"allowstreamlocalforwarding":      "AllowStreamLocalForwarding",
	"allowtcpforwarding":              "AllowTcpForwarding",
	"allowusers":                      "AllowUsers",
	"authenticationmethods":           "AuthenticationMethods",
	"authorizedkeyscommand":           "AuthorizedKeysCommand",
	"authorizedkeyscommanduser":       "AuthorizedKeysCommandUser",
	"authorizedkeysfile":              "AuthorizedKeysFile",
	"authorizedprincipalscommand":     "AuthorizedPrincipalsCommand",
	"authorizedprincipalscommanduser": "AuthorizedPrincipalsCommandUser",
	"authorizedprincipalsfile":        "AuthorizedPrincipalsFile",
	"banner":                          "Banner",
	"casignaturealgorithms":           "CASignatureAlgorithms",
	"challengeresponseauthentication": "ChallengeResponseAuthentication",
	"chrootdirectory":                 "ChrootDirectory",
	"ciphers":                         "Ciphers",
	"clientalivecountmax":             "ClientAliveCountMax",
	"clientaliveinterval":             "ClientAliveInterval",
	"compression":                     "Compression",
	"denygroups":                      "DenyGroups",
	"denyusers":                       "DenyUsers",
	"disableforwarding":               "DisableForwarding",
	"exposeauthinfo":                  "ExposeAuthInfo",
	"fingerprinthash":                 "FingerprintHash",
	"forcecommand":                    "ForceCommand",
	"gssapiauthentication":            "GSSAPIAuthentication",
	"gssapicleanupcredentials":        "GSSAPICleanupCredentials",
	"gssapistrictacceptorcheck":       "GSSAPIStrictAcceptorCheck",
	"gatewayports":                    "GatewayPorts",
	"hostcertificate":                 "HostCertificate",
	"hostkey":                         "HostKey",
	"hostkeyagent":                    "HostKeyAgent",
	"hostkeyalgorithms":               "HostKeyAlgorithms",
	"hostbasedacceptedkeytypes":       "HostbasedAcceptedKeyTypes",
	"hostbasedauthentication":         "HostbasedAuthentication",
	"hostbasedusesnamefrompacketonly": "HostbasedUsesNameFromPacketOnly",
	"ipqos":                           "IPQoS",
	"ignorerhosts":                    "IgnoreRhosts",
	"ignoreuserknownhosts":            "IgnoreUserKnownHosts",
	"include":                         "Include",
	"kbdinteractiveauthentication":    "KbdInteractiveAuthentication",
	"kerberosauthentication":          "KerberosAuthentication",
	"kerberosgetafstoken":             "KerberosGetAFSToken",
	"kerberosorlocalpasswd":           "KerberosOrLocalPasswd",
	"kerberosticketcleanup":           "KerberosTicketCleanup",
	"kexalgorithms":                   "KexAlgorithms",
	"listenaddress":                   "ListenAddress",
	"loglevel":                        "LogLevel",
	"logingracetime":                  "LoginGraceTime",
	"macs":                            "MACs",
	"match":                           "Match",
	"maxauthtries":                    "MaxAuthTries",
	"maxsessions":                     "MaxSessions",
	"maxstartups":                     "MaxStartups",
	"passwordauthentication":          "PasswordAuthentication",
	"permitemptypasswords":            "PermitEmptyPasswords",
	"permitlisten":                    "PermitListen",
	"permitopen":                      "PermitOpen",
	"permitrootlogin":                 "PermitRootLogin",
	"permittty":                       "PermitTTY",
	"permittunnel":                    "PermitTunnel",
	"permituserenvironment":           "PermitUserEnvironment",
	"permituserrc":                    "PermitUserRC",
	"pidfile":                         "PidFile",
	"port":                            "Port",
	"printlastlog":                    "PrintLastLog",
	"printmotd":                       "PrintMotd",
	"pubkeyacceptedkeytypes":          "PubkeyAcceptedKeyTypes",
	"pubkeyauthoptions":               "PubkeyAuthOptions",
	"pubkeyauthentication":            "PubkeyAuthentication",
	"rdomain":                         "RDomain",
	"rekeylimit":                      "RekeyLimit",
	"revokedkeys":                     "RevokedKeys",
	"securitykeyprovider":             "SecurityKeyProvider",
	"setenv":                          "SetEnv",
	"streamlocalbindmask":             "StreamLocalBindMask",
	"streamlocalbindunlink":           "StreamLocalBindUnlink",
	"strictmodes":                     "StrictModes",
	"subsystem":                       "Subsystem",
	"syslogfacility":                  "SyslogFacility",
	"tcpkeepalive":                    "TCPKeepAlive",
	"trustedusercakeys":               "TrustedUserCAKeys",
	"usedns":                          "UseDNS",
	"usepam":                          "UsePAM",
	"versionaddendum":                 "VersionAddendum",
	"x11displayoffset":                "X11DisplayOffset",
	"x11forwarding":                   "X11Forwarding",
	"x11uselocalhost":                 "X11UseLocalhost",
	"xauthlocation":                   "XAuthLocation",
}
