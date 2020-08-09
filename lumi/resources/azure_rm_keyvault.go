package resources

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	keyvault_vault "github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/mgmt/keyvault"
	keyvault7 "github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
)

// see https://github.com/Azure/azure-sdk-for-go/issues/8224
// type AzureStorageAccountProperties keyvault_vault.KeyPermissions

func (a *lumiAzurermKeyvault) id() (string, error) {
	return "azure.keyvault", nil
}

func (a *lumiAzurermKeyvault) GetVaults() ([]interface{}, error) {
	at, err := azuretransport(a.Runtime.Motor.Transport)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	authorizer, err := at.Authorizer()
	if err != nil {
		return nil, err
	}

	client := keyvault_vault.NewVaultsClient(at.SubscriptionID())
	client.Authorizer = authorizer

	vaults, err := client.List(ctx, nil)
	if err != nil {
		return nil, err
	}

	res := []interface{}{}
	for i := range vaults.Values() {
		entry := vaults.Values()[i]

		lumiAzure, err := a.Runtime.CreateResource("azurerm.keyvault.vault",
			"id", toString(entry.ID),
			// TODO: temproray
			"vaultName", toString(entry.Name),
			"location", toString(entry.Location),
			"type", toString(entry.Type),
			"tags", azureTagsToInterface(entry.Tags),
		)
		if err != nil {
			return nil, err
		}
		res = append(res, lumiAzure)
	}

	return res, nil
}

func (a *lumiAzurermKeyvaultVault) id() (string, error) {
	return a.Id()
}

func (a *lumiAzurermKeyvaultVault) GetVaultUri() (string, error) {
	name, err := a.VaultName()
	if err != nil {
		return "", err
	}
	KVUri := "https://" + name + ".vault.azure.net"
	return KVUri, nil
}

const azureKeyVaulAudience = "https://vault.azure.net"

func (a *lumiAzurermKeyvaultVault) GetKeys() ([]interface{}, error) {
	at, err := azuretransport(a.Runtime.Motor.Transport)
	if err != nil {
		return nil, err
	}

	KVUri, err := a.GetVaultUri()
	if err != nil {
		return nil, err
	}

	authorizer, err := at.AuthorizerWithAudience(azureKeyVaulAudience)
	if err != nil {
		return nil, err
	}

	keyvaultkeyC := keyvault7.New()
	keyvaultkeyC.Authorizer = authorizer

	ctx := context.Background()
	keys, err := keyvaultkeyC.GetKeys(ctx, KVUri, nil)
	if err != nil {
		return nil, err
	}

	res := []interface{}{}
	for i := range keys.Values() {
		entry := keys.Values()[i]

		lumiAzure, err := a.Runtime.CreateResource("azurerm.keyvault.key",
			"kid", toString(entry.Kid),
			"managed", toBool(entry.Managed),
			"tags", azureTagsToInterface(entry.Tags),
			"enabled", toBool(entry.Attributes.Enabled),
			"notBefore", azureRmUnixTime(entry.Attributes.NotBefore),
			// TODO: handle case where we need to test for a time that is not set
			"expires", azureRmUnixTime(entry.Attributes.Expires),
			"created", azureRmUnixTime(entry.Attributes.Created),
			"updated", azureRmUnixTime(entry.Attributes.Updated),
			"recoveryLevel", string(entry.Attributes.RecoveryLevel),
		)
		if err != nil {
			return nil, err
		}
		res = append(res, lumiAzure)
	}

	return res, nil
}

func (a *lumiAzurermKeyvaultVault) GetCertificates() ([]interface{}, error) {
	at, err := azuretransport(a.Runtime.Motor.Transport)
	if err != nil {
		return nil, err
	}

	KVUri, err := a.GetVaultUri()
	if err != nil {
		return nil, err
	}

	authorizer, err := at.AuthorizerWithAudience(azureKeyVaulAudience)
	if err != nil {
		return nil, err
	}

	keyvaultkeyC := keyvault7.New()
	keyvaultkeyC.Authorizer = authorizer

	ctx := context.Background()
	certificates, err := keyvaultkeyC.GetCertificates(ctx, KVUri, nil, nil)
	if err != nil {
		return nil, err
	}

	res := []interface{}{}
	for i := range certificates.Values() {
		entry := certificates.Values()[i]

		// attributes, err := jsonToDict(entry.Attributes)
		// if err != nil {
		// 	return nil, err
		// }

		lumiAzure, err := a.Runtime.CreateResource("azurerm.keyvault.certificate",
			"id", toString(entry.ID),
			"tags", azureTagsToInterface(entry.Tags),
			// "attributes", attributes,
			"x5t", toString(entry.X509Thumbprint),
			"enabled", toBool(entry.Attributes.Enabled),
			"notBefore", azureRmUnixTime(entry.Attributes.NotBefore),
			"expires", azureRmUnixTime(entry.Attributes.Expires),
			"created", azureRmUnixTime(entry.Attributes.Created),
			"updated", azureRmUnixTime(entry.Attributes.Updated),
			"recoveryLevel", string(entry.Attributes.RecoveryLevel),
		)
		if err != nil {
			return nil, err
		}
		res = append(res, lumiAzure)
	}

	return res, nil
}

func (a *lumiAzurermKeyvaultVault) GetSecrets() ([]interface{}, error) {
	at, err := azuretransport(a.Runtime.Motor.Transport)
	if err != nil {
		return nil, err
	}

	KVUri, err := a.GetVaultUri()
	if err != nil {
		return nil, err
	}

	authorizer, err := at.AuthorizerWithAudience(azureKeyVaulAudience)
	if err != nil {
		return nil, err
	}

	keyvaultkeyC := keyvault7.New()
	keyvaultkeyC.Authorizer = authorizer

	ctx := context.Background()
	secrets, err := keyvaultkeyC.GetSecrets(ctx, KVUri, nil)
	if err != nil {
		return nil, err
	}

	res := []interface{}{}
	for i := range secrets.Values() {
		entry := secrets.Values()[i]

		lumiAzure, err := a.Runtime.CreateResource("azurerm.keyvault.secret",
			"id", toString(entry.ID),
			"tags", azureTagsToInterface(entry.Tags),
			"contentType", toString(entry.ContentType),
			"managed", toBool(entry.Managed),
			"enabled", toBool(entry.Attributes.Enabled),
			"notBefore", azureRmUnixTime(entry.Attributes.NotBefore),
			"expires", azureRmUnixTime(entry.Attributes.Expires),
			"created", azureRmUnixTime(entry.Attributes.Created),
			"updated", azureRmUnixTime(entry.Attributes.Updated),
		)
		if err != nil {
			return nil, err
		}
		res = append(res, lumiAzure)
	}

	return res, nil
}

func (a *lumiAzurermKeyvaultVault) GetProperties() (map[string]interface{}, error) {

	at, err := azuretransport(a.Runtime.Motor.Transport)
	if err != nil {
		return nil, err
	}

	// id is a azure resource od
	id, err := a.Id()
	if err != nil {
		return nil, err
	}

	resourceID, err := at.ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	vaultName, err := resourceID.Component("vaults")
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	authorizer, err := at.Authorizer()
	if err != nil {
		return nil, err
	}

	client := keyvault_vault.NewVaultsClient(at.SubscriptionID())
	client.Authorizer = authorizer

	vault, err := client.Get(ctx, resourceID.ResourceGroup, vaultName)
	if err != nil {
		return nil, err
	}

	return jsonToDict(vault.Properties)
}

func (a *lumiAzurermKeyvaultVault) GetDiagnosticSettings() ([]interface{}, error) {
	// id is a azure resource od
	id, err := a.Id()
	if err != nil {
		return nil, err
	}

	// NOTE diagnostics are fetched in the init of azurerm.monitor.diagnosticsettings
	return diagnosticsSettings(a.Runtime, id)
}

func (a *lumiAzurermKeyvaultKey) id() (string, error) {
	return a.Kid()
}

func (a *lumiAzurermKeyvaultKey) GetKeyName() (interface{}, error) {
	// parse id "https://superdupervault.vault.azure.net/keys/sqltestkey"
	id, err := a.Kid()
	if err != nil {
		return nil, err
	}

	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return nil, err
	}

	return kvid.Name, nil
}

func (a *lumiAzurermKeyvaultKey) GetVersion() (interface{}, error) {
	id, err := a.Kid()
	if err != nil {
		return nil, err
	}

	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return nil, err
	}

	return kvid.Version, nil
}

func (a *lumiAzurermKeyvaultKey) GetVersions() ([]interface{}, error) {
	at, err := azuretransport(a.Runtime.Motor.Transport)
	if err != nil {
		return nil, err
	}

	id, err := a.Kid()
	if err != nil {
		return nil, err
	}

	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return nil, err
	}

	if len(kvid.Version) > 0 {
		return nil, errors.New("versions is not supported for azure key version")
	}

	if kvid.Type != "keys" {
		return nil, errors.New("only keys ids are supported")
	}

	vaultUrl := kvid.BaseUrl
	name := kvid.Name

	authorizer, err := at.AuthorizerWithAudience(azureKeyVaulAudience)
	if err != nil {
		return nil, err
	}

	keyvaultkeyC := keyvault7.New()
	keyvaultkeyC.Authorizer = authorizer

	ctx := context.Background()
	// WARN: although maxResults is marked optional, the http call never returns if not provided????
	maxResults := int32(25)
	secrets, err := keyvaultkeyC.GetKeyVersions(ctx, vaultUrl, name, &maxResults)
	if err != nil {
		return nil, err
	}

	res := []interface{}{}
	for i := range secrets.Values() {
		entry := secrets.Values()[i]

		lumiAzure, err := a.Runtime.CreateResource("azurerm.keyvault.key",
			"kid", toString(entry.Kid),
			"tags", azureTagsToInterface(entry.Tags),
			"managed", toBool(entry.Managed),

			"enabled", toBool(entry.Attributes.Enabled),
			"notBefore", azureRmUnixTime(entry.Attributes.NotBefore),
			"expires", azureRmUnixTime(entry.Attributes.Expires),
			"created", azureRmUnixTime(entry.Attributes.Created),
			"updated", azureRmUnixTime(entry.Attributes.Updated),
			"recoveryLevel", string(entry.Attributes.RecoveryLevel),
		)
		if err != nil {
			return nil, err
		}
		res = append(res, lumiAzure)
	}

	return res, nil
}

func (a *lumiAzurermKeyvaultCertificate) id() (string, error) {
	return a.Id()
}

// TODO: switch to name once the issue is solved in lumi
func (a *lumiAzurermKeyvaultCertificate) GetCertName() (interface{}, error) {
	// parse id "https://superdupervault.vault.azure.net/certificates/testcertificate"
	id, err := a.Id()
	if err != nil {
		return nil, err
	}

	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return nil, err
	}

	return kvid.Name, nil
}

func (a *lumiAzurermKeyvaultCertificate) GetVersion() (interface{}, error) {
	id, err := a.Id()
	if err != nil {
		return nil, err
	}

	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return nil, err
	}

	return kvid.Version, nil
}

func (a *lumiAzurermKeyvaultCertificate) GetX509() (interface{}, error) {
	return nil, errors.New("not implemented")
}

var keyvaultidRegex = regexp.MustCompile(`^(https:\/\/([^\/]*)\.vault\.azure\.net)\/(certificates|secrets|keys)\/([^\/]*)(?:\/([^\/]*)){0,1}$`)

type keyvaultid struct {
	BaseUrl string
	Vault   string
	Type    string
	Name    string
	Version string
}

func parseKeyVaultId(url string) (*keyvaultid, error) {
	m := keyvaultidRegex.FindStringSubmatch(url)

	if len(m) != 6 {
		return nil, fmt.Errorf("cannot parse azure keyvault id: %s", url)
	}

	return &keyvaultid{
		BaseUrl: m[1],
		Vault:   m[2],
		Type:    m[3],
		Name:    m[4],
		Version: m[5],
	}, nil
}

func (a *lumiAzurermKeyvaultCertificate) GetVersions() ([]interface{}, error) {
	at, err := azuretransport(a.Runtime.Motor.Transport)
	if err != nil {
		return nil, err
	}

	id, err := a.Id()
	if err != nil {
		return nil, err
	}

	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return nil, err
	}

	if len(kvid.Version) > 0 {
		return nil, errors.New("versions is not supported for azure certificate version")
	}

	if kvid.Type != "certificates" {
		return nil, errors.New("only certificate ids are supported")
	}

	vaultUrl := kvid.BaseUrl
	name := kvid.Name

	authorizer, err := at.AuthorizerWithAudience(azureKeyVaulAudience)
	if err != nil {
		return nil, err
	}

	keyvaultkeyC := keyvault7.New()
	keyvaultkeyC.Authorizer = authorizer

	ctx := context.Background()
	// WARN: although maxResults is marked optional, the http call never returns if not provided????
	maxResults := int32(25)
	certificates, err := keyvaultkeyC.GetCertificateVersions(ctx, vaultUrl, name, &maxResults)
	if err != nil {
		return nil, err
	}

	res := []interface{}{}
	for i := range certificates.Values() {
		entry := certificates.Values()[i]

		lumiAzure, err := a.Runtime.CreateResource("azurerm.keyvault.certificate",
			"id", toString(entry.ID),
			"tags", azureTagsToInterface(entry.Tags),
			"x5t", toString(entry.X509Thumbprint),
			"enabled", toBool(entry.Attributes.Enabled),
			"notBefore", azureRmUnixTime(entry.Attributes.NotBefore),
			"expires", azureRmUnixTime(entry.Attributes.Expires),
			"created", azureRmUnixTime(entry.Attributes.Created),
			"updated", azureRmUnixTime(entry.Attributes.Updated),
			"recoveryLevel", string(entry.Attributes.RecoveryLevel),
		)
		if err != nil {
			return nil, err
		}
		res = append(res, lumiAzure)
	}

	return res, nil
}

func (a *lumiAzurermKeyvaultSecret) id() (string, error) {
	return a.Id()
}

// TODO: switch to name once the issue is solved in lumi
func (a *lumiAzurermKeyvaultSecret) GetSecretName() (interface{}, error) {
	// parse id "https://superdupervault.vault.azure.net/certificates/testcertificate"
	id, err := a.Id()
	if err != nil {
		return nil, err
	}

	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return nil, err
	}

	return kvid.Name, nil
}

func (a *lumiAzurermKeyvaultSecret) GetVersion() (interface{}, error) {
	id, err := a.Id()
	if err != nil {
		return nil, err
	}

	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return nil, err
	}

	return kvid.Version, nil
}

func (a *lumiAzurermKeyvaultSecret) GetVersions() ([]interface{}, error) {
	at, err := azuretransport(a.Runtime.Motor.Transport)
	if err != nil {
		return nil, err
	}

	id, err := a.Id()
	if err != nil {
		return nil, err
	}

	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return nil, err
	}

	if len(kvid.Version) > 0 {
		return nil, errors.New("versions is not supported for azure secret version")
	}

	if kvid.Type != "secrets" {
		return nil, errors.New("only secret ids are supported")
	}

	vaultUrl := kvid.BaseUrl
	name := kvid.Name

	authorizer, err := at.AuthorizerWithAudience(azureKeyVaulAudience)
	if err != nil {
		return nil, err
	}

	keyvaultkeyC := keyvault7.New()
	keyvaultkeyC.Authorizer = authorizer

	ctx := context.Background()
	// WARN: although maxResults is marked optional, the http call never returns if not provided????
	maxResults := int32(25)
	secrets, err := keyvaultkeyC.GetSecretVersions(ctx, vaultUrl, name, &maxResults)
	if err != nil {
		return nil, err
	}

	res := []interface{}{}
	for i := range secrets.Values() {
		entry := secrets.Values()[i]

		lumiAzure, err := a.Runtime.CreateResource("azurerm.keyvault.secret",
			"id", toString(entry.ID),
			"tags", azureTagsToInterface(entry.Tags),
			"contentType", toString(entry.ContentType),
			"managed", toBool(entry.Managed),

			"enabled", toBool(entry.Attributes.Enabled),
			"notBefore", azureRmUnixTime(entry.Attributes.NotBefore),
			"expires", azureRmUnixTime(entry.Attributes.Expires),
			"created", azureRmUnixTime(entry.Attributes.Created),
			"updated", azureRmUnixTime(entry.Attributes.Updated),
			"recoveryLevel", string(entry.Attributes.RecoveryLevel),
		)
		if err != nil {
			return nil, err
		}
		res = append(res, lumiAzure)
	}

	return res, nil
}
