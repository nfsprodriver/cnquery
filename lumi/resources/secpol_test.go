package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResource_Secpol(t *testing.T) {
	t.Run("list systemaccess", func(t *testing.T) {
		res := testQuery(t, "secpol.systemaccess")
		assert.NotEmpty(t, res)
	})

	t.Run("test a specific secpol systemaccess entry", func(t *testing.T) {
		res := testQuery(t, "secpol.systemaccess['PasswordHistorySize'] == 0")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, true, res[0].Data.Value)
	})

	t.Run("test a specific secpol systemaccess entry", func(t *testing.T) {
		res := testQuery(t, "secpol.privilegerights['SeNetworkLogonRight']")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, []interface{}{
			"S-1-1-0",
			"S-1-5-32-544",
			"S-1-5-32-545",
			"S-1-5-32-551",
		}, res[0].Data.Value)
	})

	t.Run("test a specific secpol systemaccess entry", func(t *testing.T) {
		res := testQuery(t, "secpol.privilegerights['SeNetworkLogonRight'] == ['S-1-1-0', 'S-1-5-32-544', 'S-1-5-32-545', 'S-1-5-32-551']")
		assert.NotEmpty(t, res)
		assert.Empty(t, res[0].Result().Error)
		assert.Equal(t, true, res[0].Data.Value)
	})
}
