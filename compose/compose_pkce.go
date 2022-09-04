// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/pkce"
)

// OAuth2PKCEFactory creates a PKCE handler.
func OAuth2PKCEFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &pkce.Handler{
		AuthorizeCodeStrategy: strategy.(oauth2.AuthorizeCodeStrategy),
		Storage:               storage.(pkce.PKCERequestStorage),
		Config:                config,
	}
}

func OAuth2DevicePKCEFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &pkce.HandlerDevice{
		CoreStorage:           storage.(oauth2.CoreStorage),
		DeviceCodeStrategy:    strategy.(oauth2.DeviceCodeStrategy),
		UserCodeStrategy:      strategy.(oauth2.UserCodeStrategy),
		AuthorizeCodeStrategy: strategy.(oauth2.AuthorizeCodeStrategy),
		Storage:               storage.(pkce.PKCERequestStorage),
		Config:                config,
	}
}
