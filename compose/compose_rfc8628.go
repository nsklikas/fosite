// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/rfc8628"
)

// RFC8628DeviceFactory creates an OAuth2 device code grant ("Device Authorization Grant") handler and registers
// an user code, device code, access token and a refresh token validator.
func RFC8628DeviceFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &rfc8628.DeviceAuthHandler{
		Strategy: strategy.(rfc8628.RFC8628CodeStrategy),
		Storage:  storage.(rfc8628.RFC8628CoreStorage),
		Config:   config,
	}
}

// RFC8628DeviceAuthorizationTokenFactory creates an OAuth2 device authorization grant ("Device Authorization Grant") handler and registers
// an access token, refresh token and authorize code validator.
func RFC8628DeviceAuthorizationTokenFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &rfc8628.DeviceTokenEndpointHandler{
		DeviceRateLimitStrategy: strategy.(rfc8628.DeviceRateLimitStrategy),
		DeviceStorage:           strategy.(rfc8628.DeviceCodeStorage),
		DeviceStrategy:          strategy.(rfc8628.RFC8628CodeStrategy),
		AccessTokenStrategy:     strategy.(oauth2.AccessTokenStrategy),
		RefreshTokenStrategy:    strategy.(oauth2.RefreshTokenStrategy),
		CoreStorage:             storage.(rfc8628.RFC8628CoreStorage),
		TokenRevocationStorage:  storage.(oauth2.TokenRevocationStorage),
		Config:                  config,
	}
}
