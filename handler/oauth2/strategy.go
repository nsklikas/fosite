// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

	"github.com/ory/fosite"
)

type CoreStrategy interface {
	AccessTokenStrategy
	RefreshTokenStrategy
	AuthorizeCodeStrategy
	DeviceCodeStrategy
	UserCodeStrategy
}

type AccessTokenStrategy interface {
	AccessTokenSignature(ctx context.Context, token string) string
	GenerateAccessToken(ctx context.Context, requester fosite.Requester) (token string, signature string, err error)
	ValidateAccessToken(ctx context.Context, requester fosite.Requester, token string) (err error)
}

type RefreshTokenStrategy interface {
	RefreshTokenSignature(ctx context.Context, token string) string
	GenerateRefreshToken(ctx context.Context, requester fosite.Requester) (token string, signature string, err error)
	ValidateRefreshToken(ctx context.Context, requester fosite.Requester, token string) (err error)
}

type AuthorizeCodeStrategy interface {
	AuthorizeCodeSignature(ctx context.Context, token string) string
	GenerateAuthorizeCode(ctx context.Context, requester fosite.Requester) (token string, signature string, err error)
	ValidateAuthorizeCode(ctx context.Context, requester fosite.Requester, token string) (err error)
}

type DeviceCodeStrategy interface {
	DeviceCodeSignature(context context.Context, code string) string
	ValidateDeviceCode(context context.Context, r fosite.Requester, code string) (err error)
	GenerateDeviceCode() (code string, err error)
}

type UserCodeStrategy interface {
	UserCodeSignature(context context.Context, code string) string
	ValidateUserCode(context context.Context, r fosite.Requester, code string) (err error)
	GenerateUserCode() (code string, err error)
}
