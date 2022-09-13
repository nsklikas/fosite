// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

	"github.com/ory/fosite"
)

type CoreStorage interface {
	AuthorizeCodeStorage
	AccessTokenStorage
	RefreshTokenStorage
	DeviceCodeStorage
	UserCodeStorage
}

// AuthorizeCodeStorage handles storage requests related to authorization codes.
type AuthorizeCodeStorage interface {
	// GetAuthorizeCodeSession stores the authorization request for a given authorization code.
	CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) (err error)

	// GetAuthorizeCodeSession hydrates the session based on the given code and returns the authorization request.
	// If the authorization code has been invalidated with `InvalidateAuthorizeCodeSession`, this
	// method should return the ErrInvalidatedAuthorizeCode error.
	//
	// Make sure to also return the fosite.Requester value when returning the fosite.ErrInvalidatedAuthorizeCode error!
	GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (request fosite.Requester, err error)

	// InvalidateAuthorizeCodeSession is called when an authorize code is being used. The state of the authorization
	// code should be set to invalid and consecutive requests to GetAuthorizeCodeSession should return the
	// ErrInvalidatedAuthorizeCode error.
	InvalidateAuthorizeCodeSession(ctx context.Context, code string) (err error)
}

type AccessTokenStorage interface {
	CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) (err error)

	GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error)

	DeleteAccessTokenSession(ctx context.Context, signature string) (err error)
}

type RefreshTokenStorage interface {
	CreateRefreshTokenSession(ctx context.Context, signature string, request fosite.Requester) (err error)

	GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error)

	DeleteRefreshTokenSession(ctx context.Context, signature string) (err error)
}

type DeviceCodeStorage interface {
	// CreateDeviceCodeSession stores the device request for a given device code.
	CreateDeviceCodeSession(ctx context.Context, signature string, request fosite.Requester) (err error)

	// UpdateDeviceCodeSessionByRequestId udpate in store the device request for a given device code.
	UpdateDeviceCodeSessionByRequestId(ctx context.Context, id string, request fosite.Requester) (err error)

	// GetDeviceCodeSession hydrates the session based on the given device code and returns the device request.
	// If the device code has been invalidated with `InvalidateDeviceCodeSession`, this
	// method should return the ErrInvalidatedDeviceCode error.
	//
	// Make sure to also return the fosite.Requester value when returning the fosite.ErrInvalidatedDeviceCode error!
	GetDeviceCodeSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error)

	// InvalidateDeviceCodeSession is called when an device code is being used. The state of the user
	// code should be set to invalid and consecutive requests to GetDeviceCodeSession should return the
	// ErrInvalidatedDeviceCode error.
	InvalidateDeviceCodeSession(ctx context.Context, signature string) (err error)
}

type UserCodeStorage interface {
	// CreateUserCodeSession stores the device request for a given user code.
	CreateUserCodeSession(ctx context.Context, signature string, request fosite.Requester) (err error)

	// GetUserCodeSession hydrates the session based on the given user code and returns the device request.
	// If the user code has been invalidated with `InvalidateUserCodeSession`, this
	// method should return the ErrInvalidatedUserCode error.
	//
	// Make sure to also return the fosite.Requester value when returning the fosite.ErrInvalidatedUserCode error!
	GetUserCodeSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error)

	// InvalidateUserCodeSession is called when an user code is being used. The state of the user
	// code should be set to invalid and consecutive requests to GetUserCodeSession should return the
	// ErrInvalidatedUserCode error.
	InvalidateUserCodeSession(ctx context.Context, signature string) (err error)
}
