// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"
	"errors"
	"time"

	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/storage"
	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
)

// DeviceTokenEndpointHandler is a token response handler for the Device Code introduced in the Device Authorize Grant
// as defined in https://www.rfc-editor.org/rfc/rfc8628
type DeviceTokenEndpointHandler struct {
	DeviceRateLimitStrategy DeviceRateLimitStrategy
	DeviceStrategy          DeviceCodeStrategy
	DeviceStorage           DeviceCodeStorage

	AccessTokenStrategy    oauth2.AccessTokenStrategy
	RefreshTokenStrategy   oauth2.RefreshTokenStrategy
	CoreStorage            RFC8628CoreStorage
	TokenRevocationStorage oauth2.TokenRevocationStorage
	Config                 interface {
		fosite.AccessTokenLifespanProvider
		fosite.RefreshTokenLifespanProvider
		fosite.RefreshTokenScopesProvider
	}
}

var _ fosite.TokenEndpointHandler = (*DeviceTokenEndpointHandler)(nil)

func (c *DeviceTokenEndpointHandler) ValidateGrantTypes(ctx context.Context, requester fosite.AccessRequester) error {
	if !requester.GetClient().GetGrantTypes().Has(string(fosite.GrantTypeDeviceCode)) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:device_code\"."))
	}

	return nil
}

func (c *DeviceTokenEndpointHandler) ValidateCode(ctx context.Context, request fosite.AccessRequester, code string) error {
	return c.DeviceStrategy.ValidateDeviceCode(ctx, request, code)
}

func (c *DeviceTokenEndpointHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(errorsx.WithStack(fosite.ErrUnknownRequest))
	}

	if err := c.ValidateGrantTypes(ctx, request); err != nil {
		return err
	}

	code, _, authorizeRequest, err := c.GetDeviceCode(ctx, request)
	if errors.Is(err, fosite.ErrInvalidatedDeviceCode) {
		if authorizeRequest == nil {
			return fosite.ErrServerError.
				WithHint("Misconfigured code lead to an error that prohibited the OAuth 2.0 Framework from processing this request.").
				WithDebug("getCodeSession must return a value for \"fosite.Requester\" when returning \"ErrInvalidatedAuthorizeCode\" or \"ErrInvalidatedDeviceCode\".")
		}

		// If an authorize code is used twice, we revoke all refresh and access tokens associated with this request.
		reqID := authorizeRequest.GetID()
		hint := "The authorization code has already been used."
		debug := ""
		if revErr := c.TokenRevocationStorage.RevokeAccessToken(ctx, reqID); revErr != nil {
			hint += " Additionally, an error occurred during processing the access token revocation."
			debug += "Revocation of access_token lead to error " + revErr.Error() + "."
		}
		if revErr := c.TokenRevocationStorage.RevokeRefreshToken(ctx, reqID); revErr != nil {
			hint += " Additionally, an error occurred during processing the refresh token revocation."
			debug += "Revocation of refresh_token lead to error " + revErr.Error() + "."
		}
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint(hint).WithDebug(debug))
	} else if errors.Is(err, fosite.ErrAuthorizationPending) {
		// Don't print a stacktrace as it spams logs
		return err
	} else if errors.Is(err, fosite.ErrPollingRateLimited) {
		return errorsx.WithStack(err)
	} else if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	err = c.ValidateCode(ctx, request, code)
	if err != nil {
		return errorsx.WithStack(err)
	}

	// Override scopes
	request.SetRequestedScopes(authorizeRequest.GetRequestedScopes())

	// Override audiences
	request.SetRequestedAudience(authorizeRequest.GetRequestedAudience())

	// The authorization server MUST ensure that the authorization code was issued to the authenticated
	// confidential client, or if the client is public, ensure that the
	// code was issued to "client_id" in the request,
	if authorizeRequest.GetClient().GetID() != request.GetClient().GetID() {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the one from the authorize request."))
	}

	request.SetSession(authorizeRequest.GetSession())
	request.SetID(authorizeRequest.GetID())

	atLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	request.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	rtLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.RefreshToken, c.Config.GetRefreshTokenLifespan(ctx))
	if rtLifespan > -1 {
		request.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(rtLifespan).Round(time.Second))
	}

	return nil
}

func (c *DeviceTokenEndpointHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	code, signature, authorizeRequest, err := c.GetDeviceCode(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if err := c.ValidateCode(ctx, requester, code); err != nil {
		// This needs to happen after store retrieval for the session to be hydrated properly
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithWrap(err).WithDebug(err.Error()))
	}

	for _, scope := range authorizeRequest.GetGrantedScopes() {
		requester.GrantScope(scope)
	}

	for _, audience := range authorizeRequest.GetGrantedAudience() {
		requester.GrantAudience(audience)
	}

	access, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	var refresh, refreshSignature string
	if c.canIssueRefreshToken(ctx, authorizeRequest) {
		refresh, refreshSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
		if err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	ctx, err = storage.MaybeBeginTx(ctx, c.CoreStorage)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	defer func() {
		if err != nil {
			if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.CoreStorage); rollBackTxnErr != nil {
				err = errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
			}
		}
	}()

	if err = c.InvalidateSession(ctx, signature); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if err = c.CoreStorage.CreateAccessTokenSession(ctx, accessSignature, requester.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if refreshSignature != "" {
		if err = c.CoreStorage.CreateRefreshTokenSession(ctx, refreshSignature, requester.Sanitize([]string{})); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	responder.SetAccessToken(access)
	responder.SetTokenType("bearer")
	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, atLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	if refresh != "" {
		responder.SetExtra("refresh_token", refresh)
	}

	if err = storage.MaybeCommitTx(ctx, c.CoreStorage); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return nil
}

func (c *DeviceTokenEndpointHandler) canIssueRefreshToken(ctx context.Context, request fosite.Requester) bool {
	scope := c.Config.GetRefreshTokenScopes(ctx)
	// Require one of the refresh token scopes, if set.
	if len(scope) > 0 && !request.GetGrantedScopes().HasOneOf(scope...) {
		return false
	}
	// Do not issue a refresh token to clients that cannot use the refresh token grant type.
	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return false
	}
	return true
}

func (c *DeviceTokenEndpointHandler) GetDeviceCode(ctx context.Context, requester fosite.AccessRequester) (code string, signature string, request fosite.Requester, err error) {
	code = requester.GetRequestForm().Get("device_code")

	if c.DeviceRateLimitStrategy.ShouldRateLimit(ctx, code) {
		return "", "", nil, fosite.ErrPollingRateLimited
	}

	signature, err = c.DeviceStrategy.DeviceCodeSignature(ctx, code)
	if err != nil {
		return "", "", nil, errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	req, err := c.DeviceStorage.GetDeviceCodeSession(ctx, signature, requester.GetSession())
	return code, signature, req, err
}

func (c *DeviceTokenEndpointHandler) InvalidateSession(ctx context.Context, signature string) error {
	return c.DeviceStorage.InvalidateDeviceCodeSession(ctx, signature)
}

// implement TokenEndpointHandler
func (c *DeviceTokenEndpointHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(string(fosite.GrantTypeDeviceCode))
}

func (c *DeviceTokenEndpointHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(string(fosite.GrantTypeDeviceCode))
}

func getExpiresIn(r fosite.Requester, key fosite.TokenType, defaultLifespan time.Duration, now time.Time) time.Duration {
	if r.GetSession().GetExpiresAt(key).IsZero() {
		return defaultLifespan
	}
	return time.Duration(r.GetSession().GetExpiresAt(key).UnixNano() - now.UnixNano())
}
