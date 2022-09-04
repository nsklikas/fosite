// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ory/fosite/handler/oauth2 (interfaces: CoreStorage)

// Package internal is a generated GoMock package.
package internal

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	fosite "github.com/ory/fosite"
)

// MockCoreStorage is a mock of CoreStorage interface.
type MockCoreStorage struct {
	ctrl     *gomock.Controller
	recorder *MockCoreStorageMockRecorder
}

// MockCoreStorageMockRecorder is the mock recorder for MockCoreStorage.
type MockCoreStorageMockRecorder struct {
	mock *MockCoreStorage
}

// NewMockCoreStorage creates a new mock instance.
func NewMockCoreStorage(ctrl *gomock.Controller) *MockCoreStorage {
	mock := &MockCoreStorage{ctrl: ctrl}
	mock.recorder = &MockCoreStorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCoreStorage) EXPECT() *MockCoreStorageMockRecorder {
	return m.recorder
}

// CreateAccessTokenSession mocks base method.
func (m *MockCoreStorage) CreateAccessTokenSession(arg0 context.Context, arg1 string, arg2 fosite.Requester) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAccessTokenSession", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateAccessTokenSession indicates an expected call of CreateAccessTokenSession.
func (mr *MockCoreStorageMockRecorder) CreateAccessTokenSession(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAccessTokenSession", reflect.TypeOf((*MockCoreStorage)(nil).CreateAccessTokenSession), arg0, arg1, arg2)
}

// CreateAuthorizeCodeSession mocks base method.
func (m *MockCoreStorage) CreateAuthorizeCodeSession(arg0 context.Context, arg1 string, arg2 fosite.Requester) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAuthorizeCodeSession", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateAuthorizeCodeSession indicates an expected call of CreateAuthorizeCodeSession.
func (mr *MockCoreStorageMockRecorder) CreateAuthorizeCodeSession(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAuthorizeCodeSession", reflect.TypeOf((*MockCoreStorage)(nil).CreateAuthorizeCodeSession), arg0, arg1, arg2)
}

// CreateDeviceCodeSession mocks base method.
func (m *MockCoreStorage) CreateDeviceCodeSession(arg0 context.Context, arg1 string, arg2 fosite.Requester) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateDeviceCodeSession", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateDeviceCodeSession indicates an expected call of CreateDeviceCodeSession.
func (mr *MockCoreStorageMockRecorder) CreateDeviceCodeSession(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateDeviceCodeSession", reflect.TypeOf((*MockCoreStorage)(nil).CreateDeviceCodeSession), arg0, arg1, arg2)
}

// CreateRefreshTokenSession mocks base method.
func (m *MockCoreStorage) CreateRefreshTokenSession(arg0 context.Context, arg1 string, arg2 fosite.Requester) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateRefreshTokenSession", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateRefreshTokenSession indicates an expected call of CreateRefreshTokenSession.
func (mr *MockCoreStorageMockRecorder) CreateRefreshTokenSession(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateRefreshTokenSession", reflect.TypeOf((*MockCoreStorage)(nil).CreateRefreshTokenSession), arg0, arg1, arg2)
}

// CreateUserCodeSession mocks base method.
func (m *MockCoreStorage) CreateUserCodeSession(arg0 context.Context, arg1 string, arg2 fosite.Requester) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateUserCodeSession", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateUserCodeSession indicates an expected call of CreateUserCodeSession.
func (mr *MockCoreStorageMockRecorder) CreateUserCodeSession(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUserCodeSession", reflect.TypeOf((*MockCoreStorage)(nil).CreateUserCodeSession), arg0, arg1, arg2)
}

// DeleteAccessTokenSession mocks base method.
func (m *MockCoreStorage) DeleteAccessTokenSession(arg0 context.Context, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteAccessTokenSession", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteAccessTokenSession indicates an expected call of DeleteAccessTokenSession.
func (mr *MockCoreStorageMockRecorder) DeleteAccessTokenSession(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAccessTokenSession", reflect.TypeOf((*MockCoreStorage)(nil).DeleteAccessTokenSession), arg0, arg1)
}

// DeleteDeviceCodeSession mocks base method.
func (m *MockCoreStorage) DeleteDeviceCodeSession(arg0 context.Context, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteDeviceCodeSession", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteDeviceCodeSession indicates an expected call of DeleteDeviceCodeSession.
func (mr *MockCoreStorageMockRecorder) DeleteDeviceCodeSession(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteDeviceCodeSession", reflect.TypeOf((*MockCoreStorage)(nil).DeleteDeviceCodeSession), arg0, arg1)
}

// DeleteRefreshTokenSession mocks base method.
func (m *MockCoreStorage) DeleteRefreshTokenSession(arg0 context.Context, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteRefreshTokenSession", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteRefreshTokenSession indicates an expected call of DeleteRefreshTokenSession.
func (mr *MockCoreStorageMockRecorder) DeleteRefreshTokenSession(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteRefreshTokenSession", reflect.TypeOf((*MockCoreStorage)(nil).DeleteRefreshTokenSession), arg0, arg1)
}

// DeleteUserCodeSession mocks base method.
func (m *MockCoreStorage) DeleteUserCodeSession(arg0 context.Context, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteUserCodeSession", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteUserCodeSession indicates an expected call of DeleteUserCodeSession.
func (mr *MockCoreStorageMockRecorder) DeleteUserCodeSession(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUserCodeSession", reflect.TypeOf((*MockCoreStorage)(nil).DeleteUserCodeSession), arg0, arg1)
}

// GetAccessTokenSession mocks base method.
func (m *MockCoreStorage) GetAccessTokenSession(arg0 context.Context, arg1 string, arg2 fosite.Session) (fosite.Requester, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAccessTokenSession", arg0, arg1, arg2)
	ret0, _ := ret[0].(fosite.Requester)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAccessTokenSession indicates an expected call of GetAccessTokenSession.
func (mr *MockCoreStorageMockRecorder) GetAccessTokenSession(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAccessTokenSession", reflect.TypeOf((*MockCoreStorage)(nil).GetAccessTokenSession), arg0, arg1, arg2)
}

// GetAuthorizeCodeSession mocks base method.
func (m *MockCoreStorage) GetAuthorizeCodeSession(arg0 context.Context, arg1 string, arg2 fosite.Session) (fosite.Requester, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAuthorizeCodeSession", arg0, arg1, arg2)
	ret0, _ := ret[0].(fosite.Requester)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAuthorizeCodeSession indicates an expected call of GetAuthorizeCodeSession.
func (mr *MockCoreStorageMockRecorder) GetAuthorizeCodeSession(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAuthorizeCodeSession", reflect.TypeOf((*MockCoreStorage)(nil).GetAuthorizeCodeSession), arg0, arg1, arg2)
}

// GetDeviceCodeSession mocks base method.
func (m *MockCoreStorage) GetDeviceCodeSession(arg0 context.Context, arg1 string, arg2 fosite.Session) (fosite.Requester, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetDeviceCodeSession", arg0, arg1, arg2)
	ret0, _ := ret[0].(fosite.Requester)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetDeviceCodeSession indicates an expected call of GetDeviceCodeSession.
func (mr *MockCoreStorageMockRecorder) GetDeviceCodeSession(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetDeviceCodeSession", reflect.TypeOf((*MockCoreStorage)(nil).GetDeviceCodeSession), arg0, arg1, arg2)
}

// GetRefreshTokenSession mocks base method.
func (m *MockCoreStorage) GetRefreshTokenSession(arg0 context.Context, arg1 string, arg2 fosite.Session) (fosite.Requester, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRefreshTokenSession", arg0, arg1, arg2)
	ret0, _ := ret[0].(fosite.Requester)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRefreshTokenSession indicates an expected call of GetRefreshTokenSession.
func (mr *MockCoreStorageMockRecorder) GetRefreshTokenSession(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRefreshTokenSession", reflect.TypeOf((*MockCoreStorage)(nil).GetRefreshTokenSession), arg0, arg1, arg2)
}

// GetUserCodeSession mocks base method.
func (m *MockCoreStorage) GetUserCodeSession(arg0 context.Context, arg1 string, arg2 fosite.Session) (fosite.Requester, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserCodeSession", arg0, arg1, arg2)
	ret0, _ := ret[0].(fosite.Requester)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserCodeSession indicates an expected call of GetUserCodeSession.
func (mr *MockCoreStorageMockRecorder) GetUserCodeSession(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserCodeSession", reflect.TypeOf((*MockCoreStorage)(nil).GetUserCodeSession), arg0, arg1, arg2)
}

// InvalidateAuthorizeCodeSession mocks base method.
func (m *MockCoreStorage) InvalidateAuthorizeCodeSession(arg0 context.Context, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InvalidateAuthorizeCodeSession", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// InvalidateAuthorizeCodeSession indicates an expected call of InvalidateAuthorizeCodeSession.
func (mr *MockCoreStorageMockRecorder) InvalidateAuthorizeCodeSession(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InvalidateAuthorizeCodeSession", reflect.TypeOf((*MockCoreStorage)(nil).InvalidateAuthorizeCodeSession), arg0, arg1)
}
