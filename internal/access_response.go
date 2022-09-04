// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ory/fosite (interfaces: AccessResponder)

// Package internal is a generated GoMock package.
package internal

import (
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	fosite "github.com/ory/fosite"
)

// MockAccessResponder is a mock of AccessResponder interface.
type MockAccessResponder struct {
	ctrl     *gomock.Controller
	recorder *MockAccessResponderMockRecorder
}

// MockAccessResponderMockRecorder is the mock recorder for MockAccessResponder.
type MockAccessResponderMockRecorder struct {
	mock *MockAccessResponder
}

// NewMockAccessResponder creates a new mock instance.
func NewMockAccessResponder(ctrl *gomock.Controller) *MockAccessResponder {
	mock := &MockAccessResponder{ctrl: ctrl}
	mock.recorder = &MockAccessResponderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAccessResponder) EXPECT() *MockAccessResponderMockRecorder {
	return m.recorder
}

// GetAccessToken mocks base method.
func (m *MockAccessResponder) GetAccessToken() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAccessToken")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetAccessToken indicates an expected call of GetAccessToken.
func (mr *MockAccessResponderMockRecorder) GetAccessToken() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAccessToken", reflect.TypeOf((*MockAccessResponder)(nil).GetAccessToken))
}

// GetExtra mocks base method.
func (m *MockAccessResponder) GetExtra(arg0 string) interface{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetExtra", arg0)
	ret0, _ := ret[0].(interface{})
	return ret0
}

// GetExtra indicates an expected call of GetExtra.
func (mr *MockAccessResponderMockRecorder) GetExtra(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetExtra", reflect.TypeOf((*MockAccessResponder)(nil).GetExtra), arg0)
}

// GetTokenType mocks base method.
func (m *MockAccessResponder) GetTokenType() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTokenType")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetTokenType indicates an expected call of GetTokenType.
func (mr *MockAccessResponderMockRecorder) GetTokenType() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTokenType", reflect.TypeOf((*MockAccessResponder)(nil).GetTokenType))
}

// SetAccessToken mocks base method.
func (m *MockAccessResponder) SetAccessToken(arg0 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetAccessToken", arg0)
}

// SetAccessToken indicates an expected call of SetAccessToken.
func (mr *MockAccessResponderMockRecorder) SetAccessToken(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetAccessToken", reflect.TypeOf((*MockAccessResponder)(nil).SetAccessToken), arg0)
}

// SetExpiresIn mocks base method.
func (m *MockAccessResponder) SetExpiresIn(arg0 time.Duration) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetExpiresIn", arg0)
}

// SetExpiresIn indicates an expected call of SetExpiresIn.
func (mr *MockAccessResponderMockRecorder) SetExpiresIn(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetExpiresIn", reflect.TypeOf((*MockAccessResponder)(nil).SetExpiresIn), arg0)
}

// SetExtra mocks base method.
func (m *MockAccessResponder) SetExtra(arg0 string, arg1 interface{}) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetExtra", arg0, arg1)
}

// SetExtra indicates an expected call of SetExtra.
func (mr *MockAccessResponderMockRecorder) SetExtra(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetExtra", reflect.TypeOf((*MockAccessResponder)(nil).SetExtra), arg0, arg1)
}

// SetScopes mocks base method.
func (m *MockAccessResponder) SetScopes(arg0 fosite.Arguments) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetScopes", arg0)
}

// SetScopes indicates an expected call of SetScopes.
func (mr *MockAccessResponderMockRecorder) SetScopes(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetScopes", reflect.TypeOf((*MockAccessResponder)(nil).SetScopes), arg0)
}

// SetTokenType mocks base method.
func (m *MockAccessResponder) SetTokenType(arg0 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetTokenType", arg0)
}

// SetTokenType indicates an expected call of SetTokenType.
func (mr *MockAccessResponderMockRecorder) SetTokenType(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetTokenType", reflect.TypeOf((*MockAccessResponder)(nil).SetTokenType), arg0)
}

// ToMap mocks base method.
func (m *MockAccessResponder) ToMap() map[string]interface{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ToMap")
	ret0, _ := ret[0].(map[string]interface{})
	return ret0
}

// ToMap indicates an expected call of ToMap.
func (mr *MockAccessResponderMockRecorder) ToMap() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ToMap", reflect.TypeOf((*MockAccessResponder)(nil).ToMap))
}
