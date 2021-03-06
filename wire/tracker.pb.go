// Code generated by protoc-gen-go.
// source: source/tracker.proto
// DO NOT EDIT!

package wire

import proto "code.google.com/p/goprotobuf/proto"
import json "encoding/json"
import math "math"

// Reference proto, json, and math imports to suppress error if they are not otherwise used.
var _ = proto.Marshal
var _ = &json.SyntaxError{}
var _ = math.Inf

type TrackerRegister struct {
	Address          *string     `protobuf:"bytes,1,req,name=address" json:"address,omitempty"`
	EncryptionKey    []byte      `protobuf:"bytes,2,req,name=encryption_key" json:"encryption_key,omitempty"`
	Location         *string     `protobuf:"bytes,3,req,name=location" json:"location,omitempty"`
	Expires          *uint64     `protobuf:"varint,4,req,name=expires" json:"expires,omitempty"`
	Redirect         []*Redirect `protobuf:"bytes,5,rep,name=redirect" json:"redirect,omitempty"`
	Username         *string     `protobuf:"bytes,6,opt,name=username" json:"username,omitempty"`
	XXX_unrecognized []byte      `json:"-"`
}

func (m *TrackerRegister) Reset()         { *m = TrackerRegister{} }
func (m *TrackerRegister) String() string { return proto.CompactTextString(m) }
func (*TrackerRegister) ProtoMessage()    {}

func (m *TrackerRegister) GetAddress() string {
	if m != nil && m.Address != nil {
		return *m.Address
	}
	return ""
}

func (m *TrackerRegister) GetEncryptionKey() []byte {
	if m != nil {
		return m.EncryptionKey
	}
	return nil
}

func (m *TrackerRegister) GetLocation() string {
	if m != nil && m.Location != nil {
		return *m.Location
	}
	return ""
}

func (m *TrackerRegister) GetExpires() uint64 {
	if m != nil && m.Expires != nil {
		return *m.Expires
	}
	return 0
}

func (m *TrackerRegister) GetRedirect() []*Redirect {
	if m != nil {
		return m.Redirect
	}
	return nil
}

func (m *TrackerRegister) GetUsername() string {
	if m != nil && m.Username != nil {
		return *m.Username
	}
	return ""
}

type TrackerQuery struct {
	Address          *string `protobuf:"bytes,1,opt,name=address" json:"address,omitempty"`
	Username         *string `protobuf:"bytes,2,opt,name=username" json:"username,omitempty"`
	NeedKey          *bool   `protobuf:"varint,3,opt,name=need_key" json:"need_key,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *TrackerQuery) Reset()         { *m = TrackerQuery{} }
func (m *TrackerQuery) String() string { return proto.CompactTextString(m) }
func (*TrackerQuery) ProtoMessage()    {}

func (m *TrackerQuery) GetAddress() string {
	if m != nil && m.Address != nil {
		return *m.Address
	}
	return ""
}

func (m *TrackerQuery) GetUsername() string {
	if m != nil && m.Username != nil {
		return *m.Username
	}
	return ""
}

func (m *TrackerQuery) GetNeedKey() bool {
	if m != nil && m.NeedKey != nil {
		return *m.NeedKey
	}
	return false
}

type Redirect struct {
	Types            *string `protobuf:"bytes,1,req,name=types" json:"types,omitempty"`
	Alias            *string `protobuf:"bytes,2,req,name=alias" json:"alias,omitempty"`
	Address          *string `protobuf:"bytes,3,opt,name=address" json:"address,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *Redirect) Reset()         { *m = Redirect{} }
func (m *Redirect) String() string { return proto.CompactTextString(m) }
func (*Redirect) ProtoMessage()    {}

func (m *Redirect) GetTypes() string {
	if m != nil && m.Types != nil {
		return *m.Types
	}
	return ""
}

func (m *Redirect) GetAlias() string {
	if m != nil && m.Alias != nil {
		return *m.Alias
	}
	return ""
}

func (m *Redirect) GetAddress() string {
	if m != nil && m.Address != nil {
		return *m.Address
	}
	return ""
}

func init() {
}
