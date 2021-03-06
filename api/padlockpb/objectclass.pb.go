// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.10.1
// source: objectclass.proto

package padlockpb

import (
	_ "github.com/LLKennedy/protoc-gen-tsjson/tsjsonpb"
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type ObjectClass int32

const (
	ObjectClass_CKO_UNDEFINED_UNKNOWN ObjectClass = 0
	ObjectClass_CKO_DATA              ObjectClass = 1
	ObjectClass_CKO_CERTIFICATE       ObjectClass = 2
	ObjectClass_CKO_PUBLIC_KEY        ObjectClass = 3
	ObjectClass_CKO_PRIVATE_KEY       ObjectClass = 4
	ObjectClass_CKO_SECRET_KEY        ObjectClass = 5
	ObjectClass_CKO_HW_FEATURE        ObjectClass = 6
	ObjectClass_CKO_DOMAIN_PARAMETERS ObjectClass = 7
	ObjectClass_CKO_MECHANISM         ObjectClass = 8
	ObjectClass_CKO_OTP_KEY           ObjectClass = 9
	ObjectClass_CKO_VENDOR_DEFINED    ObjectClass = 10
)

// Enum value maps for ObjectClass.
var (
	ObjectClass_name = map[int32]string{
		0:  "CKO_UNDEFINED_UNKNOWN",
		1:  "CKO_DATA",
		2:  "CKO_CERTIFICATE",
		3:  "CKO_PUBLIC_KEY",
		4:  "CKO_PRIVATE_KEY",
		5:  "CKO_SECRET_KEY",
		6:  "CKO_HW_FEATURE",
		7:  "CKO_DOMAIN_PARAMETERS",
		8:  "CKO_MECHANISM",
		9:  "CKO_OTP_KEY",
		10: "CKO_VENDOR_DEFINED",
	}
	ObjectClass_value = map[string]int32{
		"CKO_UNDEFINED_UNKNOWN": 0,
		"CKO_DATA":              1,
		"CKO_CERTIFICATE":       2,
		"CKO_PUBLIC_KEY":        3,
		"CKO_PRIVATE_KEY":       4,
		"CKO_SECRET_KEY":        5,
		"CKO_HW_FEATURE":        6,
		"CKO_DOMAIN_PARAMETERS": 7,
		"CKO_MECHANISM":         8,
		"CKO_OTP_KEY":           9,
		"CKO_VENDOR_DEFINED":    10,
	}
)

func (x ObjectClass) Enum() *ObjectClass {
	p := new(ObjectClass)
	*p = x
	return p
}

func (x ObjectClass) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ObjectClass) Descriptor() protoreflect.EnumDescriptor {
	return file_objectclass_proto_enumTypes[0].Descriptor()
}

func (ObjectClass) Type() protoreflect.EnumType {
	return &file_objectclass_proto_enumTypes[0]
}

func (x ObjectClass) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ObjectClass.Descriptor instead.
func (ObjectClass) EnumDescriptor() ([]byte, []int) {
	return file_objectclass_proto_rawDescGZIP(), []int{0}
}

var File_objectclass_proto protoreflect.FileDescriptor

var file_objectclass_proto_rawDesc = []byte{
	0x0a, 0x11, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x07, 0x70, 0x61, 0x64, 0x6c, 0x6f, 0x63, 0x6b, 0x1a, 0x0c, 0x74, 0x73,
	0x6a, 0x73, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2a, 0xf3, 0x01, 0x0a, 0x0b, 0x4f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x12, 0x19, 0x0a, 0x15, 0x43, 0x4b,
	0x4f, 0x5f, 0x55, 0x4e, 0x44, 0x45, 0x46, 0x49, 0x4e, 0x45, 0x44, 0x5f, 0x55, 0x4e, 0x4b, 0x4e,
	0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x0c, 0x0a, 0x08, 0x43, 0x4b, 0x4f, 0x5f, 0x44, 0x41, 0x54,
	0x41, 0x10, 0x01, 0x12, 0x13, 0x0a, 0x0f, 0x43, 0x4b, 0x4f, 0x5f, 0x43, 0x45, 0x52, 0x54, 0x49,
	0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x10, 0x02, 0x12, 0x12, 0x0a, 0x0e, 0x43, 0x4b, 0x4f, 0x5f,
	0x50, 0x55, 0x42, 0x4c, 0x49, 0x43, 0x5f, 0x4b, 0x45, 0x59, 0x10, 0x03, 0x12, 0x13, 0x0a, 0x0f,
	0x43, 0x4b, 0x4f, 0x5f, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x5f, 0x4b, 0x45, 0x59, 0x10,
	0x04, 0x12, 0x12, 0x0a, 0x0e, 0x43, 0x4b, 0x4f, 0x5f, 0x53, 0x45, 0x43, 0x52, 0x45, 0x54, 0x5f,
	0x4b, 0x45, 0x59, 0x10, 0x05, 0x12, 0x12, 0x0a, 0x0e, 0x43, 0x4b, 0x4f, 0x5f, 0x48, 0x57, 0x5f,
	0x46, 0x45, 0x41, 0x54, 0x55, 0x52, 0x45, 0x10, 0x06, 0x12, 0x19, 0x0a, 0x15, 0x43, 0x4b, 0x4f,
	0x5f, 0x44, 0x4f, 0x4d, 0x41, 0x49, 0x4e, 0x5f, 0x50, 0x41, 0x52, 0x41, 0x4d, 0x45, 0x54, 0x45,
	0x52, 0x53, 0x10, 0x07, 0x12, 0x11, 0x0a, 0x0d, 0x43, 0x4b, 0x4f, 0x5f, 0x4d, 0x45, 0x43, 0x48,
	0x41, 0x4e, 0x49, 0x53, 0x4d, 0x10, 0x08, 0x12, 0x0f, 0x0a, 0x0b, 0x43, 0x4b, 0x4f, 0x5f, 0x4f,
	0x54, 0x50, 0x5f, 0x4b, 0x45, 0x59, 0x10, 0x09, 0x12, 0x16, 0x0a, 0x12, 0x43, 0x4b, 0x4f, 0x5f,
	0x56, 0x45, 0x4e, 0x44, 0x4f, 0x52, 0x5f, 0x44, 0x45, 0x46, 0x49, 0x4e, 0x45, 0x44, 0x10, 0x0a,
	0x42, 0x4b, 0x5a, 0x26, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x4c,
	0x4c, 0x4b, 0x65, 0x6e, 0x6e, 0x65, 0x64, 0x79, 0x2f, 0x70, 0x61, 0x64, 0x6c, 0x6f, 0x63, 0x6b,
	0x2f, 0x70, 0x61, 0x64, 0x6c, 0x6f, 0x63, 0x6b, 0x70, 0x62, 0x82, 0xd9, 0x66, 0x10, 0x40, 0x6c,
	0x6c, 0x6b, 0x64, 0x65, 0x6d, 0x6f, 0x2f, 0x70, 0x61, 0x64, 0x6c, 0x6f, 0x63, 0x6b, 0x8a, 0xd9,
	0x66, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_objectclass_proto_rawDescOnce sync.Once
	file_objectclass_proto_rawDescData = file_objectclass_proto_rawDesc
)

func file_objectclass_proto_rawDescGZIP() []byte {
	file_objectclass_proto_rawDescOnce.Do(func() {
		file_objectclass_proto_rawDescData = protoimpl.X.CompressGZIP(file_objectclass_proto_rawDescData)
	})
	return file_objectclass_proto_rawDescData
}

var file_objectclass_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_objectclass_proto_goTypes = []interface{}{
	(ObjectClass)(0), // 0: padlock.ObjectClass
}
var file_objectclass_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_objectclass_proto_init() }
func file_objectclass_proto_init() {
	if File_objectclass_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_objectclass_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_objectclass_proto_goTypes,
		DependencyIndexes: file_objectclass_proto_depIdxs,
		EnumInfos:         file_objectclass_proto_enumTypes,
	}.Build()
	File_objectclass_proto = out.File
	file_objectclass_proto_rawDesc = nil
	file_objectclass_proto_goTypes = nil
	file_objectclass_proto_depIdxs = nil
}
