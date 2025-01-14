// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: proto/v1/asset.proto

package protov1

import (
	_ "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Enum representing the processing status of an intent.
type ProcessingStatus int32

const (
	ProcessingStatus_PROCESSING_STATUS_UNSPECIFIED     ProcessingStatus = 0 // Default value, unspecified processing status.
	ProcessingStatus_PROCESSING_STATUS_RECEIVED        ProcessingStatus = 1 // Intent has been received.
	ProcessingStatus_PROCESSING_STATUS_SENT_TO_SOLVER  ProcessingStatus = 2 // Intent has been sent to the solver.
	ProcessingStatus_PROCESSING_STATUS_SOLVED          ProcessingStatus = 3 // Intent has been solved.
	ProcessingStatus_PROCESSING_STATUS_UNSOLVED        ProcessingStatus = 4 // Intent remains unsolved.
	ProcessingStatus_PROCESSING_STATUS_EXPIRED         ProcessingStatus = 5 // Intent has expired.
	ProcessingStatus_PROCESSING_STATUS_ON_CHAIN        ProcessingStatus = 6 // Intent is on the blockchain.
	ProcessingStatus_PROCESSING_STATUS_INVALID         ProcessingStatus = 7 // Intent is invalid.
	ProcessingStatus_PROCESSING_STATUS_ON_CHAIN_REVERT ProcessingStatus = 8 // Intent is onchain but reverted
)

// Enum value maps for ProcessingStatus.
var (
	ProcessingStatus_name = map[int32]string{
		0: "PROCESSING_STATUS_UNSPECIFIED",
		1: "PROCESSING_STATUS_RECEIVED",
		2: "PROCESSING_STATUS_SENT_TO_SOLVER",
		3: "PROCESSING_STATUS_SOLVED",
		4: "PROCESSING_STATUS_UNSOLVED",
		5: "PROCESSING_STATUS_EXPIRED",
		6: "PROCESSING_STATUS_ON_CHAIN",
		7: "PROCESSING_STATUS_INVALID",
		8: "PROCESSING_STATUS_ON_CHAIN_REVERT",
	}
	ProcessingStatus_value = map[string]int32{
		"PROCESSING_STATUS_UNSPECIFIED":     0,
		"PROCESSING_STATUS_RECEIVED":        1,
		"PROCESSING_STATUS_SENT_TO_SOLVER":  2,
		"PROCESSING_STATUS_SOLVED":          3,
		"PROCESSING_STATUS_UNSOLVED":        4,
		"PROCESSING_STATUS_EXPIRED":         5,
		"PROCESSING_STATUS_ON_CHAIN":        6,
		"PROCESSING_STATUS_INVALID":         7,
		"PROCESSING_STATUS_ON_CHAIN_REVERT": 8,
	}
)

func (x ProcessingStatus) Enum() *ProcessingStatus {
	p := new(ProcessingStatus)
	*p = x
	return p
}

func (x ProcessingStatus) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ProcessingStatus) Descriptor() protoreflect.EnumDescriptor {
	return file_proto_v1_asset_proto_enumTypes[0].Descriptor()
}

func (ProcessingStatus) Type() protoreflect.EnumType {
	return &file_proto_v1_asset_proto_enumTypes[0]
}

func (x ProcessingStatus) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ProcessingStatus.Descriptor instead.
func (ProcessingStatus) EnumDescriptor() ([]byte, []int) {
	return file_proto_v1_asset_proto_rawDescGZIP(), []int{0}
}

// BigInt represents a large number
type BigInt struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Value []byte `protobuf:"bytes,1,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *BigInt) Reset() {
	*x = BigInt{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_v1_asset_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BigInt) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BigInt) ProtoMessage() {}

func (x *BigInt) ProtoReflect() protoreflect.Message {
	mi := &file_proto_v1_asset_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BigInt.ProtoReflect.Descriptor instead.
func (*BigInt) Descriptor() ([]byte, []int) {
	return file_proto_v1_asset_proto_rawDescGZIP(), []int{0}
}

func (x *BigInt) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

// Message representing the details of an asset.
type Asset struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Address string `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"` // The address of the asset.
	// The amount of the asset.
	// In cases of AssetType being used as the to field, it doesn't have to provided
	// and can be left empty
	Amount  *BigInt `protobuf:"bytes,2,opt,name=amount,proto3" json:"amount,omitempty"`
	ChainId *BigInt `protobuf:"bytes,3,opt,name=chain_id,json=chainId,proto3" json:"chain_id,omitempty"` // The chain ID where the asset resides.
}

func (x *Asset) Reset() {
	*x = Asset{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_v1_asset_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Asset) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Asset) ProtoMessage() {}

func (x *Asset) ProtoReflect() protoreflect.Message {
	mi := &file_proto_v1_asset_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Asset.ProtoReflect.Descriptor instead.
func (*Asset) Descriptor() ([]byte, []int) {
	return file_proto_v1_asset_proto_rawDescGZIP(), []int{1}
}

func (x *Asset) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

func (x *Asset) GetAmount() *BigInt {
	if x != nil {
		return x.Amount
	}
	return nil
}

func (x *Asset) GetChainId() *BigInt {
	if x != nil {
		return x.ChainId
	}
	return nil
}

// Message representing the details of a stake.
type Stake struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Address string  `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`                // The address of the stake.
	Amount  *BigInt `protobuf:"bytes,2,opt,name=amount,proto3" json:"amount,omitempty"`                  // The amount of the stake.
	ChainId *BigInt `protobuf:"bytes,3,opt,name=chain_id,json=chainId,proto3" json:"chain_id,omitempty"` // The chain ID where the asset resides.
}

func (x *Stake) Reset() {
	*x = Stake{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_v1_asset_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Stake) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Stake) ProtoMessage() {}

func (x *Stake) ProtoReflect() protoreflect.Message {
	mi := &file_proto_v1_asset_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Stake.ProtoReflect.Descriptor instead.
func (*Stake) Descriptor() ([]byte, []int) {
	return file_proto_v1_asset_proto_rawDescGZIP(), []int{2}
}

func (x *Stake) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

func (x *Stake) GetAmount() *BigInt {
	if x != nil {
		return x.Amount
	}
	return nil
}

func (x *Stake) GetChainId() *BigInt {
	if x != nil {
		return x.ChainId
	}
	return nil
}

// Message representing the details of a loan.
type Loan struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Asset   string  `protobuf:"bytes,1,opt,name=asset,proto3" json:"asset,omitempty"`                    // The asset associated with the loan.
	Amount  *BigInt `protobuf:"bytes,2,opt,name=amount,proto3" json:"amount,omitempty"`                  // The amount of the loan.
	Address string  `protobuf:"bytes,3,opt,name=address,proto3" json:"address,omitempty"`                // The address associated with the loan.
	ChainId *BigInt `protobuf:"bytes,4,opt,name=chain_id,json=chainId,proto3" json:"chain_id,omitempty"` // The chain ID where the asset resides.
}

func (x *Loan) Reset() {
	*x = Loan{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_v1_asset_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Loan) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Loan) ProtoMessage() {}

func (x *Loan) ProtoReflect() protoreflect.Message {
	mi := &file_proto_v1_asset_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Loan.ProtoReflect.Descriptor instead.
func (*Loan) Descriptor() ([]byte, []int) {
	return file_proto_v1_asset_proto_rawDescGZIP(), []int{3}
}

func (x *Loan) GetAsset() string {
	if x != nil {
		return x.Asset
	}
	return ""
}

func (x *Loan) GetAmount() *BigInt {
	if x != nil {
		return x.Amount
	}
	return nil
}

func (x *Loan) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

func (x *Loan) GetChainId() *BigInt {
	if x != nil {
		return x.ChainId
	}
	return nil
}

// Message representing additional data for an intent.
type ExtraData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PartiallyFillable *wrapperspb.BoolValue `protobuf:"bytes,1,opt,name=partially_fillable,json=partiallyFillable,proto3" json:"partially_fillable,omitempty"` // Indicates if the intent is partially fillable.
}

func (x *ExtraData) Reset() {
	*x = ExtraData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_v1_asset_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ExtraData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ExtraData) ProtoMessage() {}

func (x *ExtraData) ProtoReflect() protoreflect.Message {
	mi := &file_proto_v1_asset_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ExtraData.ProtoReflect.Descriptor instead.
func (*ExtraData) Descriptor() ([]byte, []int) {
	return file_proto_v1_asset_proto_rawDescGZIP(), []int{4}
}

func (x *ExtraData) GetPartiallyFillable() *wrapperspb.BoolValue {
	if x != nil {
		return x.PartiallyFillable
	}
	return nil
}

// Message representing an intent with various types of transactions.
type Intent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Oneof field representing the asset being sent.
	//
	// Types that are assignable to From:
	//
	//	*Intent_FromAsset
	//	*Intent_FromStake
	//	*Intent_FromLoan
	From isIntent_From `protobuf_oneof:"from"`
	// Oneof field representing the asset being received.
	//
	// Types that are assignable to To:
	//
	//	*Intent_ToAsset
	//	*Intent_ToStake
	//	*Intent_ToLoan
	To isIntent_To `protobuf_oneof:"to"`
	// The recipient of the transfer, if different from the default
	Recipient *string          `protobuf:"bytes,8,opt,name=recipient,proto3,oneof" json:"recipient,omitempty"`
	ExtraData *ExtraData       `protobuf:"bytes,9,opt,name=extra_data,json=extraData,proto3" json:"extra_data,omitempty"`           // Additional data for the intent.
	Status    ProcessingStatus `protobuf:"varint,10,opt,name=status,proto3,enum=proto.v1.ProcessingStatus" json:"status,omitempty"` // The processing status of the intent.
	// The creation timestamp of the intent.
	CreatedAt *timestamppb.Timestamp `protobuf:"bytes,11,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	// when this intent expires
	ExpirationAt *timestamppb.Timestamp `protobuf:"bytes,12,opt,name=expiration_at,json=expirationAt,proto3" json:"expiration_at,omitempty"`
}

func (x *Intent) Reset() {
	*x = Intent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_v1_asset_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Intent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Intent) ProtoMessage() {}

func (x *Intent) ProtoReflect() protoreflect.Message {
	mi := &file_proto_v1_asset_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Intent.ProtoReflect.Descriptor instead.
func (*Intent) Descriptor() ([]byte, []int) {
	return file_proto_v1_asset_proto_rawDescGZIP(), []int{5}
}

func (m *Intent) GetFrom() isIntent_From {
	if m != nil {
		return m.From
	}
	return nil
}

func (x *Intent) GetFromAsset() *Asset {
	if x, ok := x.GetFrom().(*Intent_FromAsset); ok {
		return x.FromAsset
	}
	return nil
}

func (x *Intent) GetFromStake() *Stake {
	if x, ok := x.GetFrom().(*Intent_FromStake); ok {
		return x.FromStake
	}
	return nil
}

func (x *Intent) GetFromLoan() *Loan {
	if x, ok := x.GetFrom().(*Intent_FromLoan); ok {
		return x.FromLoan
	}
	return nil
}

func (m *Intent) GetTo() isIntent_To {
	if m != nil {
		return m.To
	}
	return nil
}

func (x *Intent) GetToAsset() *Asset {
	if x, ok := x.GetTo().(*Intent_ToAsset); ok {
		return x.ToAsset
	}
	return nil
}

func (x *Intent) GetToStake() *Stake {
	if x, ok := x.GetTo().(*Intent_ToStake); ok {
		return x.ToStake
	}
	return nil
}

func (x *Intent) GetToLoan() *Loan {
	if x, ok := x.GetTo().(*Intent_ToLoan); ok {
		return x.ToLoan
	}
	return nil
}

func (x *Intent) GetRecipient() string {
	if x != nil && x.Recipient != nil {
		return *x.Recipient
	}
	return ""
}

func (x *Intent) GetExtraData() *ExtraData {
	if x != nil {
		return x.ExtraData
	}
	return nil
}

func (x *Intent) GetStatus() ProcessingStatus {
	if x != nil {
		return x.Status
	}
	return ProcessingStatus_PROCESSING_STATUS_UNSPECIFIED
}

func (x *Intent) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *Intent) GetExpirationAt() *timestamppb.Timestamp {
	if x != nil {
		return x.ExpirationAt
	}
	return nil
}

type isIntent_From interface {
	isIntent_From()
}

type Intent_FromAsset struct {
	FromAsset *Asset `protobuf:"bytes,2,opt,name=fromAsset,proto3,oneof"` // The asset being sent.
}

type Intent_FromStake struct {
	FromStake *Stake `protobuf:"bytes,3,opt,name=fromStake,proto3,oneof"` // The stake being sent.
}

type Intent_FromLoan struct {
	FromLoan *Loan `protobuf:"bytes,4,opt,name=fromLoan,proto3,oneof"` // The loan being sent.
}

func (*Intent_FromAsset) isIntent_From() {}

func (*Intent_FromStake) isIntent_From() {}

func (*Intent_FromLoan) isIntent_From() {}

type isIntent_To interface {
	isIntent_To()
}

type Intent_ToAsset struct {
	ToAsset *Asset `protobuf:"bytes,5,opt,name=toAsset,proto3,oneof"` // The token being received.
}

type Intent_ToStake struct {
	ToStake *Stake `protobuf:"bytes,6,opt,name=toStake,proto3,oneof"` // The stake being received.
}

type Intent_ToLoan struct {
	ToLoan *Loan `protobuf:"bytes,7,opt,name=toLoan,proto3,oneof"` // The loan being received.
}

func (*Intent_ToAsset) isIntent_To() {}

func (*Intent_ToStake) isIntent_To() {}

func (*Intent_ToLoan) isIntent_To() {}

// Message representing a body of intents.
type Body struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Intents []*Intent `protobuf:"bytes,1,rep,name=intents,proto3" json:"intents,omitempty"` // A list of intents.
}

func (x *Body) Reset() {
	*x = Body{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_v1_asset_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Body) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Body) ProtoMessage() {}

func (x *Body) ProtoReflect() protoreflect.Message {
	mi := &file_proto_v1_asset_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Body.ProtoReflect.Descriptor instead.
func (*Body) Descriptor() ([]byte, []int) {
	return file_proto_v1_asset_proto_rawDescGZIP(), []int{6}
}

func (x *Body) GetIntents() []*Intent {
	if x != nil {
		return x.Intents
	}
	return nil
}

var File_proto_v1_asset_proto protoreflect.FileDescriptor

var file_proto_v1_asset_proto_rawDesc = []byte{
	0x0a, 0x14, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x73, 0x73, 0x65, 0x74,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x76, 0x31,
	0x1a, 0x1b, 0x62, 0x75, 0x66, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76,
	0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x1e,
	0x0a, 0x06, 0x42, 0x69, 0x67, 0x49, 0x6e, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x97,
	0x01, 0x0a, 0x05, 0x41, 0x73, 0x73, 0x65, 0x74, 0x12, 0x37, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72,
	0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x1d, 0xba, 0x48, 0x1a, 0x72, 0x18,
	0x32, 0x13, 0x5e, 0x30, 0x78, 0x5b, 0x61, 0x2d, 0x66, 0x41, 0x2d, 0x46, 0x30, 0x2d, 0x39, 0x5d,
	0x7b, 0x34, 0x30, 0x7d, 0x24, 0x98, 0x01, 0x2a, 0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73,
	0x73, 0x12, 0x28, 0x0a, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x10, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x76, 0x31, 0x2e, 0x42, 0x69, 0x67,
	0x49, 0x6e, 0x74, 0x52, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x2b, 0x0a, 0x08, 0x63,
	0x68, 0x61, 0x69, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x76, 0x31, 0x2e, 0x42, 0x69, 0x67, 0x49, 0x6e, 0x74, 0x52,
	0x07, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x49, 0x64, 0x22, 0x94, 0x01, 0x0a, 0x05, 0x53, 0x74, 0x61,
	0x6b, 0x65, 0x12, 0x34, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x42, 0x1a, 0xba, 0x48, 0x17, 0x72, 0x15, 0x32, 0x13, 0x5e, 0x30, 0x78, 0x5b,
	0x61, 0x2d, 0x66, 0x41, 0x2d, 0x46, 0x30, 0x2d, 0x39, 0x5d, 0x7b, 0x34, 0x30, 0x7d, 0x24, 0x52,
	0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x28, 0x0a, 0x06, 0x61, 0x6d, 0x6f, 0x75,
	0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2e, 0x76, 0x31, 0x2e, 0x42, 0x69, 0x67, 0x49, 0x6e, 0x74, 0x52, 0x06, 0x61, 0x6d, 0x6f, 0x75,
	0x6e, 0x74, 0x12, 0x2b, 0x0a, 0x08, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x76, 0x31, 0x2e,
	0x42, 0x69, 0x67, 0x49, 0x6e, 0x74, 0x52, 0x07, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x49, 0x64, 0x22,
	0xcb, 0x01, 0x0a, 0x04, 0x4c, 0x6f, 0x61, 0x6e, 0x12, 0x33, 0x0a, 0x05, 0x61, 0x73, 0x73, 0x65,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x1d, 0xba, 0x48, 0x1a, 0x72, 0x18, 0x32, 0x13,
	0x5e, 0x30, 0x78, 0x5b, 0x61, 0x2d, 0x66, 0x41, 0x2d, 0x46, 0x30, 0x2d, 0x39, 0x5d, 0x7b, 0x34,
	0x30, 0x7d, 0x24, 0x98, 0x01, 0x2a, 0x52, 0x05, 0x61, 0x73, 0x73, 0x65, 0x74, 0x12, 0x28, 0x0a,
	0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x76, 0x31, 0x2e, 0x42, 0x69, 0x67, 0x49, 0x6e, 0x74, 0x52,
	0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x37, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65,
	0x73, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x42, 0x1d, 0xba, 0x48, 0x1a, 0x72, 0x18, 0x32,
	0x13, 0x5e, 0x30, 0x78, 0x5b, 0x61, 0x2d, 0x66, 0x41, 0x2d, 0x46, 0x30, 0x2d, 0x39, 0x5d, 0x7b,
	0x34, 0x30, 0x7d, 0x24, 0x98, 0x01, 0x2a, 0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
	0x12, 0x2b, 0x0a, 0x08, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x10, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x76, 0x31, 0x2e, 0x42, 0x69,
	0x67, 0x49, 0x6e, 0x74, 0x52, 0x07, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x49, 0x64, 0x22, 0x56, 0x0a,
	0x09, 0x45, 0x78, 0x74, 0x72, 0x61, 0x44, 0x61, 0x74, 0x61, 0x12, 0x49, 0x0a, 0x12, 0x70, 0x61,
	0x72, 0x74, 0x69, 0x61, 0x6c, 0x6c, 0x79, 0x5f, 0x66, 0x69, 0x6c, 0x6c, 0x61, 0x62, 0x6c, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x42, 0x6f, 0x6f, 0x6c, 0x56, 0x61, 0x6c,
	0x75, 0x65, 0x52, 0x11, 0x70, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x6c, 0x79, 0x46, 0x69, 0x6c,
	0x6c, 0x61, 0x62, 0x6c, 0x65, 0x22, 0xbb, 0x05, 0x0a, 0x06, 0x49, 0x6e, 0x74, 0x65, 0x6e, 0x74,
	0x12, 0x2f, 0x0a, 0x09, 0x66, 0x72, 0x6f, 0x6d, 0x41, 0x73, 0x73, 0x65, 0x74, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x76, 0x31, 0x2e, 0x41,
	0x73, 0x73, 0x65, 0x74, 0x48, 0x00, 0x52, 0x09, 0x66, 0x72, 0x6f, 0x6d, 0x41, 0x73, 0x73, 0x65,
	0x74, 0x12, 0x2f, 0x0a, 0x09, 0x66, 0x72, 0x6f, 0x6d, 0x53, 0x74, 0x61, 0x6b, 0x65, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x76, 0x31, 0x2e,
	0x53, 0x74, 0x61, 0x6b, 0x65, 0x48, 0x00, 0x52, 0x09, 0x66, 0x72, 0x6f, 0x6d, 0x53, 0x74, 0x61,
	0x6b, 0x65, 0x12, 0x2c, 0x0a, 0x08, 0x66, 0x72, 0x6f, 0x6d, 0x4c, 0x6f, 0x61, 0x6e, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x76, 0x31, 0x2e,
	0x4c, 0x6f, 0x61, 0x6e, 0x48, 0x00, 0x52, 0x08, 0x66, 0x72, 0x6f, 0x6d, 0x4c, 0x6f, 0x61, 0x6e,
	0x12, 0x2b, 0x0a, 0x07, 0x74, 0x6f, 0x41, 0x73, 0x73, 0x65, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x0f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x73, 0x73,
	0x65, 0x74, 0x48, 0x01, 0x52, 0x07, 0x74, 0x6f, 0x41, 0x73, 0x73, 0x65, 0x74, 0x12, 0x2b, 0x0a,
	0x07, 0x74, 0x6f, 0x53, 0x74, 0x61, 0x6b, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x74, 0x61, 0x6b, 0x65, 0x48,
	0x01, 0x52, 0x07, 0x74, 0x6f, 0x53, 0x74, 0x61, 0x6b, 0x65, 0x12, 0x28, 0x0a, 0x06, 0x74, 0x6f,
	0x4c, 0x6f, 0x61, 0x6e, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x6f, 0x61, 0x6e, 0x48, 0x01, 0x52, 0x06, 0x74, 0x6f,
	0x4c, 0x6f, 0x61, 0x6e, 0x12, 0x3d, 0x0a, 0x09, 0x72, 0x65, 0x63, 0x69, 0x70, 0x69, 0x65, 0x6e,
	0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x42, 0x1a, 0xba, 0x48, 0x17, 0x72, 0x15, 0x32, 0x13,
	0x5e, 0x30, 0x78, 0x5b, 0x61, 0x2d, 0x66, 0x41, 0x2d, 0x46, 0x30, 0x2d, 0x39, 0x5d, 0x7b, 0x34,
	0x30, 0x7d, 0x24, 0x48, 0x02, 0x52, 0x09, 0x72, 0x65, 0x63, 0x69, 0x70, 0x69, 0x65, 0x6e, 0x74,
	0x88, 0x01, 0x01, 0x12, 0x32, 0x0a, 0x0a, 0x65, 0x78, 0x74, 0x72, 0x61, 0x5f, 0x64, 0x61, 0x74,
	0x61, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e,
	0x76, 0x31, 0x2e, 0x45, 0x78, 0x74, 0x72, 0x61, 0x44, 0x61, 0x74, 0x61, 0x52, 0x09, 0x65, 0x78,
	0x74, 0x72, 0x61, 0x44, 0x61, 0x74, 0x61, 0x12, 0x32, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x1a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e,
	0x76, 0x31, 0x2e, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x98, 0x01, 0x0a, 0x0a,
	0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x5d, 0xba, 0x48,
	0x5a, 0xba, 0x01, 0x57, 0x0a, 0x14, 0x62, 0x6c, 0x6e, 0x64, 0x67, 0x73, 0x2e, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x5f, 0x67, 0x74, 0x65, 0x1a, 0x3f, 0x74, 0x68, 0x69, 0x73,
	0x20, 0x3e, 0x3d, 0x20, 0x6e, 0x6f, 0x77, 0x20, 0x3f, 0x20, 0x27, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x62, 0x65, 0x20, 0x67, 0x72, 0x65, 0x61, 0x74, 0x65, 0x72,
	0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x6f, 0x72, 0x20, 0x65, 0x71, 0x75, 0x61, 0x6c, 0x20, 0x74,
	0x6f, 0x20, 0x6e, 0x6f, 0x77, 0x27, 0x20, 0x3a, 0x20, 0x27, 0x27, 0x52, 0x09, 0x63, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x3f, 0x0a, 0x0d, 0x65, 0x78, 0x70, 0x69, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x61, 0x74, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0c, 0x65, 0x78, 0x70, 0x69, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x74, 0x42, 0x06, 0x0a, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x42,
	0x04, 0x0a, 0x02, 0x74, 0x6f, 0x42, 0x0c, 0x0a, 0x0a, 0x5f, 0x72, 0x65, 0x63, 0x69, 0x70, 0x69,
	0x65, 0x6e, 0x74, 0x22, 0x3c, 0x0a, 0x04, 0x42, 0x6f, 0x64, 0x79, 0x12, 0x34, 0x0a, 0x07, 0x69,
	0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x76, 0x31, 0x2e, 0x49, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x42, 0x08,
	0xba, 0x48, 0x05, 0x92, 0x01, 0x02, 0x08, 0x01, 0x52, 0x07, 0x69, 0x6e, 0x74, 0x65, 0x6e, 0x74,
	0x73, 0x2a, 0xbe, 0x02, 0x0a, 0x10, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x69, 0x6e, 0x67,
	0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x21, 0x0a, 0x1d, 0x50, 0x52, 0x4f, 0x43, 0x45, 0x53,
	0x53, 0x49, 0x4e, 0x47, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x55, 0x4e, 0x53, 0x50,
	0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x1e, 0x0a, 0x1a, 0x50, 0x52, 0x4f,
	0x43, 0x45, 0x53, 0x53, 0x49, 0x4e, 0x47, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x52,
	0x45, 0x43, 0x45, 0x49, 0x56, 0x45, 0x44, 0x10, 0x01, 0x12, 0x24, 0x0a, 0x20, 0x50, 0x52, 0x4f,
	0x43, 0x45, 0x53, 0x53, 0x49, 0x4e, 0x47, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x53,
	0x45, 0x4e, 0x54, 0x5f, 0x54, 0x4f, 0x5f, 0x53, 0x4f, 0x4c, 0x56, 0x45, 0x52, 0x10, 0x02, 0x12,
	0x1c, 0x0a, 0x18, 0x50, 0x52, 0x4f, 0x43, 0x45, 0x53, 0x53, 0x49, 0x4e, 0x47, 0x5f, 0x53, 0x54,
	0x41, 0x54, 0x55, 0x53, 0x5f, 0x53, 0x4f, 0x4c, 0x56, 0x45, 0x44, 0x10, 0x03, 0x12, 0x1e, 0x0a,
	0x1a, 0x50, 0x52, 0x4f, 0x43, 0x45, 0x53, 0x53, 0x49, 0x4e, 0x47, 0x5f, 0x53, 0x54, 0x41, 0x54,
	0x55, 0x53, 0x5f, 0x55, 0x4e, 0x53, 0x4f, 0x4c, 0x56, 0x45, 0x44, 0x10, 0x04, 0x12, 0x1d, 0x0a,
	0x19, 0x50, 0x52, 0x4f, 0x43, 0x45, 0x53, 0x53, 0x49, 0x4e, 0x47, 0x5f, 0x53, 0x54, 0x41, 0x54,
	0x55, 0x53, 0x5f, 0x45, 0x58, 0x50, 0x49, 0x52, 0x45, 0x44, 0x10, 0x05, 0x12, 0x1e, 0x0a, 0x1a,
	0x50, 0x52, 0x4f, 0x43, 0x45, 0x53, 0x53, 0x49, 0x4e, 0x47, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55,
	0x53, 0x5f, 0x4f, 0x4e, 0x5f, 0x43, 0x48, 0x41, 0x49, 0x4e, 0x10, 0x06, 0x12, 0x1d, 0x0a, 0x19,
	0x50, 0x52, 0x4f, 0x43, 0x45, 0x53, 0x53, 0x49, 0x4e, 0x47, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55,
	0x53, 0x5f, 0x49, 0x4e, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x10, 0x07, 0x12, 0x25, 0x0a, 0x21, 0x50,
	0x52, 0x4f, 0x43, 0x45, 0x53, 0x53, 0x49, 0x4e, 0x47, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53,
	0x5f, 0x4f, 0x4e, 0x5f, 0x43, 0x48, 0x41, 0x49, 0x4e, 0x5f, 0x52, 0x45, 0x56, 0x45, 0x52, 0x54,
	0x10, 0x08, 0x42, 0x8c, 0x01, 0x0a, 0x0c, 0x63, 0x6f, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2e, 0x76, 0x31, 0x42, 0x0a, 0x41, 0x73, 0x73, 0x65, 0x74, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50,
	0x01, 0x5a, 0x2f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x6c,
	0x6e, 0x64, 0x67, 0x73, 0x2f, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x67,
	0x6f, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x76, 0x31, 0x3b, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x76, 0x31, 0xa2, 0x02, 0x03, 0x50, 0x58, 0x58, 0xaa, 0x02, 0x08, 0x50, 0x72, 0x6f, 0x74, 0x6f,
	0x2e, 0x56, 0x31, 0xca, 0x02, 0x08, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x5c, 0x56, 0x31, 0xe2, 0x02,
	0x14, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x5c, 0x56, 0x31, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x09, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x3a, 0x3a, 0x56,
	0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_v1_asset_proto_rawDescOnce sync.Once
	file_proto_v1_asset_proto_rawDescData = file_proto_v1_asset_proto_rawDesc
)

func file_proto_v1_asset_proto_rawDescGZIP() []byte {
	file_proto_v1_asset_proto_rawDescOnce.Do(func() {
		file_proto_v1_asset_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_v1_asset_proto_rawDescData)
	})
	return file_proto_v1_asset_proto_rawDescData
}

var file_proto_v1_asset_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_proto_v1_asset_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_proto_v1_asset_proto_goTypes = []interface{}{
	(ProcessingStatus)(0),         // 0: proto.v1.ProcessingStatus
	(*BigInt)(nil),                // 1: proto.v1.BigInt
	(*Asset)(nil),                 // 2: proto.v1.Asset
	(*Stake)(nil),                 // 3: proto.v1.Stake
	(*Loan)(nil),                  // 4: proto.v1.Loan
	(*ExtraData)(nil),             // 5: proto.v1.ExtraData
	(*Intent)(nil),                // 6: proto.v1.Intent
	(*Body)(nil),                  // 7: proto.v1.Body
	(*wrapperspb.BoolValue)(nil),  // 8: google.protobuf.BoolValue
	(*timestamppb.Timestamp)(nil), // 9: google.protobuf.Timestamp
}
var file_proto_v1_asset_proto_depIdxs = []int32{
	1,  // 0: proto.v1.Asset.amount:type_name -> proto.v1.BigInt
	1,  // 1: proto.v1.Asset.chain_id:type_name -> proto.v1.BigInt
	1,  // 2: proto.v1.Stake.amount:type_name -> proto.v1.BigInt
	1,  // 3: proto.v1.Stake.chain_id:type_name -> proto.v1.BigInt
	1,  // 4: proto.v1.Loan.amount:type_name -> proto.v1.BigInt
	1,  // 5: proto.v1.Loan.chain_id:type_name -> proto.v1.BigInt
	8,  // 6: proto.v1.ExtraData.partially_fillable:type_name -> google.protobuf.BoolValue
	2,  // 7: proto.v1.Intent.fromAsset:type_name -> proto.v1.Asset
	3,  // 8: proto.v1.Intent.fromStake:type_name -> proto.v1.Stake
	4,  // 9: proto.v1.Intent.fromLoan:type_name -> proto.v1.Loan
	2,  // 10: proto.v1.Intent.toAsset:type_name -> proto.v1.Asset
	3,  // 11: proto.v1.Intent.toStake:type_name -> proto.v1.Stake
	4,  // 12: proto.v1.Intent.toLoan:type_name -> proto.v1.Loan
	5,  // 13: proto.v1.Intent.extra_data:type_name -> proto.v1.ExtraData
	0,  // 14: proto.v1.Intent.status:type_name -> proto.v1.ProcessingStatus
	9,  // 15: proto.v1.Intent.created_at:type_name -> google.protobuf.Timestamp
	9,  // 16: proto.v1.Intent.expiration_at:type_name -> google.protobuf.Timestamp
	6,  // 17: proto.v1.Body.intents:type_name -> proto.v1.Intent
	18, // [18:18] is the sub-list for method output_type
	18, // [18:18] is the sub-list for method input_type
	18, // [18:18] is the sub-list for extension type_name
	18, // [18:18] is the sub-list for extension extendee
	0,  // [0:18] is the sub-list for field type_name
}

func init() { file_proto_v1_asset_proto_init() }
func file_proto_v1_asset_proto_init() {
	if File_proto_v1_asset_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_v1_asset_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BigInt); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_v1_asset_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Asset); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_v1_asset_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Stake); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_v1_asset_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Loan); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_v1_asset_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ExtraData); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_v1_asset_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Intent); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_v1_asset_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Body); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_proto_v1_asset_proto_msgTypes[5].OneofWrappers = []interface{}{
		(*Intent_FromAsset)(nil),
		(*Intent_FromStake)(nil),
		(*Intent_FromLoan)(nil),
		(*Intent_ToAsset)(nil),
		(*Intent_ToStake)(nil),
		(*Intent_ToLoan)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_v1_asset_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proto_v1_asset_proto_goTypes,
		DependencyIndexes: file_proto_v1_asset_proto_depIdxs,
		EnumInfos:         file_proto_v1_asset_proto_enumTypes,
		MessageInfos:      file_proto_v1_asset_proto_msgTypes,
	}.Build()
	File_proto_v1_asset_proto = out.File
	file_proto_v1_asset_proto_rawDesc = nil
	file_proto_v1_asset_proto_goTypes = nil
	file_proto_v1_asset_proto_depIdxs = nil
}
