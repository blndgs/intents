/* eslint-disable */
import _m0 from "protobufjs/minimal";
import { Timestamp } from "../../google/protobuf/timestamp";
import { BoolValue } from "../../google/protobuf/wrappers";

export const protobufPackage = "proto.v1";

/** Enum representing different types of assets. */
export enum AssetKind {
  /** ASSET_KIND_UNSPECIFIED - Default value, unspecified asset type. */
  ASSET_KIND_UNSPECIFIED = 0,
  /** ASSET_KIND_TOKEN - Token asset type. */
  ASSET_KIND_TOKEN = 1,
  /** ASSET_KIND_STAKE - Stake asset type. */
  ASSET_KIND_STAKE = 2,
  /** ASSET_KIND_LOAN - Loan asset type. */
  ASSET_KIND_LOAN = 3,
  UNRECOGNIZED = -1,
}

export function assetKindFromJSON(object: any): AssetKind {
  switch (object) {
    case 0:
    case "ASSET_KIND_UNSPECIFIED":
      return AssetKind.ASSET_KIND_UNSPECIFIED;
    case 1:
    case "ASSET_KIND_TOKEN":
      return AssetKind.ASSET_KIND_TOKEN;
    case 2:
    case "ASSET_KIND_STAKE":
      return AssetKind.ASSET_KIND_STAKE;
    case 3:
    case "ASSET_KIND_LOAN":
      return AssetKind.ASSET_KIND_LOAN;
    case -1:
    case "UNRECOGNIZED":
    default:
      return AssetKind.UNRECOGNIZED;
  }
}

export function assetKindToJSON(object: AssetKind): string {
  switch (object) {
    case AssetKind.ASSET_KIND_UNSPECIFIED:
      return "ASSET_KIND_UNSPECIFIED";
    case AssetKind.ASSET_KIND_TOKEN:
      return "ASSET_KIND_TOKEN";
    case AssetKind.ASSET_KIND_STAKE:
      return "ASSET_KIND_STAKE";
    case AssetKind.ASSET_KIND_LOAN:
      return "ASSET_KIND_LOAN";
    case AssetKind.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

/** Enum representing the processing status of an intent. */
export enum ProcessingStatus {
  /** PROCESSING_STATUS_UNSPECIFIED - Default value, unspecified processing status. */
  PROCESSING_STATUS_UNSPECIFIED = 0,
  /** PROCESSING_STATUS_RECEIVED - Intent has been received. */
  PROCESSING_STATUS_RECEIVED = 1,
  /** PROCESSING_STATUS_SENT_TO_SOLVER - Intent has been sent to the solver. */
  PROCESSING_STATUS_SENT_TO_SOLVER = 2,
  /** PROCESSING_STATUS_SOLVED - Intent has been solved. */
  PROCESSING_STATUS_SOLVED = 3,
  /** PROCESSING_STATUS_UNSOLVED - Intent remains unsolved. */
  PROCESSING_STATUS_UNSOLVED = 4,
  /** PROCESSING_STATUS_EXPIRED - Intent has expired. */
  PROCESSING_STATUS_EXPIRED = 5,
  /** PROCESSING_STATUS_ON_CHAIN - Intent is on the blockchain. */
  PROCESSING_STATUS_ON_CHAIN = 6,
  /** PROCESSING_STATUS_INVALID - Intent is invalid. */
  PROCESSING_STATUS_INVALID = 7,
  UNRECOGNIZED = -1,
}

export function processingStatusFromJSON(object: any): ProcessingStatus {
  switch (object) {
    case 0:
    case "PROCESSING_STATUS_UNSPECIFIED":
      return ProcessingStatus.PROCESSING_STATUS_UNSPECIFIED;
    case 1:
    case "PROCESSING_STATUS_RECEIVED":
      return ProcessingStatus.PROCESSING_STATUS_RECEIVED;
    case 2:
    case "PROCESSING_STATUS_SENT_TO_SOLVER":
      return ProcessingStatus.PROCESSING_STATUS_SENT_TO_SOLVER;
    case 3:
    case "PROCESSING_STATUS_SOLVED":
      return ProcessingStatus.PROCESSING_STATUS_SOLVED;
    case 4:
    case "PROCESSING_STATUS_UNSOLVED":
      return ProcessingStatus.PROCESSING_STATUS_UNSOLVED;
    case 5:
    case "PROCESSING_STATUS_EXPIRED":
      return ProcessingStatus.PROCESSING_STATUS_EXPIRED;
    case 6:
    case "PROCESSING_STATUS_ON_CHAIN":
      return ProcessingStatus.PROCESSING_STATUS_ON_CHAIN;
    case 7:
    case "PROCESSING_STATUS_INVALID":
      return ProcessingStatus.PROCESSING_STATUS_INVALID;
    case -1:
    case "UNRECOGNIZED":
    default:
      return ProcessingStatus.UNRECOGNIZED;
  }
}

export function processingStatusToJSON(object: ProcessingStatus): string {
  switch (object) {
    case ProcessingStatus.PROCESSING_STATUS_UNSPECIFIED:
      return "PROCESSING_STATUS_UNSPECIFIED";
    case ProcessingStatus.PROCESSING_STATUS_RECEIVED:
      return "PROCESSING_STATUS_RECEIVED";
    case ProcessingStatus.PROCESSING_STATUS_SENT_TO_SOLVER:
      return "PROCESSING_STATUS_SENT_TO_SOLVER";
    case ProcessingStatus.PROCESSING_STATUS_SOLVED:
      return "PROCESSING_STATUS_SOLVED";
    case ProcessingStatus.PROCESSING_STATUS_UNSOLVED:
      return "PROCESSING_STATUS_UNSOLVED";
    case ProcessingStatus.PROCESSING_STATUS_EXPIRED:
      return "PROCESSING_STATUS_EXPIRED";
    case ProcessingStatus.PROCESSING_STATUS_ON_CHAIN:
      return "PROCESSING_STATUS_ON_CHAIN";
    case ProcessingStatus.PROCESSING_STATUS_INVALID:
      return "PROCESSING_STATUS_INVALID";
    case ProcessingStatus.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

/** BigInt represents a large number */
export interface BigInt {
  value: Uint8Array;
}

/** Message representing the details of an asset. */
export interface AssetType {
  /** The type of the asset. */
  type: AssetKind;
  /** The address of the asset. */
  address: string;
  /**
   * The amount of the asset.
   * In cases of AssetType being used as the to field, it doesn't have to provided
   * and can be left empty
   */
  amount:
    | BigInt
    | undefined;
  /** The chain ID where the asset resides. */
  chainId: string;
}

/** Message representing the details of a stake. */
export interface StakeType {
  /** The type of the stake. */
  type: AssetKind;
  /** The address of the stake. */
  address: string;
  /** The amount of the stake. */
  amount:
    | BigInt
    | undefined;
  /** The chain ID where the asset resides. */
  chainId: string;
}

/** Message representing the details of a loan. */
export interface LoanType {
  /** The type of the loan. */
  type: AssetKind;
  /** The asset associated with the loan. */
  asset: string;
  /** The amount of the loan. */
  amount:
    | BigInt
    | undefined;
  /** The address associated with the loan. */
  address: string;
  /** The chain ID where the asset resides. */
  chainId: string;
}

/** Message representing additional data for an intent. */
export interface ExtraData {
  /** Indicates if the intent is partially fillable. */
  partiallyFillable: boolean | undefined;
}

/** Message representing an intent with various types of transactions. */
export interface Intent {
  /** The sender of the intent. */
  sender: string;
  /** The asset being sent. */
  fromAsset?:
    | AssetType
    | undefined;
  /** The stake being sent. */
  fromStake?:
    | StakeType
    | undefined;
  /** The loan being sent. */
  fromLoan?:
    | LoanType
    | undefined;
  /** The asset being received. */
  toAsset?:
    | AssetType
    | undefined;
  /** The stake being received. */
  toStake?:
    | StakeType
    | undefined;
  /** The loan being received. */
  toLoan?:
    | LoanType
    | undefined;
  /** Additional data for the intent. */
  extraData:
    | ExtraData
    | undefined;
  /** The processing status of the intent. */
  status: ProcessingStatus;
  /** The creation timestamp of the intent. */
  createdAt:
    | Date
    | undefined;
  /** when this intent expires */
  expirationAt: Date | undefined;
}

/** Message representing a body of intents. */
export interface Body {
  /** A list of intents. */
  intents: Intent[];
}

function createBaseBigInt(): BigInt {
  return { value: new Uint8Array(0) };
}

export const BigInt = {
  encode(message: BigInt, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.value.length !== 0) {
      writer.uint32(10).bytes(message.value);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): BigInt {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseBigInt();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.value = reader.bytes();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): BigInt {
    return { value: isSet(object.value) ? bytesFromBase64(object.value) : new Uint8Array(0) };
  },

  toJSON(message: BigInt): unknown {
    const obj: any = {};
    if (message.value.length !== 0) {
      obj.value = base64FromBytes(message.value);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<BigInt>, I>>(base?: I): BigInt {
    return BigInt.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<BigInt>, I>>(object: I): BigInt {
    const message = createBaseBigInt();
    message.value = object.value ?? new Uint8Array(0);
    return message;
  },
};

function createBaseAssetType(): AssetType {
  return { type: 0, address: "", amount: undefined, chainId: "" };
}

export const AssetType = {
  encode(message: AssetType, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.type !== 0) {
      writer.uint32(8).int32(message.type);
    }
    if (message.address !== "") {
      writer.uint32(18).string(message.address);
    }
    if (message.amount !== undefined) {
      BigInt.encode(message.amount, writer.uint32(26).fork()).ldelim();
    }
    if (message.chainId !== "") {
      writer.uint32(34).string(message.chainId);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): AssetType {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseAssetType();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 8) {
            break;
          }

          message.type = reader.int32() as any;
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.address = reader.string();
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.amount = BigInt.decode(reader, reader.uint32());
          continue;
        case 4:
          if (tag !== 34) {
            break;
          }

          message.chainId = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): AssetType {
    return {
      type: isSet(object.type) ? assetKindFromJSON(object.type) : 0,
      address: isSet(object.address) ? globalThis.String(object.address) : "",
      amount: isSet(object.amount) ? BigInt.fromJSON(object.amount) : undefined,
      chainId: isSet(object.chainId) ? globalThis.String(object.chainId) : "",
    };
  },

  toJSON(message: AssetType): unknown {
    const obj: any = {};
    if (message.type !== 0) {
      obj.type = assetKindToJSON(message.type);
    }
    if (message.address !== "") {
      obj.address = message.address;
    }
    if (message.amount !== undefined) {
      obj.amount = BigInt.toJSON(message.amount);
    }
    if (message.chainId !== "") {
      obj.chainId = message.chainId;
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<AssetType>, I>>(base?: I): AssetType {
    return AssetType.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<AssetType>, I>>(object: I): AssetType {
    const message = createBaseAssetType();
    message.type = object.type ?? 0;
    message.address = object.address ?? "";
    message.amount = (object.amount !== undefined && object.amount !== null)
      ? BigInt.fromPartial(object.amount)
      : undefined;
    message.chainId = object.chainId ?? "";
    return message;
  },
};

function createBaseStakeType(): StakeType {
  return { type: 0, address: "", amount: undefined, chainId: "" };
}

export const StakeType = {
  encode(message: StakeType, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.type !== 0) {
      writer.uint32(8).int32(message.type);
    }
    if (message.address !== "") {
      writer.uint32(18).string(message.address);
    }
    if (message.amount !== undefined) {
      BigInt.encode(message.amount, writer.uint32(26).fork()).ldelim();
    }
    if (message.chainId !== "") {
      writer.uint32(34).string(message.chainId);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): StakeType {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseStakeType();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 8) {
            break;
          }

          message.type = reader.int32() as any;
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.address = reader.string();
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.amount = BigInt.decode(reader, reader.uint32());
          continue;
        case 4:
          if (tag !== 34) {
            break;
          }

          message.chainId = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): StakeType {
    return {
      type: isSet(object.type) ? assetKindFromJSON(object.type) : 0,
      address: isSet(object.address) ? globalThis.String(object.address) : "",
      amount: isSet(object.amount) ? BigInt.fromJSON(object.amount) : undefined,
      chainId: isSet(object.chainId) ? globalThis.String(object.chainId) : "",
    };
  },

  toJSON(message: StakeType): unknown {
    const obj: any = {};
    if (message.type !== 0) {
      obj.type = assetKindToJSON(message.type);
    }
    if (message.address !== "") {
      obj.address = message.address;
    }
    if (message.amount !== undefined) {
      obj.amount = BigInt.toJSON(message.amount);
    }
    if (message.chainId !== "") {
      obj.chainId = message.chainId;
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<StakeType>, I>>(base?: I): StakeType {
    return StakeType.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<StakeType>, I>>(object: I): StakeType {
    const message = createBaseStakeType();
    message.type = object.type ?? 0;
    message.address = object.address ?? "";
    message.amount = (object.amount !== undefined && object.amount !== null)
      ? BigInt.fromPartial(object.amount)
      : undefined;
    message.chainId = object.chainId ?? "";
    return message;
  },
};

function createBaseLoanType(): LoanType {
  return { type: 0, asset: "", amount: undefined, address: "", chainId: "" };
}

export const LoanType = {
  encode(message: LoanType, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.type !== 0) {
      writer.uint32(8).int32(message.type);
    }
    if (message.asset !== "") {
      writer.uint32(18).string(message.asset);
    }
    if (message.amount !== undefined) {
      BigInt.encode(message.amount, writer.uint32(26).fork()).ldelim();
    }
    if (message.address !== "") {
      writer.uint32(34).string(message.address);
    }
    if (message.chainId !== "") {
      writer.uint32(42).string(message.chainId);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): LoanType {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseLoanType();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 8) {
            break;
          }

          message.type = reader.int32() as any;
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.asset = reader.string();
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.amount = BigInt.decode(reader, reader.uint32());
          continue;
        case 4:
          if (tag !== 34) {
            break;
          }

          message.address = reader.string();
          continue;
        case 5:
          if (tag !== 42) {
            break;
          }

          message.chainId = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): LoanType {
    return {
      type: isSet(object.type) ? assetKindFromJSON(object.type) : 0,
      asset: isSet(object.asset) ? globalThis.String(object.asset) : "",
      amount: isSet(object.amount) ? BigInt.fromJSON(object.amount) : undefined,
      address: isSet(object.address) ? globalThis.String(object.address) : "",
      chainId: isSet(object.chainId) ? globalThis.String(object.chainId) : "",
    };
  },

  toJSON(message: LoanType): unknown {
    const obj: any = {};
    if (message.type !== 0) {
      obj.type = assetKindToJSON(message.type);
    }
    if (message.asset !== "") {
      obj.asset = message.asset;
    }
    if (message.amount !== undefined) {
      obj.amount = BigInt.toJSON(message.amount);
    }
    if (message.address !== "") {
      obj.address = message.address;
    }
    if (message.chainId !== "") {
      obj.chainId = message.chainId;
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<LoanType>, I>>(base?: I): LoanType {
    return LoanType.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<LoanType>, I>>(object: I): LoanType {
    const message = createBaseLoanType();
    message.type = object.type ?? 0;
    message.asset = object.asset ?? "";
    message.amount = (object.amount !== undefined && object.amount !== null)
      ? BigInt.fromPartial(object.amount)
      : undefined;
    message.address = object.address ?? "";
    message.chainId = object.chainId ?? "";
    return message;
  },
};

function createBaseExtraData(): ExtraData {
  return { partiallyFillable: undefined };
}

export const ExtraData = {
  encode(message: ExtraData, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.partiallyFillable !== undefined) {
      BoolValue.encode({ value: message.partiallyFillable! }, writer.uint32(10).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): ExtraData {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseExtraData();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.partiallyFillable = BoolValue.decode(reader, reader.uint32()).value;
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): ExtraData {
    return { partiallyFillable: isSet(object.partiallyFillable) ? Boolean(object.partiallyFillable) : undefined };
  },

  toJSON(message: ExtraData): unknown {
    const obj: any = {};
    if (message.partiallyFillable !== undefined) {
      obj.partiallyFillable = message.partiallyFillable;
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<ExtraData>, I>>(base?: I): ExtraData {
    return ExtraData.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<ExtraData>, I>>(object: I): ExtraData {
    const message = createBaseExtraData();
    message.partiallyFillable = object.partiallyFillable ?? undefined;
    return message;
  },
};

function createBaseIntent(): Intent {
  return {
    sender: "",
    fromAsset: undefined,
    fromStake: undefined,
    fromLoan: undefined,
    toAsset: undefined,
    toStake: undefined,
    toLoan: undefined,
    extraData: undefined,
    status: 0,
    createdAt: undefined,
    expirationAt: undefined,
  };
}

export const Intent = {
  encode(message: Intent, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.sender !== "") {
      writer.uint32(10).string(message.sender);
    }
    if (message.fromAsset !== undefined) {
      AssetType.encode(message.fromAsset, writer.uint32(18).fork()).ldelim();
    }
    if (message.fromStake !== undefined) {
      StakeType.encode(message.fromStake, writer.uint32(26).fork()).ldelim();
    }
    if (message.fromLoan !== undefined) {
      LoanType.encode(message.fromLoan, writer.uint32(34).fork()).ldelim();
    }
    if (message.toAsset !== undefined) {
      AssetType.encode(message.toAsset, writer.uint32(42).fork()).ldelim();
    }
    if (message.toStake !== undefined) {
      StakeType.encode(message.toStake, writer.uint32(50).fork()).ldelim();
    }
    if (message.toLoan !== undefined) {
      LoanType.encode(message.toLoan, writer.uint32(58).fork()).ldelim();
    }
    if (message.extraData !== undefined) {
      ExtraData.encode(message.extraData, writer.uint32(66).fork()).ldelim();
    }
    if (message.status !== 0) {
      writer.uint32(72).int32(message.status);
    }
    if (message.createdAt !== undefined) {
      Timestamp.encode(toTimestamp(message.createdAt), writer.uint32(82).fork()).ldelim();
    }
    if (message.expirationAt !== undefined) {
      Timestamp.encode(toTimestamp(message.expirationAt), writer.uint32(90).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): Intent {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseIntent();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.sender = reader.string();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.fromAsset = AssetType.decode(reader, reader.uint32());
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.fromStake = StakeType.decode(reader, reader.uint32());
          continue;
        case 4:
          if (tag !== 34) {
            break;
          }

          message.fromLoan = LoanType.decode(reader, reader.uint32());
          continue;
        case 5:
          if (tag !== 42) {
            break;
          }

          message.toAsset = AssetType.decode(reader, reader.uint32());
          continue;
        case 6:
          if (tag !== 50) {
            break;
          }

          message.toStake = StakeType.decode(reader, reader.uint32());
          continue;
        case 7:
          if (tag !== 58) {
            break;
          }

          message.toLoan = LoanType.decode(reader, reader.uint32());
          continue;
        case 8:
          if (tag !== 66) {
            break;
          }

          message.extraData = ExtraData.decode(reader, reader.uint32());
          continue;
        case 9:
          if (tag !== 72) {
            break;
          }

          message.status = reader.int32() as any;
          continue;
        case 10:
          if (tag !== 82) {
            break;
          }

          message.createdAt = fromTimestamp(Timestamp.decode(reader, reader.uint32()));
          continue;
        case 11:
          if (tag !== 90) {
            break;
          }

          message.expirationAt = fromTimestamp(Timestamp.decode(reader, reader.uint32()));
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): Intent {
    return {
      sender: isSet(object.sender) ? globalThis.String(object.sender) : "",
      fromAsset: isSet(object.fromAsset) ? AssetType.fromJSON(object.fromAsset) : undefined,
      fromStake: isSet(object.fromStake) ? StakeType.fromJSON(object.fromStake) : undefined,
      fromLoan: isSet(object.fromLoan) ? LoanType.fromJSON(object.fromLoan) : undefined,
      toAsset: isSet(object.toAsset) ? AssetType.fromJSON(object.toAsset) : undefined,
      toStake: isSet(object.toStake) ? StakeType.fromJSON(object.toStake) : undefined,
      toLoan: isSet(object.toLoan) ? LoanType.fromJSON(object.toLoan) : undefined,
      extraData: isSet(object.extraData) ? ExtraData.fromJSON(object.extraData) : undefined,
      status: isSet(object.status) ? processingStatusFromJSON(object.status) : 0,
      createdAt: isSet(object.createdAt) ? fromJsonTimestamp(object.createdAt) : undefined,
      expirationAt: isSet(object.expirationAt) ? fromJsonTimestamp(object.expirationAt) : undefined,
    };
  },

  toJSON(message: Intent): unknown {
    const obj: any = {};
    if (message.sender !== "") {
      obj.sender = message.sender;
    }
    if (message.fromAsset !== undefined) {
      obj.fromAsset = AssetType.toJSON(message.fromAsset);
    }
    if (message.fromStake !== undefined) {
      obj.fromStake = StakeType.toJSON(message.fromStake);
    }
    if (message.fromLoan !== undefined) {
      obj.fromLoan = LoanType.toJSON(message.fromLoan);
    }
    if (message.toAsset !== undefined) {
      obj.toAsset = AssetType.toJSON(message.toAsset);
    }
    if (message.toStake !== undefined) {
      obj.toStake = StakeType.toJSON(message.toStake);
    }
    if (message.toLoan !== undefined) {
      obj.toLoan = LoanType.toJSON(message.toLoan);
    }
    if (message.extraData !== undefined) {
      obj.extraData = ExtraData.toJSON(message.extraData);
    }
    if (message.status !== 0) {
      obj.status = processingStatusToJSON(message.status);
    }
    if (message.createdAt !== undefined) {
      obj.createdAt = message.createdAt.toISOString();
    }
    if (message.expirationAt !== undefined) {
      obj.expirationAt = message.expirationAt.toISOString();
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<Intent>, I>>(base?: I): Intent {
    return Intent.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<Intent>, I>>(object: I): Intent {
    const message = createBaseIntent();
    message.sender = object.sender ?? "";
    message.fromAsset = (object.fromAsset !== undefined && object.fromAsset !== null)
      ? AssetType.fromPartial(object.fromAsset)
      : undefined;
    message.fromStake = (object.fromStake !== undefined && object.fromStake !== null)
      ? StakeType.fromPartial(object.fromStake)
      : undefined;
    message.fromLoan = (object.fromLoan !== undefined && object.fromLoan !== null)
      ? LoanType.fromPartial(object.fromLoan)
      : undefined;
    message.toAsset = (object.toAsset !== undefined && object.toAsset !== null)
      ? AssetType.fromPartial(object.toAsset)
      : undefined;
    message.toStake = (object.toStake !== undefined && object.toStake !== null)
      ? StakeType.fromPartial(object.toStake)
      : undefined;
    message.toLoan = (object.toLoan !== undefined && object.toLoan !== null)
      ? LoanType.fromPartial(object.toLoan)
      : undefined;
    message.extraData = (object.extraData !== undefined && object.extraData !== null)
      ? ExtraData.fromPartial(object.extraData)
      : undefined;
    message.status = object.status ?? 0;
    message.createdAt = object.createdAt ?? undefined;
    message.expirationAt = object.expirationAt ?? undefined;
    return message;
  },
};

function createBaseBody(): Body {
  return { intents: [] };
}

export const Body = {
  encode(message: Body, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    for (const v of message.intents) {
      Intent.encode(v!, writer.uint32(10).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): Body {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseBody();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.intents.push(Intent.decode(reader, reader.uint32()));
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): Body {
    return {
      intents: globalThis.Array.isArray(object?.intents) ? object.intents.map((e: any) => Intent.fromJSON(e)) : [],
    };
  },

  toJSON(message: Body): unknown {
    const obj: any = {};
    if (message.intents?.length) {
      obj.intents = message.intents.map((e) => Intent.toJSON(e));
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<Body>, I>>(base?: I): Body {
    return Body.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<Body>, I>>(object: I): Body {
    const message = createBaseBody();
    message.intents = object.intents?.map((e) => Intent.fromPartial(e)) || [];
    return message;
  },
};

function bytesFromBase64(b64: string): Uint8Array {
  if ((globalThis as any).Buffer) {
    return Uint8Array.from(globalThis.Buffer.from(b64, "base64"));
  } else {
    const bin = globalThis.atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; ++i) {
      arr[i] = bin.charCodeAt(i);
    }
    return arr;
  }
}

function base64FromBytes(arr: Uint8Array): string {
  if ((globalThis as any).Buffer) {
    return globalThis.Buffer.from(arr).toString("base64");
  } else {
    const bin: string[] = [];
    arr.forEach((byte) => {
      bin.push(globalThis.String.fromCharCode(byte));
    });
    return globalThis.btoa(bin.join(""));
  }
}

type Builtin = Date | Function | Uint8Array | string | number | boolean | undefined;

export type DeepPartial<T> = T extends Builtin ? T
  : T extends globalThis.Array<infer U> ? globalThis.Array<DeepPartial<U>>
  : T extends ReadonlyArray<infer U> ? ReadonlyArray<DeepPartial<U>>
  : T extends {} ? { [K in keyof T]?: DeepPartial<T[K]> }
  : Partial<T>;

type KeysOfUnion<T> = T extends T ? keyof T : never;
export type Exact<P, I extends P> = P extends Builtin ? P
  : P & { [K in keyof P]: Exact<P[K], I[K]> } & { [K in Exclude<keyof I, KeysOfUnion<P>>]: never };

function toTimestamp(date: Date): Timestamp {
  const seconds = Math.trunc(date.getTime() / 1_000);
  const nanos = (date.getTime() % 1_000) * 1_000_000;
  return { seconds, nanos };
}

function fromTimestamp(t: Timestamp): Date {
  let millis = (t.seconds || 0) * 1_000;
  millis += (t.nanos || 0) / 1_000_000;
  return new globalThis.Date(millis);
}

function fromJsonTimestamp(o: any): Date {
  if (o instanceof globalThis.Date) {
    return o;
  } else if (typeof o === "string") {
    return new globalThis.Date(o);
  } else {
    return fromTimestamp(Timestamp.fromJSON(o));
  }
}

function isSet(value: any): boolean {
  return value !== null && value !== undefined;
}
