/* eslint-disable */
import * as _m0 from "protobufjs/minimal";

export const protobufPackage = "proto.v1";

export enum AssetKind {
  ASSET_KIND_UNSPECIFIED = 0,
  ASSET_KIND_TOKEN = 1,
  ASSET_KIND_STAKE = 2,
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

export interface LoanType {
  type: AssetKind;
  asset: string;
  amount: string;
  address: string;
}

export interface AssetType {
  type: AssetKind;
  address: string;
  amount: string;
  chainId: string;
}

export interface StakeType {
  type: AssetKind;
  address: string;
  amount: string;
}

function createBaseLoanType(): LoanType {
  return { type: 0, asset: "", amount: "", address: "" };
}

export const LoanType = {
  encode(message: LoanType, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.type !== 0) {
      writer.uint32(8).int32(message.type);
    }
    if (message.asset !== "") {
      writer.uint32(18).string(message.asset);
    }
    if (message.amount !== "") {
      writer.uint32(26).string(message.amount);
    }
    if (message.address !== "") {
      writer.uint32(34).string(message.address);
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

          message.amount = reader.string();
          continue;
        case 4:
          if (tag !== 34) {
            break;
          }

          message.address = reader.string();
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
      amount: isSet(object.amount) ? globalThis.String(object.amount) : "",
      address: isSet(object.address) ? globalThis.String(object.address) : "",
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
    if (message.amount !== "") {
      obj.amount = message.amount;
    }
    if (message.address !== "") {
      obj.address = message.address;
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
    message.amount = object.amount ?? "";
    message.address = object.address ?? "";
    return message;
  },
};

function createBaseAssetType(): AssetType {
  return { type: 0, address: "", amount: "", chainId: "" };
}

export const AssetType = {
  encode(message: AssetType, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.type !== 0) {
      writer.uint32(8).int32(message.type);
    }
    if (message.address !== "") {
      writer.uint32(18).string(message.address);
    }
    if (message.amount !== "") {
      writer.uint32(26).string(message.amount);
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

          message.amount = reader.string();
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
      amount: isSet(object.amount) ? globalThis.String(object.amount) : "",
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
    if (message.amount !== "") {
      obj.amount = message.amount;
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
    message.amount = object.amount ?? "";
    message.chainId = object.chainId ?? "";
    return message;
  },
};

function createBaseStakeType(): StakeType {
  return { type: 0, address: "", amount: "" };
}

export const StakeType = {
  encode(message: StakeType, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.type !== 0) {
      writer.uint32(8).int32(message.type);
    }
    if (message.address !== "") {
      writer.uint32(18).string(message.address);
    }
    if (message.amount !== "") {
      writer.uint32(26).string(message.amount);
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

          message.amount = reader.string();
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
      amount: isSet(object.amount) ? globalThis.String(object.amount) : "",
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
    if (message.amount !== "") {
      obj.amount = message.amount;
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
    message.amount = object.amount ?? "";
    return message;
  },
};

type Builtin = Date | Function | Uint8Array | string | number | boolean | undefined;

export type DeepPartial<T> = T extends Builtin ? T
  : T extends globalThis.Array<infer U> ? globalThis.Array<DeepPartial<U>>
  : T extends ReadonlyArray<infer U> ? ReadonlyArray<DeepPartial<U>>
  : T extends {} ? { [K in keyof T]?: DeepPartial<T[K]> }
  : Partial<T>;

type KeysOfUnion<T> = T extends T ? keyof T : never;
export type Exact<P, I extends P> = P extends Builtin ? P
  : P & { [K in keyof P]: Exact<P[K], I[K]> } & { [K in Exclude<keyof I, KeysOfUnion<P>>]: never };

function isSet(value: any): boolean {
  return value !== null && value !== undefined;
}
