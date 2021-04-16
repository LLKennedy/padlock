import { AttributeType } from "@llkennedy/padlock-api";
import React from "react";
import { CKFalse, CKTrue, EncodeString } from "./util/Encode";

export interface Props {
	initial?: AttributeType;
	initialData?: Uint8Array | string | boolean;
	knownTypes: AttributeType[];
	defaultOverride?: boolean;
	onChange(type: AttributeType, value?: Uint8Array): Promise<void>;
}

export class State {
	selected: AttributeType = AttributeType.CKA_CLASS;
	dataType: DataType = DataType.RawBytes;
	data?: Uint8Array | string | boolean
	override: boolean = false;
}

const style: React.CSSProperties = {
	display: "inline-flex",
}

export class AttributeBuilder extends React.Component<Props, State> {
	constructor(props: Props) {
		super(props);
		let state = new State();
		if (props.initial !== undefined) {
			state.selected = props.initial;
			let matchingType = AttributeTypeKeys.get(state.selected);
			if (matchingType === undefined) matchingType = DataType.RawBytes;
			state.dataType = matchingType;
		}
		if (props.defaultOverride === true) {
			state.override = true;
		}
		this.state = state;
	}
	async omponentDidUpdate(prevProps: Props, prevState: State) {
		if (prevState.selected !== this.state.selected || this.state.data !== prevState.data) {
			let parsedType: Uint8Array | undefined;
			switch (typeof this.state.data) {
				case "undefined":
					parsedType = undefined;
					break;
				case "string":
					parsedType = EncodeString(this.state.data);
					break;
				case "boolean":
					parsedType = this.state.data ? CKTrue : CKFalse;
					break;
				case "object":
					parsedType = this.state.data;
					break;
				default:
					throw new Error("unsupported data type")
			}
			await this.props.onChange(this.state.selected, parsedType);
		}
	}
	changeType(newType: AttributeType) {
		let currentDT = this.state.dataType;
		let newDT = AttributeTypeKeys.get(newType);

	}
	toggleOverride() {
		const override = this.state.override;
		if (override) {

		}
		this.setState({
			override: !override
		})
	}
	render() {
		return <div style={style}>
			<input title="Show ALL types (I know what I'm doing)" type="checkbox" checked={this.state.override} onChange={() => {
				this.toggleOverride();
			}} />
			<select value={this.state.selected} onChange={async e => {
				let k: AttributeType = Number(e.target.value);
				let dt = AttributeTypeKeys.get(k);
				if (dt === undefined) dt = DataType.RawBytes;
				this.setState({
					dataType: dt,
					selected: k
				});
			}}>
				{
					(() => {
						for (let [key, _] of AttributeTypeKeys) {
							return <option key={key} value={key}>{`${AttributeType[key]}`}</option>
						}
					})()
				}
			</select>
			{(() => {
				return <input></input>
			})()}
		</div>
	}
}

enum DataType {
	RawBytes = 1,
	String = 2,
	Bool = 3,
	KeyType = 4,
	Class = 5,
}

export const AttributeTypeKeys: ReadonlyMap<AttributeType, DataType> = new Map([
	[AttributeType.CKA_CLASS, DataType.Class],
	[AttributeType.CKA_TOKEN, DataType.Bool],
	[AttributeType.CKA_PRIVATE, DataType.Bool],
	[AttributeType.CKA_LABEL, DataType.String],
	[AttributeType.CKA_APPLICATION, DataType.RawBytes],
	[AttributeType.CKA_VALUE, DataType.RawBytes],
	[AttributeType.CKA_OBJECT_ID, DataType.String],
	[AttributeType.CKA_CERTIFICATE_TYPE, DataType.RawBytes],
	[AttributeType.CKA_ISSUER, DataType.RawBytes],
	[AttributeType.CKA_SERIAL_NUMBER, DataType.RawBytes],
	[AttributeType.CKA_AC_ISSUER, DataType.RawBytes],
	[AttributeType.CKA_OWNER, DataType.RawBytes],
	[AttributeType.CKA_ATTR_TYPES, DataType.RawBytes],
	[AttributeType.CKA_TRUSTED, DataType.Bool],
	[AttributeType.CKA_CERTIFICATE_CATEGORY, DataType.RawBytes],
	[AttributeType.CKA_JAVA_MIDP_SECURITY_DOMAIN, DataType.RawBytes],
	[AttributeType.CKA_URL, DataType.RawBytes],
	[AttributeType.CKA_HASH_OF_SUBJECT_PUBLIC_KEY, DataType.RawBytes],
	[AttributeType.CKA_HASH_OF_ISSUER_PUBLIC_KEY, DataType.RawBytes],
	[AttributeType.CKA_NAME_HASH_ALGORITHM, DataType.RawBytes],
	[AttributeType.CKA_CHECK_VALUE, DataType.RawBytes],
	[AttributeType.CKA_KEY_TYPE, DataType.KeyType],
	[AttributeType.CKA_SUBJECT, DataType.RawBytes],
	[AttributeType.CKA_ID, DataType.RawBytes],
	[AttributeType.CKA_SENSITIVE, DataType.Bool],
	[AttributeType.CKA_ENCRYPT, DataType.Bool],
	[AttributeType.CKA_DECRYPT, DataType.Bool],
	[AttributeType.CKA_WRAP, DataType.Bool],
	[AttributeType.CKA_UNWRAP, DataType.Bool],
	[AttributeType.CKA_SIGN, DataType.Bool],
	[AttributeType.CKA_SIGN_RECOVER, DataType.Bool],
	[AttributeType.CKA_VERIFY, DataType.Bool],
	[AttributeType.CKA_VERIFY_RECOVER, DataType.Bool],
	[AttributeType.CKA_DERIVE, DataType.Bool],
	[AttributeType.CKA_START_DATE, DataType.RawBytes],
	[AttributeType.CKA_END_DATE, DataType.RawBytes],
	[AttributeType.CKA_MODULUS, DataType.RawBytes],
	[AttributeType.CKA_MODULUS_BITS, DataType.RawBytes],
	[AttributeType.CKA_PUBLIC_EXPONENT, DataType.RawBytes],
	[AttributeType.CKA_PRIVATE_EXPONENT, DataType.RawBytes],
	[AttributeType.CKA_PRIME_1, DataType.RawBytes],
	[AttributeType.CKA_PRIME_2, DataType.RawBytes],
	[AttributeType.CKA_EXPONENT_1, DataType.RawBytes],
	[AttributeType.CKA_EXPONENT_2, DataType.RawBytes],
	[AttributeType.CKA_COEFFICIENT, DataType.RawBytes],
	[AttributeType.CKA_PUBLIC_KEY_INFO, DataType.RawBytes],
	[AttributeType.CKA_PRIME, DataType.RawBytes],
	[AttributeType.CKA_SUBPRIME, DataType.RawBytes],
	[AttributeType.CKA_BASE, DataType.RawBytes],
	[AttributeType.CKA_PRIME_BITS, DataType.RawBytes],
	[AttributeType.CKA_SUBPRIME_BITS, DataType.RawBytes],
	[AttributeType.CKA_SUB_PRIME_BITS, DataType.RawBytes],
	[AttributeType.CKA_VALUE_BITS, DataType.RawBytes],
	[AttributeType.CKA_VALUE_LEN, DataType.RawBytes],
	[AttributeType.CKA_EXTRACTABLE, DataType.RawBytes],
	[AttributeType.CKA_LOCAL, DataType.RawBytes],
	[AttributeType.CKA_NEVER_EXTRACTABLE, DataType.RawBytes],
	[AttributeType.CKA_ALWAYS_SENSITIVE, DataType.RawBytes],
	[AttributeType.CKA_KEY_GEN_MECHANISM, DataType.RawBytes],
	[AttributeType.CKA_MODIFIABLE, DataType.RawBytes],
	[AttributeType.CKA_COPYABLE, DataType.RawBytes],
	[AttributeType.CKA_DESTROYABLE, DataType.RawBytes],
	[AttributeType.CKA_ECDSA_PARAMS, DataType.RawBytes],
	[AttributeType.CKA_EC_PARAMS, DataType.RawBytes],
	[AttributeType.CKA_EC_POINT, DataType.RawBytes],
	[AttributeType.CKA_SECONDARY_AUTH, DataType.RawBytes],
	[AttributeType.CKA_AUTH_PIN_FLAGS, DataType.RawBytes],
	[AttributeType.CKA_ALWAYS_AUTHENTICATE, DataType.RawBytes],
	[AttributeType.CKA_WRAP_WITH_TRUSTED, DataType.RawBytes],
	[AttributeType.CKA_WRAP_TEMPLATE, DataType.RawBytes],
	[AttributeType.CKA_UNWRAP_TEMPLATE, DataType.RawBytes],
	[AttributeType.CKA_OTP_FORMAT, DataType.RawBytes],
	[AttributeType.CKA_OTP_LENGTH, DataType.RawBytes],
	[AttributeType.CKA_OTP_TIME_INTERVAL, DataType.RawBytes],
	[AttributeType.CKA_OTP_USER_FRIENDLY_MODE, DataType.RawBytes],
	[AttributeType.CKA_OTP_CHALLENGE_REQUIREMENT, DataType.RawBytes],
	[AttributeType.CKA_OTP_TIME_REQUIREMENT, DataType.RawBytes],
	[AttributeType.CKA_OTP_COUNTER_REQUIREMENT, DataType.RawBytes],
	[AttributeType.CKA_OTP_PIN_REQUIREMENT, DataType.RawBytes],
	[AttributeType.CKA_OTP_COUNTER, DataType.RawBytes],
	[AttributeType.CKA_OTP_TIME, DataType.RawBytes],
	[AttributeType.CKA_OTP_USER_IDENTIFIER, DataType.RawBytes],
	[AttributeType.CKA_OTP_SERVICE_IDENTIFIER, DataType.RawBytes],
	[AttributeType.CKA_OTP_SERVICE_LOGO, DataType.RawBytes],
	[AttributeType.CKA_OTP_SERVICE_LOGO_TYPE, DataType.RawBytes],
	[AttributeType.CKA_GOSTR3410_PARAMS, DataType.RawBytes],
	[AttributeType.CKA_GOSTR3411_PARAMS, DataType.RawBytes],
	[AttributeType.CKA_GOST28147_PARAMS, DataType.RawBytes],
	[AttributeType.CKA_HW_FEATURE_TYPE, DataType.RawBytes],
	[AttributeType.CKA_RESET_ON_INIT, DataType.RawBytes],
	[AttributeType.CKA_HAS_RESET, DataType.RawBytes],
	[AttributeType.CKA_PIXEL_X, DataType.RawBytes],
	[AttributeType.CKA_PIXEL_Y, DataType.RawBytes],
	[AttributeType.CKA_RESOLUTION, DataType.RawBytes],
	[AttributeType.CKA_CHAR_ROWS, DataType.RawBytes],
	[AttributeType.CKA_CHAR_COLUMNS, DataType.RawBytes],
	[AttributeType.CKA_COLOR, DataType.RawBytes],
	[AttributeType.CKA_BITS_PER_PIXEL, DataType.RawBytes],
	[AttributeType.CKA_CHAR_SETS, DataType.RawBytes],
	[AttributeType.CKA_ENCODING_METHODS, DataType.RawBytes],
	[AttributeType.CKA_MIME_TYPES, DataType.RawBytes],
	[AttributeType.CKA_MECHANISM_TYPE, DataType.RawBytes],
	[AttributeType.CKA_REQUIRED_CMS_ATTRIBUTES, DataType.RawBytes],
	[AttributeType.CKA_DEFAULT_CMS_ATTRIBUTES, DataType.RawBytes],
	[AttributeType.CKA_SUPPORTED_CMS_ATTRIBUTES, DataType.RawBytes],
	[AttributeType.CKA_ALLOWED_MECHANISMS, DataType.RawBytes],
	[AttributeType.CKA_VENDOR_DEFINED, DataType.RawBytes],
])