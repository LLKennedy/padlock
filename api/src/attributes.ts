/**
 * Code generated by protoc-gen-tsjson. DO NOT EDIT.
 * versions:
 * 	protoc-gen-tsjson v0.5.3
 * 	protoc            v3.10.1
 * source: attributes.proto
 */


/** An enum */
export enum AttributeType {
	/** An enum value */
	CKA_UNDEFINED_UNKNOWN = 0,
	/** An enum value */
	CKA_CLASS = 1,
	/** An enum value */
	CKA_TOKEN = 2,
	/** An enum value */
	CKA_PRIVATE = 3,
	/** An enum value */
	CKA_LABEL = 4,
	/** An enum value */
	CKA_APPLICATION = 5,
	/** An enum value */
	CKA_VALUE = 6,
	/** An enum value */
	CKA_OBJECT_ID = 7,
	/** An enum value */
	CKA_CERTIFICATE_TYPE = 8,
	/** An enum value */
	CKA_ISSUER = 9,
	/** An enum value */
	CKA_SERIAL_NUMBER = 10,
	/** An enum value */
	CKA_AC_ISSUER = 11,
	/** An enum value */
	CKA_OWNER = 12,
	/** An enum value */
	CKA_ATTR_TYPES = 13,
	/** An enum value */
	CKA_TRUSTED = 14,
	/** An enum value */
	CKA_CERTIFICATE_CATEGORY = 15,
	/** An enum value */
	CKA_JAVA_MIDP_SECURITY_DOMAIN = 16,
	/** An enum value */
	CKA_URL = 17,
	/** An enum value */
	CKA_HASH_OF_SUBJECT_PUBLIC_KEY = 18,
	/** An enum value */
	CKA_HASH_OF_ISSUER_PUBLIC_KEY = 19,
	/** An enum value */
	CKA_NAME_HASH_ALGORITHM = 20,
	/** An enum value */
	CKA_CHECK_VALUE = 21,
	/** An enum value */
	CKA_KEY_TYPE = 22,
	/** An enum value */
	CKA_SUBJECT = 23,
	/** An enum value */
	CKA_ID = 24,
	/** An enum value */
	CKA_SENSITIVE = 25,
	/** An enum value */
	CKA_ENCRYPT = 26,
	/** An enum value */
	CKA_DECRYPT = 27,
	/** An enum value */
	CKA_WRAP = 28,
	/** An enum value */
	CKA_UNWRAP = 29,
	/** An enum value */
	CKA_SIGN = 30,
	/** An enum value */
	CKA_SIGN_RECOVER = 31,
	/** An enum value */
	CKA_VERIFY = 32,
	/** An enum value */
	CKA_VERIFY_RECOVER = 33,
	/** An enum value */
	CKA_DERIVE = 34,
	/** An enum value */
	CKA_START_DATE = 35,
	/** An enum value */
	CKA_END_DATE = 36,
	/** An enum value */
	CKA_MODULUS = 37,
	/** An enum value */
	CKA_MODULUS_BITS = 38,
	/** An enum value */
	CKA_PUBLIC_EXPONENT = 39,
	/** An enum value */
	CKA_PRIVATE_EXPONENT = 40,
	/** An enum value */
	CKA_PRIME_1 = 41,
	/** An enum value */
	CKA_PRIME_2 = 42,
	/** An enum value */
	CKA_EXPONENT_1 = 43,
	/** An enum value */
	CKA_EXPONENT_2 = 44,
	/** An enum value */
	CKA_COEFFICIENT = 45,
	/** An enum value */
	CKA_PUBLIC_KEY_INFO = 46,
	/** An enum value */
	CKA_PRIME = 47,
	/** An enum value */
	CKA_SUBPRIME = 48,
	/** An enum value */
	CKA_BASE = 49,
	/** An enum value */
	CKA_PRIME_BITS = 50,
	/** An enum value */
	CKA_SUBPRIME_BITS = 51,
	/** An enum value */
	CKA_SUB_PRIME_BITS = 52,
	/** An enum value */
	CKA_VALUE_BITS = 53,
	/** An enum value */
	CKA_VALUE_LEN = 54,
	/** An enum value */
	CKA_EXTRACTABLE = 55,
	/** An enum value */
	CKA_LOCAL = 56,
	/** An enum value */
	CKA_NEVER_EXTRACTABLE = 57,
	/** An enum value */
	CKA_ALWAYS_SENSITIVE = 58,
	/** An enum value */
	CKA_KEY_GEN_MECHANISM = 59,
	/** An enum value */
	CKA_MODIFIABLE = 60,
	/** An enum value */
	CKA_COPYABLE = 61,
	/** An enum value */
	CKA_DESTROYABLE = 62,
	/** An enum value */
	CKA_ECDSA_PARAMS = 63,
	/** An enum value */
	CKA_EC_PARAMS = 64,
	/** An enum value */
	CKA_EC_POINT = 65,
	/** An enum value */
	CKA_SECONDARY_AUTH = 66,
	/** An enum value */
	CKA_AUTH_PIN_FLAGS = 67,
	/** An enum value */
	CKA_ALWAYS_AUTHENTICATE = 68,
	/** An enum value */
	CKA_WRAP_WITH_TRUSTED = 69,
	/** An enum value */
	CKA_WRAP_TEMPLATE = 70,
	/** An enum value */
	CKA_UNWRAP_TEMPLATE = 71,
	/** An enum value */
	CKA_OTP_FORMAT = 72,
	/** An enum value */
	CKA_OTP_LENGTH = 73,
	/** An enum value */
	CKA_OTP_TIME_INTERVAL = 74,
	/** An enum value */
	CKA_OTP_USER_FRIENDLY_MODE = 75,
	/** An enum value */
	CKA_OTP_CHALLENGE_REQUIREMENT = 76,
	/** An enum value */
	CKA_OTP_TIME_REQUIREMENT = 77,
	/** An enum value */
	CKA_OTP_COUNTER_REQUIREMENT = 78,
	/** An enum value */
	CKA_OTP_PIN_REQUIREMENT = 79,
	/** An enum value */
	CKA_OTP_COUNTER = 80,
	/** An enum value */
	CKA_OTP_TIME = 81,
	/** An enum value */
	CKA_OTP_USER_IDENTIFIER = 82,
	/** An enum value */
	CKA_OTP_SERVICE_IDENTIFIER = 83,
	/** An enum value */
	CKA_OTP_SERVICE_LOGO = 84,
	/** An enum value */
	CKA_OTP_SERVICE_LOGO_TYPE = 85,
	/** An enum value */
	CKA_GOSTR3410_PARAMS = 86,
	/** An enum value */
	CKA_GOSTR3411_PARAMS = 87,
	/** An enum value */
	CKA_GOST28147_PARAMS = 88,
	/** An enum value */
	CKA_HW_FEATURE_TYPE = 89,
	/** An enum value */
	CKA_RESET_ON_INIT = 90,
	/** An enum value */
	CKA_HAS_RESET = 91,
	/** An enum value */
	CKA_PIXEL_X = 92,
	/** An enum value */
	CKA_PIXEL_Y = 93,
	/** An enum value */
	CKA_RESOLUTION = 94,
	/** An enum value */
	CKA_CHAR_ROWS = 95,
	/** An enum value */
	CKA_CHAR_COLUMNS = 96,
	/** An enum value */
	CKA_COLOR = 97,
	/** An enum value */
	CKA_BITS_PER_PIXEL = 98,
	/** An enum value */
	CKA_CHAR_SETS = 99,
	/** An enum value */
	CKA_ENCODING_METHODS = 100,
	/** An enum value */
	CKA_MIME_TYPES = 101,
	/** An enum value */
	CKA_MECHANISM_TYPE = 102,
	/** An enum value */
	CKA_REQUIRED_CMS_ATTRIBUTES = 103,
	/** An enum value */
	CKA_DEFAULT_CMS_ATTRIBUTES = 104,
	/** An enum value */
	CKA_SUPPORTED_CMS_ATTRIBUTES = 105,
	/** An enum value */
	CKA_ALLOWED_MECHANISMS = 106,
	/** An enum value */
	CKA_VENDOR_DEFINED = 107,
}

