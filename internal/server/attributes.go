package server

import (
	"log"

	"github.com/LLKennedy/padlock/api/padlockpb"
	"github.com/llkennedy/pkcs11"
)

// AttributesPBtoP11 converts multiple attributes to enums
func AttributesPBtoP11(attrs []*padlockpb.Attribute) []*pkcs11.Attribute {
	var template []*pkcs11.Attribute
	for _, attr := range attrs {
		template = append(template, pkcs11.NewAttribute(AttributePBtoP11(attr.GetType()), attr.GetValue()))
	}
	log.Println(template)
	return template
}

// AttributePBtoP11 converts attribute enums
func AttributePBtoP11(attr padlockpb.AttributeType) uint {
	converted := uint(0xFEFEFEFE) // invalid for everything
	switch attr {
	case padlockpb.AttributeType_CKA_CLASS:
		converted = pkcs11.CKA_CLASS
	case padlockpb.AttributeType_CKA_TOKEN:
		converted = pkcs11.CKA_TOKEN
	case padlockpb.AttributeType_CKA_PRIVATE:
		converted = pkcs11.CKA_PRIVATE
	case padlockpb.AttributeType_CKA_LABEL:
		converted = pkcs11.CKA_LABEL
	case padlockpb.AttributeType_CKA_APPLICATION:
		converted = pkcs11.CKA_APPLICATION
	case padlockpb.AttributeType_CKA_VALUE:
		converted = pkcs11.CKA_VALUE
	case padlockpb.AttributeType_CKA_OBJECT_ID:
		converted = pkcs11.CKA_OBJECT_ID
	case padlockpb.AttributeType_CKA_CERTIFICATE_TYPE:
		converted = pkcs11.CKA_CERTIFICATE_TYPE
	case padlockpb.AttributeType_CKA_ISSUER:
		converted = pkcs11.CKA_ISSUER
	case padlockpb.AttributeType_CKA_SERIAL_NUMBER:
		converted = pkcs11.CKA_SERIAL_NUMBER
	case padlockpb.AttributeType_CKA_AC_ISSUER:
		converted = pkcs11.CKA_AC_ISSUER
	case padlockpb.AttributeType_CKA_OWNER:
		converted = pkcs11.CKA_OWNER
	case padlockpb.AttributeType_CKA_ATTR_TYPES:
		converted = pkcs11.CKA_ATTR_TYPES
	case padlockpb.AttributeType_CKA_TRUSTED:
		converted = pkcs11.CKA_TRUSTED
	case padlockpb.AttributeType_CKA_CERTIFICATE_CATEGORY:
		converted = pkcs11.CKA_CERTIFICATE_CATEGORY
	case padlockpb.AttributeType_CKA_JAVA_MIDP_SECURITY_DOMAIN:
		converted = pkcs11.CKA_JAVA_MIDP_SECURITY_DOMAIN
	case padlockpb.AttributeType_CKA_URL:
		converted = pkcs11.CKA_URL
	case padlockpb.AttributeType_CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
		converted = pkcs11.CKA_HASH_OF_SUBJECT_PUBLIC_KEY
	case padlockpb.AttributeType_CKA_HASH_OF_ISSUER_PUBLIC_KEY:
		converted = pkcs11.CKA_HASH_OF_ISSUER_PUBLIC_KEY
	case padlockpb.AttributeType_CKA_NAME_HASH_ALGORITHM:
		converted = pkcs11.CKA_NAME_HASH_ALGORITHM
	case padlockpb.AttributeType_CKA_CHECK_VALUE:
		converted = pkcs11.CKA_CHECK_VALUE
	case padlockpb.AttributeType_CKA_KEY_TYPE:
		converted = pkcs11.CKA_KEY_TYPE
	case padlockpb.AttributeType_CKA_SUBJECT:
		converted = pkcs11.CKA_SUBJECT
	case padlockpb.AttributeType_CKA_ID:
		converted = pkcs11.CKA_ID
	case padlockpb.AttributeType_CKA_SENSITIVE:
		converted = pkcs11.CKA_SENSITIVE
	case padlockpb.AttributeType_CKA_ENCRYPT:
		converted = pkcs11.CKA_ENCRYPT
	case padlockpb.AttributeType_CKA_DECRYPT:
		converted = pkcs11.CKA_DECRYPT
	case padlockpb.AttributeType_CKA_WRAP:
		converted = pkcs11.CKA_WRAP
	case padlockpb.AttributeType_CKA_UNWRAP:
		converted = pkcs11.CKA_UNWRAP
	case padlockpb.AttributeType_CKA_SIGN:
		converted = pkcs11.CKA_SIGN
	case padlockpb.AttributeType_CKA_SIGN_RECOVER:
		converted = pkcs11.CKA_SIGN_RECOVER
	case padlockpb.AttributeType_CKA_VERIFY:
		converted = pkcs11.CKA_VERIFY
	case padlockpb.AttributeType_CKA_VERIFY_RECOVER:
		converted = pkcs11.CKA_VERIFY_RECOVER
	case padlockpb.AttributeType_CKA_DERIVE:
		converted = pkcs11.CKA_DERIVE
	case padlockpb.AttributeType_CKA_START_DATE:
		converted = pkcs11.CKA_START_DATE
	case padlockpb.AttributeType_CKA_END_DATE:
		converted = pkcs11.CKA_END_DATE
	case padlockpb.AttributeType_CKA_MODULUS:
		converted = pkcs11.CKA_MODULUS
	case padlockpb.AttributeType_CKA_MODULUS_BITS:
		converted = pkcs11.CKA_MODULUS_BITS
	case padlockpb.AttributeType_CKA_PUBLIC_EXPONENT:
		converted = pkcs11.CKA_PUBLIC_EXPONENT
	case padlockpb.AttributeType_CKA_PRIVATE_EXPONENT:
		converted = pkcs11.CKA_PRIVATE_EXPONENT
	case padlockpb.AttributeType_CKA_PRIME_1:
		converted = pkcs11.CKA_PRIME_1
	case padlockpb.AttributeType_CKA_PRIME_2:
		converted = pkcs11.CKA_PRIME_2
	case padlockpb.AttributeType_CKA_EXPONENT_1:
		converted = pkcs11.CKA_EXPONENT_1
	case padlockpb.AttributeType_CKA_EXPONENT_2:
		converted = pkcs11.CKA_EXPONENT_2
	case padlockpb.AttributeType_CKA_COEFFICIENT:
		converted = pkcs11.CKA_COEFFICIENT
	case padlockpb.AttributeType_CKA_PUBLIC_KEY_INFO:
		converted = pkcs11.CKA_PUBLIC_KEY_INFO
	case padlockpb.AttributeType_CKA_PRIME:
		converted = pkcs11.CKA_PRIME
	case padlockpb.AttributeType_CKA_SUBPRIME:
		converted = pkcs11.CKA_SUBPRIME
	case padlockpb.AttributeType_CKA_BASE:
		converted = pkcs11.CKA_BASE
	case padlockpb.AttributeType_CKA_PRIME_BITS:
		converted = pkcs11.CKA_PRIME_BITS
	case padlockpb.AttributeType_CKA_SUBPRIME_BITS:
		converted = pkcs11.CKA_SUBPRIME_BITS
	case padlockpb.AttributeType_CKA_SUB_PRIME_BITS:
		converted = pkcs11.CKA_SUB_PRIME_BITS
	case padlockpb.AttributeType_CKA_VALUE_BITS:
		converted = pkcs11.CKA_VALUE_BITS
	case padlockpb.AttributeType_CKA_VALUE_LEN:
		converted = pkcs11.CKA_VALUE_LEN
	case padlockpb.AttributeType_CKA_EXTRACTABLE:
		converted = pkcs11.CKA_EXTRACTABLE
	case padlockpb.AttributeType_CKA_LOCAL:
		converted = pkcs11.CKA_LOCAL
	case padlockpb.AttributeType_CKA_NEVER_EXTRACTABLE:
		converted = pkcs11.CKA_NEVER_EXTRACTABLE
	case padlockpb.AttributeType_CKA_ALWAYS_SENSITIVE:
		converted = pkcs11.CKA_ALWAYS_SENSITIVE
	case padlockpb.AttributeType_CKA_KEY_GEN_MECHANISM:
		converted = pkcs11.CKA_KEY_GEN_MECHANISM
	case padlockpb.AttributeType_CKA_MODIFIABLE:
		converted = pkcs11.CKA_MODIFIABLE
	case padlockpb.AttributeType_CKA_COPYABLE:
		converted = pkcs11.CKA_COPYABLE
	case padlockpb.AttributeType_CKA_DESTROYABLE:
		converted = pkcs11.CKA_DESTROYABLE
	case padlockpb.AttributeType_CKA_ECDSA_PARAMS:
		converted = pkcs11.CKA_ECDSA_PARAMS
	case padlockpb.AttributeType_CKA_EC_PARAMS:
		converted = pkcs11.CKA_EC_PARAMS
	case padlockpb.AttributeType_CKA_EC_POINT:
		converted = pkcs11.CKA_EC_POINT
	case padlockpb.AttributeType_CKA_SECONDARY_AUTH:
		converted = pkcs11.CKA_SECONDARY_AUTH
	case padlockpb.AttributeType_CKA_AUTH_PIN_FLAGS:
		converted = pkcs11.CKA_AUTH_PIN_FLAGS
	case padlockpb.AttributeType_CKA_ALWAYS_AUTHENTICATE:
		converted = pkcs11.CKA_ALWAYS_AUTHENTICATE
	case padlockpb.AttributeType_CKA_WRAP_WITH_TRUSTED:
		converted = pkcs11.CKA_WRAP_WITH_TRUSTED
	case padlockpb.AttributeType_CKA_WRAP_TEMPLATE:
		converted = pkcs11.CKA_WRAP_TEMPLATE
	case padlockpb.AttributeType_CKA_UNWRAP_TEMPLATE:
		converted = pkcs11.CKA_UNWRAP_TEMPLATE
	case padlockpb.AttributeType_CKA_OTP_FORMAT:
		converted = pkcs11.CKA_OTP_FORMAT
	case padlockpb.AttributeType_CKA_OTP_LENGTH:
		converted = pkcs11.CKA_OTP_LENGTH
	case padlockpb.AttributeType_CKA_OTP_TIME_INTERVAL:
		converted = pkcs11.CKA_OTP_TIME_INTERVAL
	case padlockpb.AttributeType_CKA_OTP_USER_FRIENDLY_MODE:
		converted = pkcs11.CKA_OTP_USER_FRIENDLY_MODE
	case padlockpb.AttributeType_CKA_OTP_CHALLENGE_REQUIREMENT:
		converted = pkcs11.CKA_OTP_CHALLENGE_REQUIREMENT
	case padlockpb.AttributeType_CKA_OTP_TIME_REQUIREMENT:
		converted = pkcs11.CKA_OTP_TIME_REQUIREMENT
	case padlockpb.AttributeType_CKA_OTP_COUNTER_REQUIREMENT:
		converted = pkcs11.CKA_OTP_COUNTER_REQUIREMENT
	case padlockpb.AttributeType_CKA_OTP_PIN_REQUIREMENT:
		converted = pkcs11.CKA_OTP_PIN_REQUIREMENT
	case padlockpb.AttributeType_CKA_OTP_COUNTER:
		converted = pkcs11.CKA_OTP_COUNTER
	case padlockpb.AttributeType_CKA_OTP_TIME:
		converted = pkcs11.CKA_OTP_TIME
	case padlockpb.AttributeType_CKA_OTP_USER_IDENTIFIER:
		converted = pkcs11.CKA_OTP_USER_IDENTIFIER
	case padlockpb.AttributeType_CKA_OTP_SERVICE_IDENTIFIER:
		converted = pkcs11.CKA_OTP_SERVICE_IDENTIFIER
	case padlockpb.AttributeType_CKA_OTP_SERVICE_LOGO:
		converted = pkcs11.CKA_OTP_SERVICE_LOGO
	case padlockpb.AttributeType_CKA_OTP_SERVICE_LOGO_TYPE:
		converted = pkcs11.CKA_OTP_SERVICE_LOGO_TYPE
	case padlockpb.AttributeType_CKA_GOSTR3410_PARAMS:
		converted = pkcs11.CKA_GOSTR3410_PARAMS
	case padlockpb.AttributeType_CKA_GOSTR3411_PARAMS:
		converted = pkcs11.CKA_GOSTR3411_PARAMS
	case padlockpb.AttributeType_CKA_GOST28147_PARAMS:
		converted = pkcs11.CKA_GOST28147_PARAMS
	case padlockpb.AttributeType_CKA_HW_FEATURE_TYPE:
		converted = pkcs11.CKA_HW_FEATURE_TYPE
	case padlockpb.AttributeType_CKA_RESET_ON_INIT:
		converted = pkcs11.CKA_RESET_ON_INIT
	case padlockpb.AttributeType_CKA_HAS_RESET:
		converted = pkcs11.CKA_HAS_RESET
	case padlockpb.AttributeType_CKA_PIXEL_X:
		converted = pkcs11.CKA_PIXEL_X
	case padlockpb.AttributeType_CKA_PIXEL_Y:
		converted = pkcs11.CKA_PIXEL_Y
	case padlockpb.AttributeType_CKA_RESOLUTION:
		converted = pkcs11.CKA_RESOLUTION
	case padlockpb.AttributeType_CKA_CHAR_ROWS:
		converted = pkcs11.CKA_CHAR_ROWS
	case padlockpb.AttributeType_CKA_CHAR_COLUMNS:
		converted = pkcs11.CKA_CHAR_COLUMNS
	case padlockpb.AttributeType_CKA_COLOR:
		converted = pkcs11.CKA_COLOR
	case padlockpb.AttributeType_CKA_BITS_PER_PIXEL:
		converted = pkcs11.CKA_BITS_PER_PIXEL
	case padlockpb.AttributeType_CKA_CHAR_SETS:
		converted = pkcs11.CKA_CHAR_SETS
	case padlockpb.AttributeType_CKA_ENCODING_METHODS:
		converted = pkcs11.CKA_ENCODING_METHODS
	case padlockpb.AttributeType_CKA_MIME_TYPES:
		converted = pkcs11.CKA_MIME_TYPES
	case padlockpb.AttributeType_CKA_MECHANISM_TYPE:
		converted = pkcs11.CKA_MECHANISM_TYPE
	case padlockpb.AttributeType_CKA_REQUIRED_CMS_ATTRIBUTES:
		converted = pkcs11.CKA_REQUIRED_CMS_ATTRIBUTES
	case padlockpb.AttributeType_CKA_DEFAULT_CMS_ATTRIBUTES:
		converted = pkcs11.CKA_DEFAULT_CMS_ATTRIBUTES
	case padlockpb.AttributeType_CKA_SUPPORTED_CMS_ATTRIBUTES:
		converted = pkcs11.CKA_SUPPORTED_CMS_ATTRIBUTES
	case padlockpb.AttributeType_CKA_ALLOWED_MECHANISMS:
		converted = pkcs11.CKA_ALLOWED_MECHANISMS
	case padlockpb.AttributeType_CKA_VENDOR_DEFINED:
		converted = pkcs11.CKA_VENDOR_DEFINED
	}
	return converted
}

// AttributeP11toPB converts mechanism enums
func AttributeP11toPB(attr uint) padlockpb.AttributeType {
	converted := padlockpb.AttributeType_CKA_UNDEFINED_UNKNOWN // invalid for everything
	switch attr {
	case pkcs11.CKA_CLASS:
		converted = padlockpb.AttributeType_CKA_CLASS
	case pkcs11.CKA_TOKEN:
		converted = padlockpb.AttributeType_CKA_TOKEN
	case pkcs11.CKA_PRIVATE:
		converted = padlockpb.AttributeType_CKA_PRIVATE
	case pkcs11.CKA_LABEL:
		converted = padlockpb.AttributeType_CKA_LABEL
	case pkcs11.CKA_APPLICATION:
		converted = padlockpb.AttributeType_CKA_APPLICATION
	case pkcs11.CKA_VALUE:
		converted = padlockpb.AttributeType_CKA_VALUE
	case pkcs11.CKA_OBJECT_ID:
		converted = padlockpb.AttributeType_CKA_OBJECT_ID
	case pkcs11.CKA_CERTIFICATE_TYPE:
		converted = padlockpb.AttributeType_CKA_CERTIFICATE_TYPE
	case pkcs11.CKA_ISSUER:
		converted = padlockpb.AttributeType_CKA_ISSUER
	case pkcs11.CKA_SERIAL_NUMBER:
		converted = padlockpb.AttributeType_CKA_SERIAL_NUMBER
	case pkcs11.CKA_AC_ISSUER:
		converted = padlockpb.AttributeType_CKA_AC_ISSUER
	case pkcs11.CKA_OWNER:
		converted = padlockpb.AttributeType_CKA_OWNER
	case pkcs11.CKA_ATTR_TYPES:
		converted = padlockpb.AttributeType_CKA_ATTR_TYPES
	case pkcs11.CKA_TRUSTED:
		converted = padlockpb.AttributeType_CKA_TRUSTED
	case pkcs11.CKA_CERTIFICATE_CATEGORY:
		converted = padlockpb.AttributeType_CKA_CERTIFICATE_CATEGORY
	case pkcs11.CKA_JAVA_MIDP_SECURITY_DOMAIN:
		converted = padlockpb.AttributeType_CKA_JAVA_MIDP_SECURITY_DOMAIN
	case pkcs11.CKA_URL:
		converted = padlockpb.AttributeType_CKA_URL
	case pkcs11.CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
		converted = padlockpb.AttributeType_CKA_HASH_OF_SUBJECT_PUBLIC_KEY
	case pkcs11.CKA_HASH_OF_ISSUER_PUBLIC_KEY:
		converted = padlockpb.AttributeType_CKA_HASH_OF_ISSUER_PUBLIC_KEY
	case pkcs11.CKA_NAME_HASH_ALGORITHM:
		converted = padlockpb.AttributeType_CKA_NAME_HASH_ALGORITHM
	case pkcs11.CKA_CHECK_VALUE:
		converted = padlockpb.AttributeType_CKA_CHECK_VALUE
	case pkcs11.CKA_KEY_TYPE:
		converted = padlockpb.AttributeType_CKA_KEY_TYPE
	case pkcs11.CKA_SUBJECT:
		converted = padlockpb.AttributeType_CKA_SUBJECT
	case pkcs11.CKA_ID:
		converted = padlockpb.AttributeType_CKA_ID
	case pkcs11.CKA_SENSITIVE:
		converted = padlockpb.AttributeType_CKA_SENSITIVE
	case pkcs11.CKA_ENCRYPT:
		converted = padlockpb.AttributeType_CKA_ENCRYPT
	case pkcs11.CKA_DECRYPT:
		converted = padlockpb.AttributeType_CKA_DECRYPT
	case pkcs11.CKA_WRAP:
		converted = padlockpb.AttributeType_CKA_WRAP
	case pkcs11.CKA_UNWRAP:
		converted = padlockpb.AttributeType_CKA_UNWRAP
	case pkcs11.CKA_SIGN:
		converted = padlockpb.AttributeType_CKA_SIGN
	case pkcs11.CKA_SIGN_RECOVER:
		converted = padlockpb.AttributeType_CKA_SIGN_RECOVER
	case pkcs11.CKA_VERIFY:
		converted = padlockpb.AttributeType_CKA_VERIFY
	case pkcs11.CKA_VERIFY_RECOVER:
		converted = padlockpb.AttributeType_CKA_VERIFY_RECOVER
	case pkcs11.CKA_DERIVE:
		converted = padlockpb.AttributeType_CKA_DERIVE
	case pkcs11.CKA_START_DATE:
		converted = padlockpb.AttributeType_CKA_START_DATE
	case pkcs11.CKA_END_DATE:
		converted = padlockpb.AttributeType_CKA_END_DATE
	case pkcs11.CKA_MODULUS:
		converted = padlockpb.AttributeType_CKA_MODULUS
	case pkcs11.CKA_MODULUS_BITS:
		converted = padlockpb.AttributeType_CKA_MODULUS_BITS
	case pkcs11.CKA_PUBLIC_EXPONENT:
		converted = padlockpb.AttributeType_CKA_PUBLIC_EXPONENT
	case pkcs11.CKA_PRIVATE_EXPONENT:
		converted = padlockpb.AttributeType_CKA_PRIVATE_EXPONENT
	case pkcs11.CKA_PRIME_1:
		converted = padlockpb.AttributeType_CKA_PRIME_1
	case pkcs11.CKA_PRIME_2:
		converted = padlockpb.AttributeType_CKA_PRIME_2
	case pkcs11.CKA_EXPONENT_1:
		converted = padlockpb.AttributeType_CKA_EXPONENT_1
	case pkcs11.CKA_EXPONENT_2:
		converted = padlockpb.AttributeType_CKA_EXPONENT_2
	case pkcs11.CKA_COEFFICIENT:
		converted = padlockpb.AttributeType_CKA_COEFFICIENT
	case pkcs11.CKA_PUBLIC_KEY_INFO:
		converted = padlockpb.AttributeType_CKA_PUBLIC_KEY_INFO
	case pkcs11.CKA_PRIME:
		converted = padlockpb.AttributeType_CKA_PRIME
	case pkcs11.CKA_SUBPRIME:
		converted = padlockpb.AttributeType_CKA_SUBPRIME
	case pkcs11.CKA_BASE:
		converted = padlockpb.AttributeType_CKA_BASE
	case pkcs11.CKA_PRIME_BITS:
		converted = padlockpb.AttributeType_CKA_PRIME_BITS
	case pkcs11.CKA_SUBPRIME_BITS:
		converted = padlockpb.AttributeType_CKA_SUBPRIME_BITS
	case pkcs11.CKA_VALUE_BITS:
		converted = padlockpb.AttributeType_CKA_VALUE_BITS
	case pkcs11.CKA_VALUE_LEN:
		converted = padlockpb.AttributeType_CKA_VALUE_LEN
	case pkcs11.CKA_EXTRACTABLE:
		converted = padlockpb.AttributeType_CKA_EXTRACTABLE
	case pkcs11.CKA_LOCAL:
		converted = padlockpb.AttributeType_CKA_LOCAL
	case pkcs11.CKA_NEVER_EXTRACTABLE:
		converted = padlockpb.AttributeType_CKA_NEVER_EXTRACTABLE
	case pkcs11.CKA_ALWAYS_SENSITIVE:
		converted = padlockpb.AttributeType_CKA_ALWAYS_SENSITIVE
	case pkcs11.CKA_KEY_GEN_MECHANISM:
		converted = padlockpb.AttributeType_CKA_KEY_GEN_MECHANISM
	case pkcs11.CKA_MODIFIABLE:
		converted = padlockpb.AttributeType_CKA_MODIFIABLE
	case pkcs11.CKA_COPYABLE:
		converted = padlockpb.AttributeType_CKA_COPYABLE
	case pkcs11.CKA_DESTROYABLE:
		converted = padlockpb.AttributeType_CKA_DESTROYABLE
	case pkcs11.CKA_ECDSA_PARAMS:
		converted = padlockpb.AttributeType_CKA_ECDSA_PARAMS
	case pkcs11.CKA_EC_POINT:
		converted = padlockpb.AttributeType_CKA_EC_POINT
	case pkcs11.CKA_SECONDARY_AUTH:
		converted = padlockpb.AttributeType_CKA_SECONDARY_AUTH
	case pkcs11.CKA_AUTH_PIN_FLAGS:
		converted = padlockpb.AttributeType_CKA_AUTH_PIN_FLAGS
	case pkcs11.CKA_ALWAYS_AUTHENTICATE:
		converted = padlockpb.AttributeType_CKA_ALWAYS_AUTHENTICATE
	case pkcs11.CKA_WRAP_WITH_TRUSTED:
		converted = padlockpb.AttributeType_CKA_WRAP_WITH_TRUSTED
	case pkcs11.CKA_WRAP_TEMPLATE:
		converted = padlockpb.AttributeType_CKA_WRAP_TEMPLATE
	case pkcs11.CKA_UNWRAP_TEMPLATE:
		converted = padlockpb.AttributeType_CKA_UNWRAP_TEMPLATE
	case pkcs11.CKA_OTP_FORMAT:
		converted = padlockpb.AttributeType_CKA_OTP_FORMAT
	case pkcs11.CKA_OTP_LENGTH:
		converted = padlockpb.AttributeType_CKA_OTP_LENGTH
	case pkcs11.CKA_OTP_TIME_INTERVAL:
		converted = padlockpb.AttributeType_CKA_OTP_TIME_INTERVAL
	case pkcs11.CKA_OTP_USER_FRIENDLY_MODE:
		converted = padlockpb.AttributeType_CKA_OTP_USER_FRIENDLY_MODE
	case pkcs11.CKA_OTP_CHALLENGE_REQUIREMENT:
		converted = padlockpb.AttributeType_CKA_OTP_CHALLENGE_REQUIREMENT
	case pkcs11.CKA_OTP_TIME_REQUIREMENT:
		converted = padlockpb.AttributeType_CKA_OTP_TIME_REQUIREMENT
	case pkcs11.CKA_OTP_COUNTER_REQUIREMENT:
		converted = padlockpb.AttributeType_CKA_OTP_COUNTER_REQUIREMENT
	case pkcs11.CKA_OTP_PIN_REQUIREMENT:
		converted = padlockpb.AttributeType_CKA_OTP_PIN_REQUIREMENT
	case pkcs11.CKA_OTP_COUNTER:
		converted = padlockpb.AttributeType_CKA_OTP_COUNTER
	case pkcs11.CKA_OTP_TIME:
		converted = padlockpb.AttributeType_CKA_OTP_TIME
	case pkcs11.CKA_OTP_USER_IDENTIFIER:
		converted = padlockpb.AttributeType_CKA_OTP_USER_IDENTIFIER
	case pkcs11.CKA_OTP_SERVICE_IDENTIFIER:
		converted = padlockpb.AttributeType_CKA_OTP_SERVICE_IDENTIFIER
	case pkcs11.CKA_OTP_SERVICE_LOGO:
		converted = padlockpb.AttributeType_CKA_OTP_SERVICE_LOGO
	case pkcs11.CKA_OTP_SERVICE_LOGO_TYPE:
		converted = padlockpb.AttributeType_CKA_OTP_SERVICE_LOGO_TYPE
	case pkcs11.CKA_GOSTR3410_PARAMS:
		converted = padlockpb.AttributeType_CKA_GOSTR3410_PARAMS
	case pkcs11.CKA_GOSTR3411_PARAMS:
		converted = padlockpb.AttributeType_CKA_GOSTR3411_PARAMS
	case pkcs11.CKA_GOST28147_PARAMS:
		converted = padlockpb.AttributeType_CKA_GOST28147_PARAMS
	case pkcs11.CKA_HW_FEATURE_TYPE:
		converted = padlockpb.AttributeType_CKA_HW_FEATURE_TYPE
	case pkcs11.CKA_RESET_ON_INIT:
		converted = padlockpb.AttributeType_CKA_RESET_ON_INIT
	case pkcs11.CKA_HAS_RESET:
		converted = padlockpb.AttributeType_CKA_HAS_RESET
	case pkcs11.CKA_PIXEL_X:
		converted = padlockpb.AttributeType_CKA_PIXEL_X
	case pkcs11.CKA_PIXEL_Y:
		converted = padlockpb.AttributeType_CKA_PIXEL_Y
	case pkcs11.CKA_RESOLUTION:
		converted = padlockpb.AttributeType_CKA_RESOLUTION
	case pkcs11.CKA_CHAR_ROWS:
		converted = padlockpb.AttributeType_CKA_CHAR_ROWS
	case pkcs11.CKA_CHAR_COLUMNS:
		converted = padlockpb.AttributeType_CKA_CHAR_COLUMNS
	case pkcs11.CKA_COLOR:
		converted = padlockpb.AttributeType_CKA_COLOR
	case pkcs11.CKA_BITS_PER_PIXEL:
		converted = padlockpb.AttributeType_CKA_BITS_PER_PIXEL
	case pkcs11.CKA_CHAR_SETS:
		converted = padlockpb.AttributeType_CKA_CHAR_SETS
	case pkcs11.CKA_ENCODING_METHODS:
		converted = padlockpb.AttributeType_CKA_ENCODING_METHODS
	case pkcs11.CKA_MIME_TYPES:
		converted = padlockpb.AttributeType_CKA_MIME_TYPES
	case pkcs11.CKA_MECHANISM_TYPE:
		converted = padlockpb.AttributeType_CKA_MECHANISM_TYPE
	case pkcs11.CKA_REQUIRED_CMS_ATTRIBUTES:
		converted = padlockpb.AttributeType_CKA_REQUIRED_CMS_ATTRIBUTES
	case pkcs11.CKA_DEFAULT_CMS_ATTRIBUTES:
		converted = padlockpb.AttributeType_CKA_DEFAULT_CMS_ATTRIBUTES
	case pkcs11.CKA_SUPPORTED_CMS_ATTRIBUTES:
		converted = padlockpb.AttributeType_CKA_SUPPORTED_CMS_ATTRIBUTES
	case pkcs11.CKA_ALLOWED_MECHANISMS:
		converted = padlockpb.AttributeType_CKA_ALLOWED_MECHANISMS
	case pkcs11.CKA_VENDOR_DEFINED:
		converted = padlockpb.AttributeType_CKA_VENDOR_DEFINED
	}
	return converted
}
