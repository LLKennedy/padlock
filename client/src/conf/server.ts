export interface ServerConfig {
	addressAndPort: string;
	defaultModule: string;
}

export class DefaultServerConfig implements ServerConfig {
	addressAndPort: string = "localhost:6298";
	defaultModule: string = `D:\\\\Downloads\\\\SecurityServerEvaluation-V4.40.0.2\\\\Software\\\\Windows\\\\x86-64\\\\Crypto_APIs\\\\PKCS11_R3\\\\lib\\\\cs_pkcs11_R3.dll`;
}

export function LoadServerConfig(): ServerConfig {
	let cfg: ServerConfig = new DefaultServerConfig();
	// TODO: load from file at build time
	return cfg;
}