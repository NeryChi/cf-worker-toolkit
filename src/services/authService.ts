import { 
  SignJWT, 
  jwtVerify, 
  JWTPayload, 
  KeyLike, 
  importPKCS8, 
  importSPKI 
} from 'jose';

interface GenerateTokenParams {
  payload: JWTPayload;
  privateKey: string; // Clave privada en formato PEM
  expiration?: string; // Por ejemplo: '15m', '1h'
  alg?: 'RS256' | 'RS384' | 'RS512'; // Algoritmo, por defecto 'RS256'
  issuer: string; // Emisor del token (obligatorio)
  audience: string | string[]; // Audiencia del token (obligatorio)
}

interface ValidateTokenParams {
  token: string;
  publicKey: string; // Clave pública en formato PEM
  alg?: 'RS256' | 'RS384' | 'RS512'; // Algoritmo, por defecto 'RS256'
  issuer: string; // Emisor esperado (obligatorio)
  audience: string | string[]; // Audiencia esperada (obligatorio)
}

function generateUniqueId(): string {
  return crypto.randomUUID();
}

async function importPrivateKey(pemKey: string, alg: string): Promise<KeyLike> {
  return await importPKCS8(pemKey, alg);
}

async function importPublicKey(pemKey: string, alg: string): Promise<KeyLike> {
  return await importSPKI(pemKey, alg);
}

export async function generateToken(
  params: GenerateTokenParams
): Promise<{ success: boolean; token?: string; error?: string }> {
  const {
    payload,
    privateKey,
    expiration = '15m', // Duración por defecto reducida a 15 minutos
    alg = 'RS256',
    issuer, // Ahora es obligatorio
    audience, // Ahora es obligatorio
  } = params;

  try {
    const key = await importPrivateKey(privateKey, alg);

    const token = await new SignJWT({ ...payload })
      .setProtectedHeader({ alg })
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime(expiration)
      .setJti(generateUniqueId())
      .sign(key);

    return { success: true, token };
  } catch (error) {
    return { success: false, error: 'Error al generar el token' };
  }
}

export async function validateToken(
  params: ValidateTokenParams
): Promise<{ success: boolean; payload?: JWTPayload; error?: string }> {
  const {
    token,
    publicKey,
    alg = 'RS256',
    issuer, // Ahora es obligatorio
    audience, // Ahora es obligatorio
  } = params;

  try {
    const key = await importPublicKey(publicKey, alg);

    const { payload } = await jwtVerify(token, key, {
      algorithms: [alg],
      issuer,
      audience,
    });

    return { success: true, payload };
  } catch (error) {
    return { success: false, error: 'Token inválido o expirado' };
  }
}
