package clienteNovaSoft;
import java.security.KeyPair;

import javax.crypto.Cipher;

public class CifradorAsimetrico {

	// -------------------------------
	// Atributos
	// -------------------------------
	private final static String ALGORITMO = Cliente.asimetrico;
	private KeyPair keyPair;

	// -------------------------------
	// Constructor
	// -------------------------------

	public CifradorAsimetrico(KeyPair parDeLlaves) {
		this.keyPair = parDeLlaves;
	}

	// -------------------------------
	// Metodos
	// -------------------------------

	public byte[] cifrar(byte[] clearText) {
		try {
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
			byte[] cipheredText = cipher.doFinal(clearText);
			return cipheredText;
		} catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}

	public byte[] descifrar(byte[] cipheredText) {
		try {
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
			
			System.out.println("LONGITUD: " + cipheredText.length);
			byte[] clearText = cipher.doFinal(cipheredText);
			
			return clearText;
		} catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}

	public KeyPair getPair(){ return keyPair; }
}
