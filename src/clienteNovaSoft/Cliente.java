package clienteNovaSoft;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;



@SuppressWarnings("deprecation")
public class Cliente extends Thread {
	static String IP="localhost";
	static int puerto=123;
	static PrintWriter escritor = null;
	static BufferedReader lector = null;
	static Socket socket = null;
	static String simetrico = "AES";
	static String asimetrico = "RSA";
	static String hmac = "HMACMD5";
	static Key publicaServ=null;
	
	private CifradorSimetrico cSimetrico;
	private SecretKey llaveSimetrica;
	private KeyPair parejaLlaves;

	public Cliente ()
	{
		try {
			KeyPairGenerator generador = KeyPairGenerator.getInstance(asimetrico);
			generador.initialize(1024);
			parejaLlaves = generador.generateKeyPair();
			
			cSimetrico = new CifradorSimetrico();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public X509Certificate generarCertificado(KeyPair pair) throws InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException
	{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
		certGen.setNotBefore(new Date(System.currentTimeMillis() - 10000));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 10000));
		certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
		certGen.setPublicKey(pair.getPublic());
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

		certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
		certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature
				| KeyUsage.keyEncipherment));
		certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(
				KeyPurposeId.id_kp_serverAuth));

		certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(
				new GeneralName(GeneralName.rfc822Name, "test@test.test")));

		return certGen.generateX509Certificate(pair.getPrivate(), "BC");

	}

	public String toHex(String arg) {
		return String.format("%040x", new BigInteger(1, arg.getBytes(/*YOUR_CHARSET?*/)));
	}

	public void run()
	{
		//configuracion del socket
		try
		{
			socket = new Socket(IP, puerto);
			InputStream input=socket.getInputStream();
			OutputStream output=socket.getOutputStream();
			escritor = new PrintWriter(output, true);
			lector = new BufferedReader(new InputStreamReader(input));
			
			//Hola para dar inicio
			escritor.println("HOLA");
			//Algoritmos
			if(lector.readLine().contains("OK"))
			{
				escritor.println("ALGORITMOS:"+simetrico+":"+asimetrico+":"+ hmac);
				System.out.println("Se enviaron algoritmos algoritmos con exito");
			}
			else
			{
				System.out.println("Error, Deberia recibir HOLA");
				escritor.close();
				lector.close();
			}
			//Certificado cliente
			if(lector.readLine().contains("OK"))
			{
				System.out.println("El servidor recibio los algoritmos con exito");

				X509Certificate certificado = generarCertificado(parejaLlaves);
				byte[] certificadoEnBytes = certificado.getEncoded();
				String certificadoEnString = DatatypeConverter.printHexBinary(certificadoEnBytes);
				System.out.println("Mi certificado: " + certificadoEnString);
				escritor.println(certificadoEnString);
				byte[] pruebaByte = DatatypeConverter.parseHexBinary(certificadoEnString);
				System.out.println("MI CERTIFICADO BYTE: " + pruebaByte.toString());

				System.out.println("Se envio el certificado del cliente");
			}
			else
			{
				System.out.println("No se enviaron los algoritmos correctamente");
				escritor.close();
				lector.close();
			}

			//Certificado servidor
			if(lector.readLine().contains("OK"))
			{
				String certString = lector.readLine();
				byte[] certServ = DatatypeConverter.parseHexBinary(certString);
				ByteArrayInputStream inStreamByte = new ByteArrayInputStream(certServ);
				X509Certificate cdServ = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(inStreamByte);

				publicaServ =cdServ.getPublicKey();
				cdServ.verify((PublicKey) publicaServ);
				System.out.println(cdServ.toString());
				escritor.println("OK");
				System.out.println("Dice ok");
			}
			else
			{
				System.out.println("No se envio el certificado con exito");
				escritor.close();
				lector.close();
			}
			
			System.out.println("Se recibio con exito el certificado del servidor");
			
			
			//Recibir llave simetrica
			String llaveSimetricaCifrada = lector.readLine();
			byte[] llaveCifByte = DatatypeConverter.parseHexBinary(llaveSimetricaCifrada);
			
			System.out.println(llaveCifByte.length);
			byte[] llaveDescifradaBytes = descifrarAsimetrico(llaveCifByte, parejaLlaves.getPrivate());
			
			//Enviar llave simetrica
			
			byte[] llaveCifSer = cifrarAsimetrico(llaveDescifradaBytes, publicaServ);
			String llaveCifMensaje = DatatypeConverter.printHexBinary(llaveCifSer);
			escritor.println(llaveCifMensaje);

			//Enviar consulta
			if(lector.readLine().contains("OK"))
			{
				//Creacion numero consulta
				Integer numeroConsulta = (int) (Math.random()*9999900);
				System.out.println("Numero Consulta: " + numeroConsulta);
				
				String numLetras = numeroConsulta.toString();
				byte[] numByte = numLetras.getBytes();
				
				//Cifrar consulta simetrica
				llaveSimetrica = new SecretKeySpec(llaveDescifradaBytes, simetrico);
				cSimetrico.setKey(llaveSimetrica);
				byte[] numeroCif = cSimetrico.cifrar(numByte);
				String mensajeNumero = DatatypeConverter.printHexBinary(numeroCif);
				escritor.println(mensajeNumero);
				
				//Hmac
				byte[] llaveMac = getLlaveDigest(numByte);
				System.out.println(llaveMac);
				
				String mensajeMacNumero = DatatypeConverter.printHexBinary(llaveMac);
				escritor.println(mensajeMacNumero);
				System.out.println("MAC NUMERO: " + mensajeMacNumero);
				System.out.println("NUMERO CIF " + mensajeNumero);
				System.out.println("LLAVE SIM: " + DatatypeConverter.printHexBinary(llaveDescifradaBytes));
				
			}
			else
			{
				System.out.println("El servidor no respondio haber recibido la llave");
			}
			
			System.out.println("HOLA ACA");
			String finale = lector.readLine();
			System.out.println(finale);

		}		
		catch(Exception e)
		{
			e.printStackTrace();
			System.out.println(e.getMessage());
		}
	}
	
	public byte[] cifrarAsimetrico(byte[] clearText, Key kPublica) {
		try {
			Cipher cipher = Cipher.getInstance(asimetrico);
			cipher.init(Cipher.ENCRYPT_MODE, kPublica);
			byte[] cipheredText = cipher.doFinal(clearText);
			return cipheredText;
		} catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}
	
	public byte[] descifrarAsimetrico(byte[] cipheredText, Key kPrivada) {
		try {
			Cipher cipher = Cipher.getInstance(asimetrico);
			cipher.init(Cipher.DECRYPT_MODE, kPrivada);
			
			System.out.println("LONGITUD: " + cipheredText.length);
			byte[] clearText = cipher.doFinal(cipheredText);
			
			return clearText;
		} catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}
	
	public byte[] getLlaveDigest(byte[] buffer) throws Exception{
		Mac mac = Mac.getInstance(hmac);
	    mac.init(llaveSimetrica);
	    byte[] bytes = mac.doFinal(buffer);
	    return bytes;
	}

	public static void main(String[] args) {
		Cliente c = new Cliente();
		c.start();
	}
}
