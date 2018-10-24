package clienteNovaSoft;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class Cliente extends Thread {
	static String IP="localhost";
	static int puerto=1234;
	static PrintWriter escritor = null;
	static BufferedReader lector = null;
	static Socket socket = null;
	static String simetrico = "AES";
	static String asimetrico = "RSA";
	static String hmac = "HMACMD5";
	static Comunicacion comunicacion;
	
	private KeyPair parejaLlaves;

	public Cliente ()
	{
		try {
			KeyPairGenerator generador = KeyPairGenerator.getInstance(asimetrico);
			generador.initialize(1024);
			parejaLlaves = generador.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public X509Certificate generarCertificado(KeyPair pair) throws Exception
	{
		try {
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

			X509Certificate certificado = certGen.generateX509Certificate(pair.getPrivate(), "BC");

			return certificado;
		}
		catch(Exception e)
		{
			throw new Exception("Error creando el certificado"); 
		}
		
	}

	public void run()
	{
		//configuracion del socket
		try
		{
			socket = new Socket(IP, 1234);
			InputStream input=socket.getInputStream();
			OutputStream output=socket.getOutputStream();
			escritor = new PrintWriter(output, true);
			lector = new BufferedReader(new InputStreamReader(input));
			BufferedReader lectorPropio = new BufferedReader(new InputStreamReader(System.in));
			
			
			//Hola para dar inicio
			escritor.println("HOLA");
			if(lector.readLine().contains("OK"))
			{
				escritor.println("ALGORITMOS:"+simetrico+":"+asimetrico+":"+ hmac);
				System.out.println("Se enviaron algoritmos algoritmos con exito");
			}
			if(lector.readLine().contains("OK"))
			{
				System.out.println("El servidor recibio los algoritmos con exito");
				
				X509Certificate certificado = generarCertificado(parejaLlaves);
				socket.getOutputStream().write(certificado.getEncoded());
				
				System.out.println("Se envio el certificado del cliente");
			}
			else
			{
				System.out.println("El servidor no pudo recibir los algoritmos con exito");
				escritor.close();
				lector.close();
			}
			if(lector.readLine().contains("OK"))
			{
				System.out.println("El servidor recibio con exito el certificado");
				
				
				
				System.out.println("Se recibio con exito el certificado del servidor");
				escritor.println("OK");
			}
		}
		catch(Exception e)
		{

		}
	}
}
