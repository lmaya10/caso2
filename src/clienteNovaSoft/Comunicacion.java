package clienteNovaSoft;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.X509V3CertificateGenerator;

public class Comunicacion {

	private String simetrico;
	private String asimetrico;
	private String hmac;
	
	public void entablarComunicacion(String pSimetrico, String pAsimetrico, String pHmac, InputStream input, OutputStream output, PrintWriter escritor, BufferedReader lector) throws IOException {
		simetrico=pSimetrico;
		asimetrico=pAsimetrico;
		hmac=pHmac;
		
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
			
			 Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

			    
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
			//Recibir certificado del servidor
			System.out.println("Se recibio con exito el certificado del servidor");
			escritor.println("OK");
		}
		
		
	}
}
