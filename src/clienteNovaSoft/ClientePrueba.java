package clienteNovaSoft;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.Key;

public class ClientePrueba extends Thread{

	static String IP="localhost";
	static int puerto=123;
	static PrintWriter escritor = null;
	static BufferedReader lector = null;
	static Socket socket = null;
	static String simetrico = "AES";
	static String asimetrico = "RSA";
	static String hmac = "HMACMD5";
	static Key publicaServ=null;

	public ClientePrueba()
	{

	}

	public void run() 
	{
		try {
		socket = new Socket(IP, puerto);
		InputStream input=socket.getInputStream();
		OutputStream output=socket.getOutputStream();
		escritor = new PrintWriter(output, true);
		lector = new BufferedReader(new InputStreamReader(input));
		
		escritor.println("HOLA");
		System.out.println("respuesta 1: " + lector.readLine());
		escritor.println("ALGORITMOS:"+simetrico+":"+asimetrico+":"+ hmac);
		System.out.println("Respuesta 2: " + lector.readLine());
		escritor.println("CertificadoCliente");
		System.out.println("Respuesta 3: " + lector.readLine());
		System.out.println("Respuesta 4: " + lector.readLine());
		escritor.println("OK");
		String llaveSim = lector.readLine();
		System.out.println("Respuesta 5: " + llaveSim);
		escritor.println(llaveSim);
		System.out.println("Respuesta 6: " + lector.readLine());
		escritor.println(123456);
		escritor.println(123456);
		String ultima = lector.readLine();
		System.out.println("Respuesta 7: " + ultima);
		
		}
		catch(Exception e)
		{
			
		}
	}
	
	public static void main(String[] args) {
		ClientePrueba c = new ClientePrueba();
		c.start();
	}



}
