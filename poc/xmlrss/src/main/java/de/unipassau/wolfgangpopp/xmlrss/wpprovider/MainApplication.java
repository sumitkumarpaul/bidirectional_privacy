package de.unipassau.wolfgangpopp.xmlrss.wpprovider;


import java.io.File;
import java.nio.file.Files;
import java.io.IOException;
import java.io.*;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
//import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;

import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.time.LocalDateTime;
import java.time.temporal.*;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.OutputKeys;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.junit.Assert;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNull;
import org.w3c.dom.Document;
import org.w3c.dom.DocumentType;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Element;
import org.w3c.dom.DOMImplementation;
import org.xml.sax.SAXException;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss.PSRSSPrivateKey;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss.PSRSSPublicKey;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.xml.RedactableXMLSignatureException;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.io.FileInputStream;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;

import javax.xml.transform.stream.StreamResult;

public class MainApplication {
	
	public static String algorithm = "XMLPSRSSwithPSA";
	public static LocalDateTime start_time, end_time;

	public static void main(String[] args) {
		try {
			//System.out.println("Start: " + args[0] + " " + args[1] + " ..." + LocalDateTime.now().toString());

			// This line is needed to register the security profile
			Security.addProvider(new WPProvider());

			if (args[0].equals("Sig")) {
				//System.out.println("Input file:" + args[1] + " number of redactable elements:" + args[2] + " output file:" + args[3] + " and exporting the pub-key in the file:" + args[4]);
			    Sig(args[1], Integer.parseInt(args[2]), args[3], args[4]);
			} else if (args[0].equals("Red")) {
				//System.out.println("Input file:" + args[1] + " number of elements to be redacted:" + args[2] + " the public-key file:" + args[3] + " output file:" + args[4]);
				Red(args[1], Integer.parseInt(args[2]), args[3], args[4]);
			} else if (args[0].equals("Vf")) {
				//System.out.println("Verifying the input file:" + args[1] + " the public-key file:" + args[2]);
				Vf(args[1], args[2]);
			} else if (args[0].equals("RSASig")) {
				//System.out.println("Verifying the input file:" + args[1] + " the public-key file:" + args[2]);
				RSASig(args[1], args[2], args[3]);
			} else if (args[0].equals("RSAVf")) {
				//System.out.println("Verifying the input file:" + args[1] + " the public-key file:" + args[2]);
				RSAVf(args[1], args[2], args[3]);
			} else {
				System.out.println("Provide either of the following three arguments:");
				System.out.println("  - Sig <Input file> <Number of redactable elements> <Output file name> <Exported public key file name>");
				System.out.println("  - Red <Input file> <Number of elements to be redacted> <Exported public key file name> <Output file name>");
				System.out.println("  - Vf  <Input file> <Public key file name>");
				System.out.println("  - RSASig <Input file> <Output signaure file name> <Exported public key file name>");
				System.out.println("  - RSAVf  <Input file> <Signaure file name> <Public key file name>");
			}

//			System.out.println(args[0] + "\tstart-time: " + start_time.toString() + " end-time: " + end_time.toString() + " total: " + ChronoUnit.MICROS.between(start_time, end_time));
			System.out.println(args[0] + "\ttotal-time: " + ChronoUnit.MICROS.between(start_time, end_time) + " us");
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

    private static void Sig(String input_file, int num_pd, String output_file, String exported_pub_key) throws Exception {
        XPath xPath;
		FileOutputStream fileOut = new FileOutputStream(exported_pub_key);
        ObjectOutputStream out = new ObjectOutputStream(fileOut);	
		//For the testing purpose, using the same key-pair always
		KeyPair keyPair = new KeyPair(
	                new PSRSSPublicKey(new BigInteger("7249349928048807500024891411067629370056303429447255270046802991880425543412906735607605108373982421012500888307062421310001762155422489671132976679912849")),
	                new PSRSSPrivateKey(new BigInteger("7249349928048807500024891411067629370056303429447255270046802991880425543412734960638035580933850038621738468566657503090109097536944629352405060890801636"))
        );
        out.writeObject(keyPair.getPublic());
        out.close();
        fileOut.close();

        RedactableXMLSignature sig = RedactableXMLSignature.getInstance(algorithm);
        sig.initSign(keyPair);

        sig.setDocument(new FileInputStream(input_file));

		//Make all the elements redactable
        for (int i = 0; i < num_pd; i++) {
        	sig.addSignSelector("#xpointer(id('pd_" + (i+1) + "'))", true);
		}
		start_time = LocalDateTime.now();
        Document document = sig.sign();

		end_time = LocalDateTime.now();
		//At this moment stop this from saving it in the disk in real file format
		saveDocument(document, new File(output_file));

//		fileOut = new FileOutputStream(output_file+".obj");
		//fileOut = new FileOutputStream(output_file);
        //out = new ObjectOutputStream(fileOut);	
        //out.writeObject(document);
        //out.close();
        //fileOut.close();
	}

    private static void Vf(String input_file, String pub_key_file) throws Exception {
        start_time = LocalDateTime.now();
		XPath xPath;
		FileInputStream fileIn = new FileInputStream(pub_key_file);
        ObjectInputStream in = new ObjectInputStream(fileIn);
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance(algorithm);
		sig.initVerify((PSRSSPublicKey)in.readObject());
        in.close();
        fileIn.close();

//		fileIn = new FileInputStream(input_file+".obj");
		//fileIn = new FileInputStream(input_file);
        //in = new ObjectInputStream(fileIn);
        //Removed sig.setDocument((Document)in.readObject());
        sig.setDocument(new FileInputStream(input_file));
		//in.close();
        //fileIn.close();

        //assertTrue(sig.verify());
		if (sig.verify() != true) {
			System.out.println("XMLRSS signature verification failed\n");
		}
		end_time = LocalDateTime.now();
	}

	/* TODO: Verification after the redaction is not working */
    private static void Red(String input_file, int num_red_pd, String pub_key_file, String output_file) throws Exception {
        start_time = LocalDateTime.now();
		XPath xPath;
		FileInputStream fileIn = new FileInputStream(pub_key_file);
        ObjectInputStream in = new ObjectInputStream(fileIn);
        RedactableXMLSignature sig = RedactableXMLSignature.getInstance(algorithm);
		sig.initRedact((PSRSSPublicKey)in.readObject());

//        sig.setDocument(new FileInputStream(input_file));
//		fileIn = new FileInputStream(input_file+".obj");
		//fileIn = new FileInputStream(input_file);
        //in = new ObjectInputStream(fileIn);
        sig.setDocument(new FileInputStream(input_file));
        //sig.setDocument(new FileInputStream(input_file));
		in.close();
        fileIn.close();

		//Make all the elements redactable
        for (int i = 0; i < num_red_pd; i++) {
        	sig.addRedactSelector("#xpointer(id('pd_" + (i+1) + "'))");
//        	sig.addRedactSelector("#xpath(id('/PC/PDS/PD[" + (i+1) + "]'))");
		}
//        	sig.addRedactSelector("#xpointer(id('pd_12'))");
//        	sig.addRedactSelector("#xpointer(id('pd_83'))");

		Document document = sig.redact();

		//Save in object format
		//FileOutputStream fileOut = new FileOutputStream(output_file+".obj");
        //FileOutputStream fileOut = new FileOutputStream(output_file);
        //ObjectOutputStream out = new ObjectOutputStream(fileOut);	
        //out.writeObject(document);
        //out.close();
        //fileOut.close();

		//At this moment stop this from saving it in the disk in real file format
    	saveDocument(document, new File(output_file));
		end_time = LocalDateTime.now();
	}

    private static void RSASig(String input_file, String output_file, String exported_pub_key) throws Exception {
        XPath xPath;
	    File ifile = new File(input_file);
		Path path = Paths. get(output_file);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();
		byte[] key = keyPair.getPublic().getEncoded();
		FileOutputStream keyfos = new FileOutputStream(exported_pub_key);
		keyfos.write(key);
		keyfos.close();
	
        //Let's sign our message
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(keyPair.getPrivate());
        privateSignature.update(Files.readAllBytes(Paths.get(input_file)));

		start_time = LocalDateTime.now();
        byte[] signature = privateSignature.sign();
		Files. write(path, signature);

		//TODO: Similar to the xmlrss, the signature should be written into the file and save that file
		//To make comparison fair
		end_time = LocalDateTime.now();
	}

    private static void RSAVf(String input_file, String sig_file, String pub_key_file) throws Exception {
        start_time = LocalDateTime.now();
		/*
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
		FileInputStream keyfis = new FileInputStream(pub_key_file);
		byte[] encKey = new byte[keyfis.available()];  
		keyfis.read(encKey);
		keyfis.close();
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SUN");
		PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        publicSignature.initVerify(pubKey);

        publicSignature.update(Files.readAllBytes(Paths.get(input_file)));

        if (publicSignature.verify(Files.readAllBytes(Paths.get(sig_file))) != true) {
			System.out.println("RSA signature verification failed\n");
		}
		*/

		end_time = LocalDateTime.now();
	}

	private static void saveDocument(Document document, File output) throws TransformerException {
		DocumentType doctype = document.getImplementation().createDocumentType("doctype","", "xmlrss/testdata/pc.dtd");
        Transformer trans = TransformerFactory.newInstance().newTransformer();
		trans.setOutputProperty(OutputKeys.DOCTYPE_SYSTEM, doctype.getSystemId());
		trans.setOutputProperty(OutputKeys.INDENT, "yes");
		trans.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        trans.transform(new DOMSource(document), new StreamResult(output));
    }
}
