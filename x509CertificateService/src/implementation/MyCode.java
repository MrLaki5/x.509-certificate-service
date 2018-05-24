package implementation;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;

import javax.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import code.GuiException;
import gui.Constants;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {
	
	private static String LOCAL_KEY_STORE_PATH="/Users/milanlazarevic/Desktop/myStore.pkcs12";
	private static String LOCAL_KEY_STORAGE_PASS="password";
	
	private KeyStore localKeyStore;

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
		Security.addProvider(new BouncyCastleProvider());
	}

	@Override
	public boolean canSign(String arg0) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean exportCSR(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean exportCertificate(String arg0, String arg1, int arg2, int arg3) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean exportKeypair(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String getCertPublicKeyAlgorithm(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getCertPublicKeyParameter(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getSubjectInfo(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean importCAReply(String arg0, String arg1) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String importCSR(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean importCertificate(String arg0, String arg1) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean importKeypair(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public int loadKeypair(String keypair_name) {
		try {
			if(!localKeyStore.containsAlias(keypair_name)) {
				return -1;
			}
			super.access.setVersion(Constants.V3);
			java.security.cert.X509Certificate certificate=(java.security.cert.X509Certificate) localKeyStore.getCertificate(keypair_name);
			Principal principal=certificate.getSubjectDN();
			String[] params=principal.getName().split(", ");
			for(int i=0; i<params.length; i++) {
				String[] tempPars=params[i].split("=");
				if(tempPars.length>1) {
					switch(tempPars[0]) {
						case "C":
							super.access.setSubjectCountry(tempPars[1]);
							break;
						case "ST":
							super.access.setSubjectState(tempPars[1]);
							break;
						case "L":
							super.access.setSubjectLocality(tempPars[1]);
							break;
						case "O":
							super.access.setSubjectOrganization(tempPars[1]);
							break;
						case "OU":
							super.access.setSubjectOrganizationUnit(tempPars[1]);
							break;
						case "CN":
							super.access.setSubjectCommonName(tempPars[1]);
							break;
					}
				}
			}
			principal=certificate.getIssuerDN();
			params=principal.getName().split(", ");
			String issStr="";
			for(int i=0; i<params.length; i++) {
				String []tempStr=params[i].split("=");
				if(tempStr.length<=1) {
					continue;
				}
				issStr+=params[i];
				if((i+1)<params.length) {
					issStr+=",";
				}
			}
			super.access.setIssuer(issStr);
			super.access.setIssuerSignatureAlgorithm(certificate.getSigAlgName());
			
			super.access.setSerialNumber(certificate.getSerialNumber().toString());
			
			super.access.setNotAfter(certificate.getNotAfter());
			super.access.setNotBefore(certificate.getNotBefore());
			
			super.access.setPublicKeyDigestAlgorithm(certificate.getSigAlgName());
			super.access.setSubjectSignatureAlgorithm(certificate.getPublicKey().getAlgorithm());
			RSAPublicKey rsaPk = (RSAPublicKey) certificate.getPublicKey();
			int pKLen=rsaPk.getModulus().bitLength();
			super.access.setPublicKeyParameter(""+pKLen);	
			
			boolean[] keyUsageVal=certificate.getKeyUsage();
			if(keyUsageVal!=null) {
				super.access.setKeyUsage(keyUsageVal);
				super.access.setCritical(Constants.KU, true);
			}
			
			return 1;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return -1;
	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		Enumeration<String> enumeration=null;
		File file=new File(LOCAL_KEY_STORE_PATH);
		FileInputStream inStream=null;
		try {
			localKeyStore=KeyStore.getInstance("PKCS12");	
			if(file.exists() && file.isFile()) {
				inStream= new FileInputStream(file);
				localKeyStore.load(inStream, LOCAL_KEY_STORAGE_PASS.toCharArray());
			}
			else {
				localKeyStore.load(null, LOCAL_KEY_STORAGE_PASS.toCharArray());
			}
			enumeration=localKeyStore.aliases();
		} catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			try {
				if(inStream!=null) {
					inStream.close();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return enumeration;
	}
	
	public void saveLocalKeystore() {
		File file=new File(LOCAL_KEY_STORE_PATH);
		FileOutputStream oStream=null;
		try {
			if (!file.exists()) {
				file.createNewFile();
			}
			oStream=new FileOutputStream(file);
			localKeyStore.store(oStream, LOCAL_KEY_STORAGE_PASS.toCharArray());
			oStream.flush();
		} catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			if(oStream!=null) {
				try {
					oStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	@Override
	public boolean removeKeypair(String arg0) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void resetLocalKeystore() {
		File file=new File(LOCAL_KEY_STORE_PATH);
		if(file.exists()) {
			file.delete();
		}
		this.loadLocalKeystore();
	}

	@SuppressWarnings("deprecation")
	@Override
	public boolean saveKeypair(String keypair_name) {	
		KeyPair keyPair=null;
		KeyPairGenerator keyPairGenerator=null;
		String algorithm=super.access.getPublicKeyDigestAlgorithm();
		try {
			keyPairGenerator= KeyPairGenerator.getInstance("RSA", "BC");
			int keySize=Integer.parseInt(super.access.getPublicKeyParameter());
			keyPairGenerator.initialize(keySize);
			keyPair=keyPairGenerator.generateKeyPair();	
			X509Name x509Name= new X509Name(
					"C=" + this.access.getSubjectCountry() + ", " +
					"ST=" + this.access.getSubjectState() + ", " +
					"L=" + this.access.getSubjectLocality()+ ", " +
					"O=" + this.access.getSubjectOrganization() + ", " +
					"OU=" + this.access.getSubjectOrganizationUnit() + ", " +
					"CN=" + this.access.getSubjectCommonName());
			BigInteger serialNumber=new BigInteger(this.access.getSerialNumber());      
			X509V3CertificateGenerator gen= new X509V3CertificateGenerator();	
			gen.setSerialNumber(serialNumber);
			gen.setSubjectDN(x509Name);
			gen.setIssuerDN(x509Name);
			gen.setNotBefore(super.access.getNotBefore());
			gen.setNotAfter(super.access.getNotAfter());
			gen.setSignatureAlgorithm(algorithm);
			gen.setPublicKey(keyPair.getPublic());
			
			boolean[] keyUsageValues=super.access.getKeyUsage();
			int keyusageValue=0;
			for(int i=0; i<keyUsageValues.length; i++) {
				if(keyUsageValues[i]) {
					switch(i) {
						case 0:
							keyusageValue=keyusageValue|KeyUsage.digitalSignature;
							break;
						case 1:
							keyusageValue=keyusageValue|KeyUsage.nonRepudiation;
							break;
						case 2:
							keyusageValue=keyusageValue|KeyUsage.keyEncipherment;
							break;
						case 3:
							keyusageValue=keyusageValue|KeyUsage.dataEncipherment;
							break;
						case 4:
							keyusageValue=keyusageValue|KeyUsage.keyAgreement;
							break;
						case 5:
							keyusageValue=keyusageValue|KeyUsage.keyCertSign;
							break;
						case 6:
							keyusageValue=keyusageValue|KeyUsage.cRLSign;
							break;
						case 7:
							keyusageValue=keyusageValue|KeyUsage.encipherOnly;
							break;
						case 8:
							keyusageValue=keyusageValue|KeyUsage.decipherOnly;
							break;
					}
				}
			}
			if(keyusageValue!=0) {
				KeyUsage keyUsage=new KeyUsage(keyusageValue);
				gen.addExtension(X509Extensions.KeyUsage, true, keyUsage);
			}
			java.security.cert.X509Certificate certificate=gen.generate(keyPair.getPrivate(), "BC");			
			localKeyStore.setCertificateEntry(keypair_name, certificate);			
			saveLocalKeystore();
			loadLocalKeystore();
			return true;
		} catch (Exception e) {
			e.printStackTrace();
		}	
		return false;
	}

	@Override
	public boolean signCSR(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}

}
