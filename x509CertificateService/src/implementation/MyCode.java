package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Set;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

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
	
	protected boolean saveKeyPairToLocalStorage(String alias, Key key, java.security.cert.Certificate certificate) {
		alias=alias.toLowerCase();
		java.security.cert.Certificate []certificates= new java.security.cert.X509Certificate[1];
		certificates[0]=certificate;
		try {
			localKeyStore.setKeyEntry(alias, key, null, certificates);
			saveLocalKeystore();
			loadLocalKeystore();
			return true;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	protected boolean saveCertificateToLocalStorage(String alias, java.security.cert.Certificate certificate) {
		alias=alias.toLowerCase();
		try {
			localKeyStore.setCertificateEntry(alias, certificate);
			saveLocalKeystore();
			loadLocalKeystore();
			return true;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public boolean canSign(String keypair_name) {
		try {
			java.security.cert.X509Certificate certificate= (java.security.cert.X509Certificate) localKeyStore.getCertificate(keypair_name);
			if(certificate!=null) {
				if(certificate.getBasicConstraints()!=-1) {
					if(certificate.getKeyUsage()[5]==true) {
						return true;
					}
				}
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public boolean exportCSR(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean exportCertificate(String fileName, String keypair_name, int encoding, int format) {
		FileOutputStream oStream=null;
		try {
			if(localKeyStore.containsAlias(keypair_name)) {
				java.security.cert.Certificate certificate=(java.security.cert.Certificate) localKeyStore.getCertificate(keypair_name);
				File file=new File(fileName);
				if (!file.exists()) {
					file.createNewFile();
				}
				oStream=new FileOutputStream(file);
				
				if(encoding==1) {
					if(format==0) {
						byte[] bCert=certificate.getEncoded();
						String encoded="-----BEGIN CERTIFICATE-----\n" + Base64.getEncoder().encodeToString(bCert)+ "-----END CERTIFICATE-----";
						oStream.write(encoded.getBytes());
					}
					else {
						java.security.cert.Certificate[] certificates= localKeyStore.getCertificateChain(keypair_name);
						if(certificates==null) {
							certificates=new java.security.cert.X509Certificate[1];
							certificates[0]=certificate;
						}
						for(int i=0; i<certificates.length; i++) {
							java.security.cert.Certificate tempCert=certificates[i];
							byte[] bCert=tempCert.getEncoded();
							String encoded="-----BEGIN CERTIFICATE-----\n" + Base64.getEncoder().encodeToString(bCert)+ "\n-----END CERTIFICATE-----";
							oStream.write(encoded.getBytes());
						}
					}
				}
				else {
					oStream.write(certificate.getEncoded());
				}
				
				oStream.flush();
				return true;
			}
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
		return false;
	}

	@Override
	public boolean exportKeypair(String keypair_name, String fileName, String password) {
		FileOutputStream oStream=null;
		try {
			if(localKeyStore.containsAlias(keypair_name)) {
				java.security.cert.X509Certificate certificate=(java.security.cert.X509Certificate) localKeyStore.getCertificate(keypair_name);
				File file=new File(fileName);
				if (!file.exists()) {
					file.createNewFile();
				}		
				java.security.cert.Certificate[] certificates= new java.security.cert.X509Certificate[1];
				certificates[0]=certificate;			
				KeyStore tempKeyStore=KeyStore.getInstance("PKCS12");
				tempKeyStore.load(null, password.toCharArray());
				tempKeyStore.setKeyEntry(keypair_name, localKeyStore.getKey(keypair_name, null), null, certificates);		
				oStream=new FileOutputStream(file);
				tempKeyStore.store(oStream, password.toCharArray());
				oStream.flush();
				return true;
			}
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
		return false;
	}

	@Override
	public String getCertPublicKeyAlgorithm(String keypair_name) {
		java.security.cert.X509Certificate certificate;
		try {
			certificate = (java.security.cert.X509Certificate) localKeyStore.getCertificate(keypair_name);			
			return certificate.getPublicKey().getAlgorithm();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return "";
	}

	@Override
	public String getCertPublicKeyParameter(String keypair_name) {
		java.security.cert.X509Certificate certificate;
		try {
			certificate = (java.security.cert.X509Certificate) localKeyStore.getCertificate(keypair_name);	
			RSAPublicKey rsaPk = (RSAPublicKey) certificate.getPublicKey();
			int pKLen=rsaPk.getModulus().bitLength();
			return ""+pKLen;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return "";
	}

	@Override
	public String getSubjectInfo(String keypair_name) {
		java.security.cert.X509Certificate certificate;
		try {
			certificate = (java.security.cert.X509Certificate) localKeyStore.getCertificate(keypair_name);
			Principal principal=certificate.getSubjectDN();
			String[] params=principal.getName().split(", ");
			String subStr="";
			for(int i=0; i<params.length; i++) {
				String []tempStr=params[i].split("=");
				if(tempStr.length<=1) {
					continue;
				}
				subStr+=params[i];
				if((i+1)<params.length) {
					subStr+=",";
				}
			}
			return subStr;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return "";
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
	public boolean importCertificate(String filePath, String keypair_name) {
		FileInputStream fStream=null;
		try {
			File file=new File(filePath);
			if(!file.exists()) {
				return false;
			}
			fStream=new FileInputStream(filePath);
			/*Collection  coll = java.security.cert.CertificateFactory.getInstance("X509").generateCertificates(fStream);
			Iterator iterator = coll.iterator();
			while(iterator.hasNext()) {
				java.security.cert.Certificate tempCert = (java.security.cert.Certificate) coll.iterator().next();
				saveCertificateToLocalStorage(keypair_name, tempCert);
				break;
			}*/
			java.security.cert.Certificate tempCert =java.security.cert.CertificateFactory.getInstance("X509").generateCertificate(fStream);
			saveCertificateToLocalStorage(keypair_name, tempCert);
			return true;
		} catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			if(fStream!=null) {
				try {
					fStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return false;
	}

	@Override
	public boolean importKeypair(String keypair_name, String filePath, String password) {
		File file= new File(filePath);
		FileInputStream inStream=null;
		if(file.exists()) {
			try {
				KeyStore tempKeyStore=KeyStore.getInstance("PKCS12");
				inStream= new FileInputStream(file);
				tempKeyStore.load(inStream, password.toCharArray());
				Enumeration<String> keyStoreAliases=tempKeyStore.aliases();
				while(keyStoreAliases.hasMoreElements()) {
					String tempAlias=keyStoreAliases.nextElement();
					java.security.cert.Certificate certificate=tempKeyStore.getCertificate(tempAlias);
					saveKeyPairToLocalStorage(tempAlias, tempKeyStore.getKey(tempAlias, null), certificate);
				}
				return true;
			} catch (Exception e) {
				e.printStackTrace();
			}
			finally {
				if(inStream!=null) {
					try {
						inStream.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}
		}
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
			
			int retInt=0;
			try {
				PublicKey pubKey=certificate.getPublicKey();
				certificate.verify(pubKey);
				if(localKeyStore.isCertificateEntry(keypair_name)) {
					retInt=2;
				}
			}
			catch(Exception ex) {
				retInt=0;
			}
			
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
			
			if(retInt==2) {
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
			}
			
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
			
			Set<String> criticalExtensions=certificate.getCriticalExtensionOIDs();
			
			byte[] subjectDirectoryBytes=certificate.getExtensionValue(Extension.subjectDirectoryAttributes.toString());
			try {
				if(subjectDirectoryBytes!=null) {
		            SubjectDirectoryAttributes subjectDirectoryAttributes = SubjectDirectoryAttributes.getInstance(X509ExtensionUtil.fromExtensionValue(subjectDirectoryBytes));
		            Vector<Attribute> attributes = subjectDirectoryAttributes.getAttributes();
		            for (Attribute attribute : attributes) {
		                if (attribute.getAttrType().equals(BCStyle.DATE_OF_BIRTH)) {
		                    ASN1UTCTime dateOfBirthTime = (ASN1UTCTime) attribute.getAttrValues().getObjectAt(0);
		                    SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMdd");
		                    access.setDateOfBirth(simpleDateFormat.format(dateOfBirthTime.getDate()));
		                } else if (attribute.getAttrType().equals(BCStyle.PLACE_OF_BIRTH)) {
		                    DEROctetString derOctetString = (DEROctetString) attribute.getAttrValues().getObjectAt(0);
		                    super.access.setSubjectDirectoryAttribute(Constants.POB, new String(derOctetString.getOctets()));
		                } else if (attribute.getAttrType().equals(BCStyle.COUNTRY_OF_CITIZENSHIP)) {
		                    DEROctetString derOctetString = (DEROctetString) attribute.getAttrValues().getObjectAt(0);
		                    super.access.setSubjectDirectoryAttribute(Constants.COC, new String(derOctetString.getOctets()));
		                } else if (attribute.getAttrType().equals(BCStyle.GENDER)) {
		                    DEROctetString derOctetString = (DEROctetString) attribute.getAttrValues().getObjectAt(0);
		                    super.access.setGender(new String(derOctetString.getOctets()));
		                }
		            }
		            if(criticalExtensions.contains(Extension.subjectDirectoryAttributes.toString())) {
		            	super.access.setCritical(Constants.SDA, true);
		            }
		        }
			}
			catch(Exception ex) {
				ex.printStackTrace();
			}
			
			byte[] inhabitAnyPolicyBytes = certificate.getExtensionValue(Extension.inhibitAnyPolicy.toString());
			try {
		        if (inhabitAnyPolicyBytes != null) {
		            ASN1Integer skipCertsInteger;
					skipCertsInteger = (ASN1Integer) X509ExtensionUtil.fromExtensionValue(inhabitAnyPolicyBytes);
		            super.access.setSkipCerts(skipCertsInteger.getValue().toString());
		            super.access.setInhibitAnyPolicy(true);
		            if(criticalExtensions.contains(Extension.inhibitAnyPolicy.toString())) {
		            	super.access.setCritical(Constants.IAP, true);
		            }
		        }
			}
			catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			return retInt;
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
	public boolean removeKeypair(String keypair_name) {
		try {
			if(localKeyStore.containsAlias(keypair_name)) {
				localKeyStore.deleteEntry(keypair_name);
				saveLocalKeystore();
				return true;
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
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
			
			Vector<Attribute> attributesTemp = new Vector<Attribute>();
			boolean flagsubDirAtrUsage=false;
			boolean isCriticalsubDirAtrUsage=super.access.isCritical(Constants.SDA);
			String gender=super.access.getGender();
			if(!gender.isEmpty()) {
				attributesTemp.add(new Attribute(BCStyle.GENDER, new DERSet(new DEROctetString(gender.getBytes()))));
				flagsubDirAtrUsage=true;
			}
			String countryAndCitizenship=super.access.getSubjectDirectoryAttribute(Constants.COC);
			if(!countryAndCitizenship.isEmpty()) {
				attributesTemp.add(new Attribute(BCStyle.COUNTRY_OF_CITIZENSHIP, new DERSet(new DEROctetString(countryAndCitizenship.getBytes()))));
				flagsubDirAtrUsage=true;
			}
			String dateOfBirth=super.access.getDateOfBirth();
			if(!dateOfBirth.isEmpty()) {
				SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMdd");
				Date dateOfBirthDate = simpleDateFormat.parse(dateOfBirth);
				attributesTemp.add(new Attribute(BCStyle.DATE_OF_BIRTH, new DERSet(new Time(dateOfBirthDate))));
				flagsubDirAtrUsage=true;
			}
			String placeOfBirth=super.access.getSubjectDirectoryAttribute(Constants.POB);
			if(!placeOfBirth.isEmpty()) {
				attributesTemp.add(new Attribute(BCStyle.PLACE_OF_BIRTH, new DERSet(new DEROctetString(placeOfBirth.getBytes()))));
				flagsubDirAtrUsage=true;
			}
			if(flagsubDirAtrUsage) {
				SubjectDirectoryAttributes attributes=new SubjectDirectoryAttributes(attributesTemp);			
				gen.addExtension(X509Extensions.SubjectDirectoryAttributes, isCriticalsubDirAtrUsage, attributes);
			}
			
			boolean inhibitAnyPolicyFlag=super.access.getInhibitAnyPolicy();
			boolean isCriticalInhibitAnyPolicyFlag=super.access.isCritical(Constants.IAP);
			if(inhibitAnyPolicyFlag) {
				String skipCerts=super.access.getSkipCerts();
				if(!skipCerts.isEmpty()) {
					ASN1Integer skipCertsInteger = new ASN1Integer(new BigInteger(skipCerts));
					gen.addExtension(Extension.inhibitAnyPolicy, isCriticalInhibitAnyPolicyFlag, skipCertsInteger);
				}
			}
			
			java.security.cert.X509Certificate certificate=gen.generate(keyPair.getPrivate(), "BC");
			saveKeyPairToLocalStorage(keypair_name, keyPair.getPrivate(), certificate);
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
