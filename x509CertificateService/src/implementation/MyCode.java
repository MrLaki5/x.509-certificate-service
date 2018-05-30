package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.Set;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import code.GuiException;
import gui.Constants;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {
	
	//Path of application key store
	private static String LOCAL_KEY_STORE_PATH="/Users/milanlazarevic/Desktop/myStore.pkcs12";
	//Password of application key store
	private static String LOCAL_KEY_STORAGE_PASS="password";
	//Object used in signing certification request (CSR) 
	private PKCS10CertificationRequest importedCsr;
	//Application key store
	private KeyStore localKeyStore;
	//exportKeypair exports whole chain-true, exports only head certificate-false
	private static boolean KEYPAIR_EXPORT_PARAM=true;

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
		//Adding bouncy castle as provider
		Security.addProvider(new BouncyCastleProvider());
	}
	
	//Method for saving one untrusted certificate (can be CA) or key pair to key store
	protected boolean saveKeyPairToLocalStorage(String alias, Key key, java.security.cert.Certificate certificate) {
		//Create certificate chain with one element
		java.security.cert.Certificate []certificates= new java.security.cert.X509Certificate[1];
		certificates[0]=certificate;
		try {
			//Save chain to key store and key store to file, reload
			localKeyStore.setKeyEntry(alias, key, null, certificates);
			saveLocalKeystore();
			loadLocalKeystore();
			return true;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	//Method for saving untrusted certificate chain (can be CA) or key pair with chain to key store
	protected boolean saveKeyPairToLocalStorage(String alias, Key key, java.security.cert.Certificate[] certificates) {
		try {
			//Save chain to key store and key store to file, reload
			localKeyStore.setKeyEntry(alias, key, null, certificates);
			saveLocalKeystore();
			loadLocalKeystore();
			return true;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	//Method for saving trusted certificate to key store
	protected boolean saveCertificateToLocalStorage(String alias, java.security.cert.Certificate certificate) {
		try {
			//Save certificate to key store and key store to file, reload
			localKeyStore.setCertificateEntry(alias, certificate);
			saveLocalKeystore();
			loadLocalKeystore();
			return true;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	//Method for checking key store entry type: 0-key pair, 1-not trusted certificate, 2-trusted certificate, -1 error
	protected int checkTypeOfKeyStoreEntry(java.security.cert.Certificate certificate) {
		String keypair_name;
		try {
			keypair_name = localKeyStore.getCertificateAlias(certificate);
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return -1;
		}
		int retInt=0;
		try {
			//If certificate is in certificate entry then its trusted certificate
			if(localKeyStore.isCertificateEntry(keypair_name)) {
				retInt=2;
			}
			//Check if certificate is self signed
			PublicKey pubKey=certificate.getPublicKey();
			certificate.verify(pubKey);
			//If its self signed and it can sign, its CA
			if(canSign(keypair_name)) {
				retInt=1;
			}
		}
		catch(Exception ex) {
			//Its not self signed but its not trusted
			retInt=1;
		}
		return retInt;
	}
	
	//Used to check if certificate is CA in GUI
	@Override
	public boolean canSign(String keypair_name) {
		try {
			java.security.cert.X509Certificate certificate= (java.security.cert.X509Certificate) localKeyStore.getCertificate(keypair_name);
			if(certificate!=null) {
				//If certificate is CA it has set basic constraints extension
				if(certificate.getBasicConstraints()!=-1) {
					//Extra check for bug on android 1.7
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

	//Method used when exporting certificate sign request (CSR)
	@Override
	public boolean exportCSR(String filePath, String keypair_name, String algorithm) {
		FileOutputStream oStream=null;	
		try {
			java.security.cert.X509Certificate certificate=(X509Certificate) localKeyStore.getCertificate(keypair_name);
			if(certificate!=null) {
				//Check if certificate is key pair
				int certType=checkTypeOfKeyStoreEntry(certificate);
				if(certType!=-1) {
					if(certType==2 || certType==1) {
						super.access.reportError("CSR only available for keypair");
						return false;
					}
				}
				else {
					return false;
				}
				File file=new File(filePath);
				if (!file.exists()) {
					file.createNewFile();
				}
				//Build PKCS#10 object and flush it into file
				oStream=new FileOutputStream(file);
				//Get subject info
				X500Principal subject=certificate.getSubjectX500Principal();
				//Get public key from key pair
				PublicKey publicKey=certificate.getPublicKey();
				PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);		
				ContentSigner signGen = new JcaContentSignerBuilder(algorithm).build((PrivateKey)localKeyStore.getKey(keypair_name, null));		
				PKCS10CertificationRequest csr = builder.build(signGen);
				oStream.write(csr.getEncoded());
				oStream.flush();
				return true;
			}
		}
		catch(Exception e) {
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

	//Method for exporting certificate
	@Override
	public boolean exportCertificate(String fileName, String keypair_name, int encoding, int format) {
		FileOutputStream oStream=null;
		try {
			if(localKeyStore.containsAlias(keypair_name)) {
				java.security.cert.Certificate certificate=(java.security.cert.Certificate) localKeyStore.getCertificate(keypair_name);
				if(certificate==null) {
					return false;
				}
				//Check if certificate is not key pair
				int certType=checkTypeOfKeyStoreEntry(certificate);
				if(certType!=-1) {
					if(certType==0) {
						super.access.reportError("Certificate export only available for certificates");
						return false;
					}
				}
				else {
					return false;
				}
				File file=new File(fileName);
				if (!file.exists()) {
					file.createNewFile();
				}
				oStream=new FileOutputStream(file);
				//PEM encoding
				if(encoding==1) {
					//Head
					if(format==0) {
						//Put head certificate to file stream
						byte[] bCert=certificate.getEncoded();
						String encoded="-----BEGIN CERTIFICATE-----\n" + Base64.getEncoder().encodeToString(bCert)+ "-----END CERTIFICATE-----";
						oStream.write(encoded.getBytes());
					}
					//Entire chain (can only be in PEM encoding)
					else {
						//Put chain to file stream
						java.security.cert.Certificate[] certificates= localKeyStore.getCertificateChain(keypair_name);
						//If its certificate entry, chain will be null. So create it
						if(certificates==null) {
							certificates=new java.security.cert.X509Certificate[1];
							certificates[0]=certificate;
						}
						for(int i=0; i<certificates.length; i++) {
							java.security.cert.Certificate tempCert=certificates[i];
							byte[] bCert=tempCert.getEncoded();
							String encoded="-----BEGIN CERTIFICATE-----\n" + Base64.getEncoder().encodeToString(bCert)+ "\n-----END CERTIFICATE-----";
							if((i+1)<certificates.length) {
								encoded+="\n";
							}
							oStream.write(encoded.getBytes());
						}
					}
				}
				//DER encoding
				else {
					//Put certificate to file stream
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

	//Method for exporting key pair
	@Override
	public boolean exportKeypair(String keypair_name, String fileName, String password) {
		FileOutputStream oStream=null;
		try {
			if(localKeyStore.containsAlias(keypair_name)) {
				java.security.cert.X509Certificate certificate=(java.security.cert.X509Certificate) localKeyStore.getCertificate(keypair_name);
				//Check if certificate is not trusted. Trusted certificate does not have private key in key store
				int certType=checkTypeOfKeyStoreEntry(certificate);
				if(certType!=-1) {
					if(certType==2) {
						super.access.reportError("Private key unknown for given certificate");
						return false;
					}
				}
				else {
					return false;
				}
				File file=new File(fileName);
				if (!file.exists()) {
					file.createNewFile();
				}
				java.security.cert.Certificate[] certificates=null;
				//			TWO VARIANTS:
				//		1: exportKeyPair exports whole chain
				if(KEYPAIR_EXPORT_PARAM) {
					certificates= localKeyStore.getCertificateChain(keypair_name);
				}
				//		2: exportKeyPair exports only head certificate
				else {
					certificates= new java.security.cert.X509Certificate[1];
					certificates[0]=certificate;
				}
				//Put certificates in new export file and flush
				KeyStore tempKeyStore=KeyStore.getInstance("PKCS12");
				tempKeyStore.load(null, password.toCharArray());
				tempKeyStore.setKeyEntry(keypair_name, localKeyStore.getKey(keypair_name, null), password.toCharArray(), certificates);		
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

	//Method for getting name of public key algorithm of certificate
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

	//Method for getting length of RSA algorithm of certificate
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

	//Method for getting info about subject of certificate
	@Override
	public String getSubjectInfo(String keypair_name) {
		java.security.cert.X509Certificate certificate;
		try {
			certificate = (java.security.cert.X509Certificate) localKeyStore.getCertificate(keypair_name);
			//Remove spaces and empty fields, so GUI can read it nicely
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

	//Method for importing signed certificate and replacing it with key pair
	@Override
	public boolean importCAReply(String filePath, String keypair_name) {
		FileInputStream is=null;
		try {
			File file=new File(filePath);
			if(!file.exists()) {
				return false;
			}
			//Load CA reply to certificate chain
			is = new FileInputStream(file);
			java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X509");
			java.util.Collection collection=cf.generateCertificates( is );
			java.util.Iterator i = collection.iterator();
			java.security.cert.X509Certificate[] certChain=new java.security.cert.X509Certificate[collection.size()];
			int p=certChain.length-1;
			while ( i.hasNext() ) 
			{
			   java.security.cert.X509Certificate c = (java.security.cert.X509Certificate)i.next();
			   certChain[p]=c;
			   p--;
			}
			java.security.cert.X509Certificate oldCert=(X509Certificate) localKeyStore.getCertificate(keypair_name);
			if(oldCert!=null && certChain.length>1) {
				X500Principal oldSubPrincipal=oldCert.getSubjectX500Principal();
				X500Principal newSubPrincipal=certChain[0].getSubjectX500Principal();
				//Compare if imported certificate and selected key pair are same
				if(oldSubPrincipal.toString().equals(newSubPrincipal.toString())) {
					//Replace key pair with chain
					Key key=localKeyStore.getKey(keypair_name, null);
					localKeyStore.deleteEntry(keypair_name);
					saveKeyPairToLocalStorage(keypair_name, key, certChain);
					loadKeypair(keypair_name);
					return true;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			if(is!=null) {
				try {
					is.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return false;
	}

	//Method used for importing certificate sign request (CSR)
	@Override
	public String importCSR(String filePath) {
		try {
			File file=new File(filePath);
			if(!file.exists()) {
				return null;
			}
			//Load PKCS#10 from file
			java.nio.file.Path path = java.nio.file.Paths.get(filePath);
			byte[] data = java.nio.file.Files.readAllBytes(path);
			PKCS10CertificationRequest csrr=new PKCS10CertificationRequest(data);
			//Save it to this (used in signing certificate later)
			importedCsr=csrr;
			//Load subject info and return it
			String tempVr=csrr.getSubject().toString();
			String[] params=tempVr.split(",");
			String subStr="";
			for(int i=0; i<params.length; i++) {
				params[i]=params[i].trim();
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
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	//Method used for importing certificate as trusted certificate
	@Override
	public boolean importCertificate(String filePath, String keypair_name) {
		FileInputStream fStream=null;
		try {
			File file=new File(filePath);
			if(!file.exists()) {
				return false;
			}
			fStream=new FileInputStream(filePath);
			
			
			//Used if chain can be imported from certificate file 
			
			java.util.Collection  coll = java.security.cert.CertificateFactory.getInstance("X509").generateCertificates(fStream);
			java.util.Iterator iterator = coll.iterator();
			while(iterator.hasNext()) {
				java.security.cert.Certificate tempCert = (java.security.cert.Certificate) coll.iterator().next();
				saveCertificateToLocalStorage(keypair_name, tempCert);
				break;
			}
			
			
			//Load first certificate from file and save it to key store ass trusted certificate
			//java.security.cert.Certificate tempCert =java.security.cert.CertificateFactory.getInstance("X509").generateCertificate(fStream);
			//saveCertificateToLocalStorage(keypair_name, tempCert);
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

	//Method used for importing key pair
	@Override
	public boolean importKeypair(String keypair_name, String filePath, String password) {
		File file= new File(filePath);
		FileInputStream inStream=null;
		if(file.exists()) {
			try {
				//Go through all elements in key store and add them to application key storage (without trusted certificates (they have no private key))
				KeyStore tempKeyStore=KeyStore.getInstance("PKCS12");
				inStream= new FileInputStream(file);
				tempKeyStore.load(inStream, password.toCharArray());
				Enumeration<String> keyStoreAliases=tempKeyStore.aliases();
				while(keyStoreAliases.hasMoreElements()) {
					String tempAlias=keyStoreAliases.nextElement();
					java.security.cert.Certificate certificate=tempKeyStore.getCertificate(tempAlias);
					if(!tempKeyStore.isCertificateEntry(tempAlias)) {
						saveKeyPairToLocalStorage(keypair_name, tempKeyStore.getKey(tempAlias, password.toCharArray()), certificate);
					}
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

	//Method for loading selected key pair to GUI
	@Override
	public int loadKeypair(String keypair_name) {
		try {
			if(!localKeyStore.containsAlias(keypair_name)) {
				return -1;
			}
			super.access.setVersion(Constants.V3);
			java.security.cert.X509Certificate certificate=(java.security.cert.X509Certificate) localKeyStore.getCertificate(keypair_name);
			if(certificate==null) {
				return -1;
			}
			//Check type of key pair
			int retInt=checkTypeOfKeyStoreEntry(certificate);
			if(retInt==-1) {
				return retInt;
			}
			//Load subject info
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
			//If its certificate, load issuer info
			if(retInt==2 || retInt==1) {
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
			//Load serial number
			super.access.setSerialNumber(certificate.getSerialNumber().toString());
			//Load dates
			super.access.setNotAfter(certificate.getNotAfter());
			super.access.setNotBefore(certificate.getNotBefore());
			//Load algorithm
			super.access.setPublicKeyDigestAlgorithm(certificate.getSigAlgName());
			super.access.setSubjectSignatureAlgorithm(certificate.getPublicKey().getAlgorithm());
			RSAPublicKey rsaPk = (RSAPublicKey) certificate.getPublicKey();
			int pKLen=rsaPk.getModulus().bitLength();
			super.access.setPublicKeyParameter(""+pKLen);	
			//Load key usage extension
			boolean[] keyUsageVal=certificate.getKeyUsage();
			if(keyUsageVal!=null) {
				super.access.setKeyUsage(keyUsageVal);
				super.access.setCritical(Constants.KU, true);
			}
			//Find all critical extensions
			Set<String> criticalExtensions=certificate.getCriticalExtensionOIDs();
			//Load subject directory extension
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
			//Load inhabit any policy extension
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
				e.printStackTrace();
			}
			return retInt;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return -1;
	}

	//Method used for loading key store from file
	@Override
	public Enumeration<String> loadLocalKeystore() {
		Enumeration<String> enumeration=null;
		File file=new File(LOCAL_KEY_STORE_PATH);
		FileInputStream inStream=null;
		try {
			//If key store does not exist create it
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
	
	//Method used for saving key store to file
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

	//Method used for removing selected key pair from key store
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

	//Method used for deleting all key pairs from key storage
	@Override
	public void resetLocalKeystore() {
		File file=new File(LOCAL_KEY_STORE_PATH);
		if(file.exists()) {
			file.delete();
		}
		this.loadLocalKeystore();
	}

	//Method for saving created key pair to key store
	@SuppressWarnings("deprecation")
	@Override
	public boolean saveKeypair(String keypair_name) {	
		KeyPair keyPair=null;
		KeyPairGenerator keyPairGenerator=null;
		String algorithm=super.access.getPublicKeyDigestAlgorithm();
		try {
			//Generate keys
			keyPairGenerator= KeyPairGenerator.getInstance("RSA", "BC");
			int keySize=Integer.parseInt(super.access.getPublicKeyParameter());
			keyPairGenerator.initialize(keySize);
			keyPair=keyPairGenerator.generateKeyPair();	
			//Get subject info
			X509Principal x509Princ= new X509Principal(
					"C=" + this.access.getSubjectCountry() + ", " +
					"ST=" + this.access.getSubjectState() + ", " +
					"L=" + this.access.getSubjectLocality()+ ", " +
					"O=" + this.access.getSubjectOrganization() + ", " +
					"OU=" + this.access.getSubjectOrganizationUnit() + ", " +
					"CN=" + this.access.getSubjectCommonName());
			//Get serial number
			BigInteger serialNumber=new BigInteger(this.access.getSerialNumber());  
			//Set information to builder
			X509V3CertificateGenerator gen= new X509V3CertificateGenerator();	
			gen.setSerialNumber(serialNumber);
			gen.setSubjectDN(x509Princ);
			gen.setIssuerDN(x509Princ);
			gen.setNotBefore(super.access.getNotBefore());
			gen.setNotAfter(super.access.getNotAfter());
			gen.setSignatureAlgorithm(algorithm);
			gen.setPublicKey(keyPair.getPublic());
			//Get key usage extension
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
			//Get subject directory attributes extension
			Vector<Attribute> attributesTemp = new Vector<Attribute>();
			boolean flagsubDirAtrUsage=false;
			boolean isCriticalsubDirAtrUsage=super.access.isCritical(Constants.SDA);
			if(isCriticalsubDirAtrUsage) {
				super.access.reportError("Subject Directory Attributes extension must not be marked critical");
				return false;
			}
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
			//Get inhibit any policy extension
			boolean inhibitAnyPolicyFlag=super.access.getInhibitAnyPolicy();
			boolean isCriticalInhibitAnyPolicyFlag=super.access.isCritical(Constants.IAP);
			if(inhibitAnyPolicyFlag) {
				String skipCerts=super.access.getSkipCerts();
				if(!skipCerts.isEmpty()) {
					ASN1Integer skipCertsInteger = new ASN1Integer(new BigInteger(skipCerts));
					if(!isCriticalInhibitAnyPolicyFlag) {
						super.access.reportError("Inhibit any policy extension must be marked critical");
						return false;
					}
					gen.addExtension(Extension.inhibitAnyPolicy, isCriticalInhibitAnyPolicyFlag, skipCertsInteger);
				}
				else {
					super.access.reportError("Skip certs must be set in inhibit any policy extension");
					return false;
				}
			}
			//Save key pair to key store
			java.security.cert.X509Certificate certificate=gen.generate(keyPair.getPrivate(), "BC");
			saveKeyPairToLocalStorage(keypair_name, keyPair.getPrivate(), certificate);
			return true;
		} catch (Exception e) {
			e.printStackTrace();
		}	
		return false;
	}

	//Method used when certificate authority (CA) is signing certificate sign request (CRS)
	@SuppressWarnings("deprecation")
	@Override
	public boolean signCSR(String filePath, String keypair_name, String algorithm) {
		FileOutputStream oStream = null;
		try {
			java.security.cert.X509Certificate caCertificate=(java.security.cert.X509Certificate) localKeyStore.getCertificate(keypair_name);
			if(caCertificate!=null && importedCsr!=null) {
				//Get subject public key
				SubjectPublicKeyInfo pkInfo = importedCsr.getSubjectPublicKeyInfo();
				RSAKeyParameters rsa = (RSAKeyParameters) PublicKeyFactory.createKey(pkInfo);
				RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(rsa.getModulus(), rsa.getExponent());
				KeyFactory kf = KeyFactory.getInstance("RSA");
				PublicKey rsaPub = kf.generatePublic(rsaSpec);
				//Get subject info
				X509Principal x509Princ= new X509Principal(
						"C=" + this.access.getSubjectCountry() + ", " +
						"ST=" + this.access.getSubjectState() + ", " +
						"L=" + this.access.getSubjectLocality()+ ", " +
						"O=" + this.access.getSubjectOrganization() + ", " +
						"OU=" + this.access.getSubjectOrganizationUnit() + ", " +
						"CN=" + this.access.getSubjectCommonName());
				//Get serial number
				BigInteger serialNumber=new BigInteger(this.access.getSerialNumber());
				//Load certificate info to generator
				X509V3CertificateGenerator gen= new X509V3CertificateGenerator();	
				gen.setSerialNumber(serialNumber);
				gen.setSubjectDN(x509Princ);
				gen.setIssuerDN(caCertificate.getSubjectX500Principal());
				gen.setNotBefore(super.access.getNotBefore());
				gen.setNotAfter(super.access.getNotAfter());
				gen.setSignatureAlgorithm(algorithm);
				gen.setPublicKey(rsaPub);
				//Load key usage extension
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
				//Get subject directory attributes extension
				Vector<Attribute> attributesTemp = new Vector<Attribute>();
				boolean flagsubDirAtrUsage=false;
				boolean isCriticalsubDirAtrUsage=super.access.isCritical(Constants.SDA);
				if(isCriticalsubDirAtrUsage) {
					super.access.reportError("Subject Directory Attributes extension must not be marked critical");
					return false;
				}
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
				//Load inhibit any policy extension
				boolean inhibitAnyPolicyFlag=super.access.getInhibitAnyPolicy();
				boolean isCriticalInhibitAnyPolicyFlag=super.access.isCritical(Constants.IAP);
				if(inhibitAnyPolicyFlag) {
					String skipCerts=super.access.getSkipCerts();
					if(!skipCerts.isEmpty()) {
						ASN1Integer skipCertsInteger = new ASN1Integer(new BigInteger(skipCerts));
						if(!isCriticalInhibitAnyPolicyFlag) {
							super.access.reportError("Inhibit any policy extension must be marked critical");
							return false;
						}
						gen.addExtension(Extension.inhibitAnyPolicy, isCriticalInhibitAnyPolicyFlag, skipCertsInteger);
					}
					else {
						super.access.reportError("Skip certs must be set in inhibit any policy extension");
						return false;
					}
				}
				//Sign and generate certificate
				java.security.cert.X509Certificate certificate=gen.generate((PrivateKey)localKeyStore.getKey(keypair_name, null), "BC");
				//Create certificate authority reply generator
				CMSSignedDataGenerator gen1 = new CMSSignedDataGenerator();
				//Create certificate chain
				java.util.List<X509Certificate> certificates = new java.util.ArrayList<>();
				certificates.add((X509Certificate) caCertificate);
				certificates.add((X509Certificate) certificate);
				//Put certificate chain to holders
				java.util.Collection<JcaX509CertificateHolder> x509CertificateHolder = new java.util.ArrayList<>();			
				for (X509Certificate certificateTemp : certificates) {
					x509CertificateHolder.add(new JcaX509CertificateHolder(certificateTemp));
				}
				CollectionStore<JcaX509CertificateHolder> store = new CollectionStore<>(x509CertificateHolder);
				//Add certificate chain to certificate authority reply generator
				gen1.addCertificates(store);
				//Reply encoded data
				CMSTypedData content = new CMSProcessableByteArray(certificate.getEncoded());
				//Generate certificate authority reply and flush it to file
				CMSSignedData signedData = gen1.generate(content, true);	 
				File file=new File(filePath);
				if (!file.exists()) {
					file.createNewFile();
				}		
				oStream=new FileOutputStream(filePath);
				oStream.write(signedData.getEncoded());
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
}
