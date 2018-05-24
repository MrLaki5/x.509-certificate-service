package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Security;
import java.util.Enumeration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import code.GuiException;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {
	
	private static String LOCAL_KEY_STORE_PATH="/Users/milanlazarevic/Desktop/myStore.pkcs12";
	private static String LOCAL_KEY_STORAGE_PASS="12345678";
	
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
	public int loadKeypair(String arg0) {
		// TODO Auto-generated method stub
		return 0;
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
	}

	@Override
	public boolean saveKeypair(String arg0) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean signCSR(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}

}
