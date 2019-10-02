package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import code.GuiException;
import gui.Constants;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {
	
	KeyStore keyStore;
	
	private static final String keyStoreName = "myLocalKeyStore.p12";
	private static final char[] keyStorePassword = "qwerty".toCharArray();
	
	PKCS10CertificationRequest csr;

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
		// Auto-generated constructor stub
	}

	@Override
	public boolean canSign(String keypair_name) {
		try {
			
			X509Certificate certificate = (X509Certificate) keyStore.getCertificate(keypair_name);
			if (certificate.getBasicConstraints() != -1)
				return true;
			
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public boolean exportCSR(String file, String keypair_name, String algorithm) {
		try {
			
			X509Certificate certificate = (X509Certificate) keyStore.getCertificate(keypair_name);
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(keypair_name, keyStorePassword);
			
			PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(certificate.getSubjectX500Principal(), certificate.getPublicKey());
			
			JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(algorithm);
			ContentSigner signer = csBuilder.build(privateKey);
			
			PKCS10CertificationRequest CSR = p10Builder.build(signer);
			
			// write
			FileWriter FW = new FileWriter(file);
			PemWriter pw = new PemWriter(FW);
			
			pw.writeObject(new PemObject("CERTIFICATE REQUEST", CSR.getEncoded()));
			
			pw.flush();
			pw.close();
			
			return true;
			
		} catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException | OperatorCreationException | IOException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public boolean exportCertificate(String file, String keypair_name, int encoding, int format) {
		try {
			
			if (format == 0) {
				X509Certificate certificate = (X509Certificate) keyStore.getCertificate(keypair_name);
				byte[] encoded = certificate.getEncoded();
				
				if (encoding == 0) {	// DER formatted string
					FileOutputStream FOS = new FileOutputStream(file);
					
					FOS.write(encoded);
					FOS.close();
					
					return true;
				} else if (encoding == 1) {		//PEM formatted string			
					FileWriter FW = new FileWriter(file);
					PemWriter pw = new PemWriter(FW);
					
					pw.writeObject(new PemObject("CERTIFICATE", encoded));
					
					pw.flush();
					pw.close();
					
					return true;
				} else {
					System.out.println("Not supported encoding!");
					return false;
				}
			} else if (format == 1) {
				Certificate[] chain = keyStore.getCertificateChain(keypair_name);
				if (chain == null) {
					chain = new Certificate[]{keyStore.getCertificate(keypair_name)};
				}
				
				if (encoding == 1) {	//PEM formatted string			
					FileWriter FW = new FileWriter(file);
					PemWriter pw = new PemWriter(FW);
					
					for (Certificate certificate : chain) {
						byte[] encoded = certificate.getEncoded();
						pw.writeObject(new PemObject("CERTIFICATE", encoded));
					}
					
					pw.flush();
					pw.close();
					
					return true;
				} else {
					System.out.println("Not supported encoding!");
					return false;
				}
			} else {
				System.out.println("Not supported format!");
				return false;
			}
		} catch (KeyStoreException | CertificateEncodingException | IOException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public boolean exportKeypair(String keypair_name, String file, String password) {
        try {
        	FileOutputStream FOS = new FileOutputStream(file);
        	
            KeyStore temp = KeyStore.getInstance("PKCS12");
            temp.load(null, password.toCharArray());

            java.security.Key key = keyStore.getKey(keypair_name, keyStorePassword);
            Certificate[] chain = keyStore.getCertificateChain(keypair_name);

            temp.setKeyEntry(keypair_name, key, password.toCharArray(), chain);
            temp.store(FOS, password.toCharArray());
            
            FOS.close();
            
            return true;
            
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            e.printStackTrace();
        }
        return false;
    }

	@Override
	public String getCertPublicKeyAlgorithm(String keypair_name) {
		try {
			X509Certificate certificate = (X509Certificate) keyStore.getCertificate(keypair_name);
			
			return certificate.getPublicKey().getAlgorithm();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public String getCertPublicKeyParameter(String keypair_name) {
		try {
			X509Certificate certificate = (X509Certificate) keyStore.getCertificate(keypair_name);
		
			if (certificate.getPublicKey() instanceof DSAPublicKey) {
				
	        	return String.valueOf(((DSAPublicKey) certificate.getPublicKey()).getY().bitLength());
	        	
	        } else if (certificate.getPublicKey() instanceof RSAPublicKey) {	// ZATO STO JE ONAJ NJIHOV PRIMER RSA

	        	return String.valueOf(((RSAPublicKey) certificate.getPublicKey()).getModulus().bitLength());
	        	
	        } else {
	        	System.out.println("Algorithm not supported!");
	        	return null;
	        }
		
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		return null;
	}

	@Override
	public String getSubjectInfo(String keypair_name) {
		try {
			X509Certificate certificate = (X509Certificate) keyStore.getCertificate(keypair_name);
			JcaX509CertificateHolder certificateHolder = new JcaX509CertificateHolder(certificate);
            X500Name subjectInfo = certificateHolder.getSubject();
            
            String subject = (subjectInfo.toString() + " ").replaceAll(", ", ",").replaceAll("=,", "= ,").replaceAll("  ", " ");
            subject = subject.substring(0, subject.length() - 1);
            subject += ",SA=" + certificate.getSigAlgName();
            
            return subject;
		} catch (KeyStoreException | CertificateEncodingException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public boolean importCAReply(String file, String keypair_name) {
		try {
			
			FileInputStream FIS = new FileInputStream(file);
			
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			Iterator<? extends Certificate> iterator = certificateFactory.generateCertificates(FIS).iterator();
			
			List<Certificate> chainList = new ArrayList<>();
			
			while (iterator.hasNext()) {
				
				X509Certificate certificate = (X509Certificate)iterator.next();
				chainList.add(certificate);
			}
			
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(keypair_name, keyStorePassword);
			
			Certificate[] chain = new Certificate[chainList.size()];
	        
	        keyStore.deleteEntry(keypair_name);
	        keyStore.setKeyEntry(keypair_name, privateKey, keyStorePassword, chainList.toArray(chain));
		        
			save();
			// loadLocalKeystore();
	        
	        return true;
		} catch (CertificateException | FileNotFoundException | KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public String importCSR(String file) {
		try {
			PemReader pr = new PemReader(new InputStreamReader(new FileInputStream(file)));
			PemObject po = pr.readPemObject();
			pr.close();
			
			if (po.getType().equals("CERTIFICATE REQUEST") == false) {
				System.out.println("File is not CSR!");
				return null;
			}
			PKCS10CertificationRequest CSR = new PKCS10CertificationRequest(po.getContent());
			
			X500Name subjectInfo = CSR.getSubject();
			
            String subject = (subjectInfo.toString() + " ").replaceAll(", ", ",").replaceAll("=,", "= ,").replaceAll("  ", " ");
            subject = subject.substring(0, subject.length() - 1);
            DefaultAlgorithmNameFinder algorithmFinder = new DefaultAlgorithmNameFinder();
            subject += ",SA=" + algorithmFinder.getAlgorithmName(CSR.getSignatureAlgorithm());
            
            csr = CSR;
            return subject;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
 		}
	}

	@Override
	public boolean importCertificate(String file, String keypair_name) {
		try {
			FileInputStream FIS = new FileInputStream(file);
			
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(FIS);
	        keyStore.setCertificateEntry(keypair_name, certificate);
	        
	        save();
	        // loadLocalKeystore();
	        
	        return true;
		} catch (KeyStoreException | CertificateException | FileNotFoundException e) {
			e.printStackTrace();
		}
		
		return false;
	}

	@Override
	public boolean importKeypair(String keypair_name, String file, String password) {
        try {
            FileInputStream FIS = new FileInputStream(file);

            KeyStore temp = KeyStore.getInstance("PKCS12");
            temp.load(FIS, password.toCharArray());
            
            FIS.close();
            
            Enumeration<String> aliases = temp.aliases();
            String onlyKey = aliases.nextElement();
            if (aliases.hasMoreElements()) {
            	System.out.println("File has more than one key pair!");
            	return false;
            }

            java.security.Key key = temp.getKey(onlyKey, password.toCharArray()); //get key
            Certificate[] chain = temp.getCertificateChain(onlyKey); //get chain

            keyStore.setKeyEntry(keypair_name, key, keyStorePassword, chain);

            save();
            return true;

        } catch (UnrecoverableKeyException | NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
            e.printStackTrace();
        }
		return false;
	}

	@Override
	public int loadKeypair(String keypair_name) {
		
        try {
        	
        	X509Certificate certificate = (X509Certificate) keyStore.getCertificate(keypair_name);

            JcaX509CertificateHolder certificateHolder = new JcaX509CertificateHolder(certificate);
            X500Name issuerName = certificateHolder.getIssuer();
            X500Name subjectName = certificateHolder.getSubject();
            
//          String name = IETFUtils.valueToString(issuerName.getRDNs(BCStyle.CN)[0].getFirst().getValue());
            
            if (subjectName.getRDNs(BCStyle.C).length > 0)
                access.setSubjectCountry(IETFUtils.valueToString(subjectName.getRDNs(BCStyle.C)[0].getFirst().getValue()));
            if (subjectName.getRDNs(BCStyle.ST).length > 0)
                access.setSubjectState(IETFUtils.valueToString(subjectName.getRDNs(BCStyle.ST)[0].getFirst().getValue()));
            if (subjectName.getRDNs(BCStyle.L).length > 0)
                access.setSubjectLocality(IETFUtils.valueToString(subjectName.getRDNs(BCStyle.L)[0].getFirst().getValue()));
            if (subjectName.getRDNs(BCStyle.O).length > 0)
                access.setSubjectOrganization(IETFUtils.valueToString(subjectName.getRDNs(BCStyle.O)[0].getFirst().getValue()));
            if (subjectName.getRDNs(BCStyle.OU).length > 0)
                access.setSubjectOrganizationUnit(IETFUtils.valueToString(subjectName.getRDNs(BCStyle.OU)[0].getFirst().getValue()));
            if (subjectName.getRDNs(BCStyle.CN).length > 0)
                access.setSubjectCommonName(IETFUtils.valueToString(subjectName.getRDNs(BCStyle.CN)[0].getFirst().getValue()));
            access.setSubjectSignatureAlgorithm(certificate.getSigAlgName());
            
            access.setIssuer((issuerName.toString() + " ").replaceAll(", ", ",").replaceAll("=,", "= ,").replaceAll("  ", " "));
            access.setIssuerSignatureAlgorithm(certificate.getSigAlgName());

            access.setVersion(certificateHolder.getVersionNumber() - 1);
            
            access.setSerialNumber(String.valueOf(certificate.getSerialNumber()));
            
            access.setNotBefore(certificate.getNotBefore());
            access.setNotAfter(certificate.getNotAfter());
            
            if (certificate.getPublicKey() instanceof DSAPublicKey) {
            	access.setPublicKeyAlgorithm("DSA");
            	access.setPublicKeyParameter(String.valueOf(((DSAPublicKey) certificate.getPublicKey()).getY().bitLength()));
            } else if (certificate.getPublicKey() instanceof RSAPublicKey) {	// ZATO STO JE ONAJ NJIHOV PRIMER RSA
            	access.setPublicKeyAlgorithm("RSA");
            	access.setPublicKeyParameter(String.valueOf(((RSAPublicKey) certificate.getPublicKey()).getModulus().bitLength()));
            } else {
            	System.out.println("Algorithm is not supported!");
            	return -1;
            }
            access.setPublicKeyDigestAlgorithm(certificate.getSigAlgName());
            
            
            //EKSTENZIJE
            Set<String> criticalSet = certificate.getCriticalExtensionOIDs();
            
            if (criticalSet != null && !criticalSet.isEmpty()) {
                for (String oid : criticalSet) {
                    if (oid.equals("2.5.29.14")) {
                    	access.setCritical(Constants.SKID, true);
                    } else if (oid.equals("2.5.29.17")) {
                    	access.setCritical(Constants.SAN, true);
                    } else if (oid.equals("2.5.29.37")) {
                    	access.setCritical(Constants.EKU, true);
                    }
                }
            }
            
            // subject key identifier
            byte[] DER = certificate.getExtensionValue("2.5.29.14");
            
            if (DER != null) {
            	access.setEnabledSubjectKeyID(true);
            	
				String subjectKeyId = JcaX509ExtensionUtils.parseExtensionValue(DER).toString();
				access.setSubjectKeyID(subjectKeyId);
            }
            
            // subject alternative name  
			Collection<List<?>> names =  certificate.getSubjectAlternativeNames();
			
			if (names != null) {
				StringBuilder SB = new StringBuilder(); 
				for (List<?> item : names) {
					SB.append(item.get(1));		// 1 zato sto je rfc822Name
				}
				access.setAlternativeName(Constants.SAN, SB.toString());
			}

			// extended key usage
			List<String> extendedKeyUsage = certificate.getExtendedKeyUsage();
			
			if (extendedKeyUsage != null) {
				boolean[] myExtendedKeyUsage = new boolean[7]; 
				for (String item : extendedKeyUsage) {
					switch (item) {
					case "2.5.29.37.0":
						myExtendedKeyUsage[0] = true;
						break;
					case "1.3.6.1.5.5.7.3.1":
						myExtendedKeyUsage[1] = true;
						break;
					case "1.3.6.1.5.5.7.3.2":
						myExtendedKeyUsage[2] = true;
						break;
					case "1.3.6.1.5.5.7.3.3":
						myExtendedKeyUsage[3] = true;
						break;
					case "1.3.6.1.5.5.7.3.4":
						myExtendedKeyUsage[4] = true;
						break;
					case "1.3.6.1.5.5.7.3.8":
						myExtendedKeyUsage[5] = true;
						break;
					case "1.3.6.1.5.5.7.3.9":
						myExtendedKeyUsage[6] = true;
						break;
					default:
						System.out.println("Extended key usage error!");
						return -1;
					}
				}
				access.setExtendedKeyUsage(myExtendedKeyUsage);
			}
            
                
        } catch (KeyStoreException | CertificateEncodingException | IOException | CertificateParsingException e) {
			e.printStackTrace();
			return -1;
		}
        
        // return statment   
        try {
			if (keyStore.isCertificateEntry(keypair_name)) {
			    return 2;
			} else if (keyStore.getCertificateChain(keypair_name).length == 1) {
			    return 0;
			} else {
			    return 1;
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return -1;
		}
	}
	

	@Override
	public Enumeration<String> loadLocalKeystore() {
		
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            
            File file = new File(keyStoreName);
            
            if (file.exists()) {
            	FileInputStream FIS = new FileInputStream(keyStoreName);
            	keyStore.load(FIS, keyStorePassword);
            	FIS.close();
            	return keyStore.aliases();
            } else {
            	keyStore.load(null, keyStorePassword);
            }
            
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            e.printStackTrace();
        }
		return null;
	}

	@Override
	public boolean removeKeypair(String keypair_name) {
		try {
			keyStore.deleteEntry(keypair_name);
			save();
			// loadLocalKeystore();
			return true;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public void resetLocalKeystore() {
		
		try {
			int size = keyStore.size();
			for (int i = 0; i < size; i++) {
				keyStore.deleteEntry(keyStore.aliases().nextElement());		// isprazni key store
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
        File file = new File(keyStoreName);		// obrisi local key store
        if (file.exists()) 
            file.delete();    
	}

	@Override
	public boolean saveKeypair(String keypair_name) {
		
		// ne smeju dva kljuca da imaju isto ime
		try {
			if (keyStore.containsAlias(keypair_name)) 
				return false;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		//UCITAVANJE
		String C = access.getSubjectCountry();
		String ST =  access.getSubjectState();
		String L = access.getSubjectLocality();
		String O = access.getSubjectOrganization();
		String OU = access.getSubjectOrganizationUnit();
		String CN = access.getSubjectCommonName();
		
		//String access.getIssuerSignatureAlgorithm();
		
		int certificateVersion = access.getVersion();
		if (certificateVersion != Constants.V3) {
			System.out.println("Not supported version!");
			return false;
		}
		
		String serialNumber = access.getSerialNumber();
		
		Date notBefore = access.getNotBefore();
		Date notAfter = access.getNotAfter();
        
		String algorithm = access.getPublicKeyAlgorithm();
        if (algorithm != "DSA") {
        	System.out.println("Not supported algorithm!");
        	return false;
        }
        String keyLength = access.getPublicKeyParameter();
        String hashAlgorithm = access.getPublicKeyDigestAlgorithm();
        
        // EKSTENZIJE SKID, SAN, EKU
        if (access.isSupported(Constants.AKID) ||
        	access.isSupported(Constants.KU) ||
        	access.isSupported(Constants.CP) ||
        	access.isSupported(Constants.PM) ||
        	access.isSupported(Constants.IAN) ||
        	access.isSupported(Constants.SDA) ||
        	access.isSupported(Constants.BC) ||
        	access.isSupported(Constants.NC) ||
        	access.isSupported(Constants.PC) ||
        	access.isSupported(Constants.CRLDP) ||
        	access.isSupported(Constants.IAP) ||
        	access.isSupported(Constants.FCRL)) {
        	
        	System.out.println("Not supported extension!");
        	return false;
        }
        
        boolean criticalSKID = access.isCritical(Constants.SKID);
        boolean criticalSAN = access.isCritical(Constants.SAN);
        boolean criticalEKU = access.isCritical(Constants.EKU);
        
        boolean enableSKID =  access.getEnabledSubjectKeyID();
        String[] alternativeNamesSAN = access.getAlternativeName(Constants.SAN);
        boolean[] checkboxsEKU = access.getExtendedKeyUsage();
        // END EKSTENZIJE
        // END UCITAVANJE
        
        KeyPair keyPair = null;
        
        // Generate KeyPair
        KeyPairGenerator KPG;
		try {
			KPG = KeyPairGenerator.getInstance(algorithm);
			KPG.initialize(Integer.parseInt(keyLength));
	        keyPair = KPG.genKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} 
        // END Generate KeyPair
        
        // Create certificate		
		try {
        
	        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
	        builder.addRDN(BCStyle.C, C);
	        builder.addRDN(BCStyle.ST, ST);
	        builder.addRDN(BCStyle.L, L);
	        builder.addRDN(BCStyle.O, O);
	        builder.addRDN(BCStyle.OU, OU);
	        builder.addRDN(BCStyle.CN, CN);
	        X500Name subject = builder.build();
	        
	        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(subject, new BigInteger(serialNumber), notBefore, notAfter, subject, keyPair.getPublic());
	        
	//        X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
	//        
	//        generator.setSerialNumber(new BigInteger(serialNumber));
	//        generator.setSignatureAlgorithm(algorithm);
	//        generator.setIssuerDN(new X500Principal(subject.toString()));
	//        generator.setNotBefore(notBefore);
	//        generator.setNotAfter(notAfter);
	//        generator.setSubjectDN(new X500Principal(subject.toString()));
	//        generator.setPublicKey(keyPair.getPublic());
	        
	        // SKID
	        if (enableSKID) 
	        	certificateBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, criticalSKID, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic()));
	        
	        // SAN
	        if (alternativeNamesSAN.length > 0) {
	        	GeneralName[] all = new GeneralName[alternativeNamesSAN.length];
	        	
	            for (int i = 0; i < alternativeNamesSAN.length; i++)
	                all[i] = new GeneralName(GeneralName.dNSName, alternativeNamesSAN[i]);	//rfc822Name
	            
	            GeneralNames alternativeNames = new GeneralNames(all);
	            
	            certificateBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, criticalSAN, alternativeNames);
	        }
	        
	        // EKU
	        int length = 0;
	        for (int i = 0; i < checkboxsEKU.length; i++)
	        	if (checkboxsEKU[i])
	        		length++;
	        
	        if (length > 0) {
	        	
		        KeyPurposeId[] KPI = new KeyPurposeId[length];
		        
		        int i = 0;
		        if (checkboxsEKU[0]) 
		        	KPI[i++] = KeyPurposeId.anyExtendedKeyUsage;
		        if (checkboxsEKU[1]) 
		        	KPI[i++] = KeyPurposeId.id_kp_serverAuth;
		        if (checkboxsEKU[2]) 
		        	KPI[i++] = KeyPurposeId.id_kp_clientAuth;
		        if (checkboxsEKU[3]) 
		        	KPI[i++] = KeyPurposeId.id_kp_codeSigning;
		        if (checkboxsEKU[4]) 
		        	KPI[i++] = KeyPurposeId.id_kp_emailProtection;
		        if (checkboxsEKU[5]) 
		        	KPI[i++] = KeyPurposeId.id_kp_timeStamping;
		        if (checkboxsEKU[6]) 
		        	KPI[i++] = KeyPurposeId.id_kp_OCSPSigning;
		        
		        certificateBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, criticalEKU, new ExtendedKeyUsage(KPI));
	        }
	        
	        ContentSigner signer = new JcaContentSignerBuilder(hashAlgorithm).build(keyPair.getPrivate());
	        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer));
	        
	        keyStore.setKeyEntry(keypair_name, keyPair.getPrivate(), keyStorePassword, new Certificate[]{certificate});
	        
	        save();
	        
	        return true;
        
		} catch (CertIOException | NoSuchAlgorithmException | OperatorCreationException | CertificateException | KeyStoreException e) {
			e.printStackTrace();
		}
        
		return false;
		
	}

	@Override
	public boolean signCSR(String file, String keypair_name, String algorithm) {
		
		if (csr == null) {
			System.out.print("Greska!");
			return false;
		}
		JcaPKCS10CertificationRequest jcaCSR = new JcaPKCS10CertificationRequest(csr);
		
		//UCITAVANJE
		int certificateVersion = access.getVersion();
		if (certificateVersion != Constants.V3) {
			System.out.println("Not supported version!");
			return false;
		}
		
		String serialNumber = access.getSerialNumber();
		
		Date notBefore = access.getNotBefore();
		Date notAfter = access.getNotAfter();
        
        // EKSTENZIJE SKID, SAN, EKU
        if (access.isSupported(Constants.AKID) ||
        	access.isSupported(Constants.KU) ||
        	access.isSupported(Constants.CP) ||
        	access.isSupported(Constants.PM) ||
        	access.isSupported(Constants.IAN) ||
        	access.isSupported(Constants.SDA) ||
        	access.isSupported(Constants.BC) ||
        	access.isSupported(Constants.NC) ||
        	access.isSupported(Constants.PC) ||
        	access.isSupported(Constants.CRLDP) ||
        	access.isSupported(Constants.IAP) ||
        	access.isSupported(Constants.FCRL)) {
        	
        	System.out.println("Not supported extension!");
        	return false;
        }
        
        boolean criticalSKID = access.isCritical(Constants.SKID);
        boolean criticalSAN = access.isCritical(Constants.SAN);
        boolean criticalEKU = access.isCritical(Constants.EKU);
        
        boolean enableSKID =  access.getEnabledSubjectKeyID();
        String[] alternativeNamesSAN = access.getAlternativeName(Constants.SAN);
        boolean[] checkboxsEKU = access.getExtendedKeyUsage();
        // END EKSTENZIJE
        // END UCITAVANJE
        
        try {
		
			PrivateKey CAPrivateKey = (PrivateKey) keyStore.getKey(keypair_name, keyStorePassword);
			X509Certificate CAcertificate = (X509Certificate) keyStore.getCertificate(keypair_name);
	        
	        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(CAcertificate, new BigInteger(serialNumber), notBefore, notAfter, jcaCSR.getSubject(), jcaCSR.getPublicKey());
	
	        // EKSTENZIJE
	        // SKID
	        if (enableSKID) 
	        	certificateBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, criticalSKID, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(jcaCSR.getPublicKey()));
	        
	        // SAN
	        if (alternativeNamesSAN.length > 0) {
	        	GeneralName[] all = new GeneralName[alternativeNamesSAN.length];
	        	
	            for (int i = 0; i < alternativeNamesSAN.length; i++)
	                all[i] = new GeneralName(GeneralName.dNSName, alternativeNamesSAN[i]);	//rfc822Name
	            
	            GeneralNames alternativeNames = new GeneralNames(all);
	            
	            certificateBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, criticalSAN, alternativeNames);
	        }
	        
	        // EKU
	        int length = 0;
	        for (int i = 0; i < checkboxsEKU.length; i++)
	        	if (checkboxsEKU[i])
	        		length++;
	        
	        if (length > 0) {
	        	
		        KeyPurposeId[] KPI = new KeyPurposeId[length];
		        
		        int i = 0;
		        if (checkboxsEKU[0]) 
		        	KPI[i++] = KeyPurposeId.anyExtendedKeyUsage;
		        if (checkboxsEKU[1]) 
		        	KPI[i++] = KeyPurposeId.id_kp_serverAuth;
		        if (checkboxsEKU[2]) 
		        	KPI[i++] = KeyPurposeId.id_kp_clientAuth;
		        if (checkboxsEKU[3]) 
		        	KPI[i++] = KeyPurposeId.id_kp_codeSigning;
		        if (checkboxsEKU[4]) 
		        	KPI[i++] = KeyPurposeId.id_kp_emailProtection;
		        if (checkboxsEKU[5]) 
		        	KPI[i++] = KeyPurposeId.id_kp_timeStamping;
		        if (checkboxsEKU[6]) 
		        	KPI[i++] = KeyPurposeId.id_kp_OCSPSigning;
		        
		        certificateBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, criticalEKU, new ExtendedKeyUsage(KPI));
	        }
	        // END EKSTENZIJE
	
	        ContentSigner signer = new JcaContentSignerBuilder(algorithm).build(CAPrivateKey);
	
	        X509Certificate signedCertificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer));
	        
	        Certificate[] oldChain = keyStore.getCertificateChain(keypair_name);
	        Collection<JcaX509CertificateHolder> newChain = new ArrayList<>(oldChain.length + 1);
	        newChain.add(new JcaX509CertificateHolder(signedCertificate));
	        for (int i = 0; i < oldChain.length; i++)
	            newChain.add(new JcaX509CertificateHolder((X509Certificate) oldChain[i]));
	        
	        CollectionStore<JcaX509CertificateHolder> store = new CollectionStore<>(newChain);
	        
	        CMSSignedDataGenerator CMSGenerator = new CMSSignedDataGenerator();
	        CMSGenerator.addCertificates(store);
	        
	        CMSProcessableByteArray msg = new CMSProcessableByteArray("Signed Certificate!".getBytes());
	        CMSSignedData CMSData = CMSGenerator.generate(msg, true);
	        
	        // WRITE
			FileWriter FW = new FileWriter(file);
			PemWriter pw = new PemWriter(FW);
			
			pw.writeObject(new PemObject("PKCS7", CMSData.getEncoded()));
			
			pw.flush();
			pw.close();
			// END WRITE
	
	        return true;
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException | InvalidKeyException | OperatorCreationException | CertificateException | CMSException | IOException e) {
			e.printStackTrace();
			return false;
		}
	}
	
    public void save() {
    	
        try {
        	FileOutputStream FOS = new FileOutputStream(keyStoreName);
            keyStore.store(FOS, keyStorePassword);
            FOS.close();
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            e.printStackTrace();
        }
    }
    
}