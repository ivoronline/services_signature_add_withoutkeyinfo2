import org.w3c.dom.Document;
import xmlutil.XMLUtil;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import java.security.KeyStore;
import java.security.PrivateKey;

public class AddSignature {

  //KEY STORE
  static String keyStoreName     = "src/main/resources/ClientKeyStore.jks";
  static String keyStorePassword = "mypassword";
  static String keyStoreType     = "JKS";
  static String keyAlias         = "clientkeys1";

  //XML FILES
  static String fileXMLInput     = "src/main/resources/Person.xml";
  static String fileXMLSigned    = "src/main/resources/PersonSigned.xml";

  //================================================================================
  // MAIN
  //================================================================================
  public static void main(String[] args) throws Exception {

    //GET PRIVATE KEY
    KeyStore.PrivateKeyEntry keyPair    = XMLUtil.getPrivateKeyPair(keyStoreName, keyStorePassword, keyStoreType, keyAlias);
    PrivateKey               privateKey = keyPair.getPrivateKey();

    //SIGN DOCUMENT
    Document      document = XMLUtil.readXMLFromFile(fileXMLInput);
    XMLUtil.signDocument (document, privateKey, "Person", "data", DigestMethod.SHA1, SignatureMethod.RSA_SHA1);
    XMLUtil.saveXMLToFile(document, fileXMLSigned);
  }

}
