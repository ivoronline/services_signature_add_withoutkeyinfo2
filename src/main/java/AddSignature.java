import org.w3c.dom.Document;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import java.security.KeyStore;
import java.security.PrivateKey;

public class AddSignature {

  //KEY STORE
  static String keyStoreName     = "/ClientKeyStore.jks";
  static String keyStorePassword = "mypassword";
  static String keyStoreType     = "JKS";
  static String keyAlias         = "clientkeys1";

  //XML FILES
  static String fileXMLInput     = "/Person.xml";
  static String fileXMLSigned    = "PersonSigned.xml";

  //================================================================================
  // MAIN
  //================================================================================
  public static void main(String[] args) throws Exception {

    //GET PRIVATE KEY
    KeyStore.PrivateKeyEntry keyPair    = UtilKeys.getKeyPair(keyStoreName, keyStorePassword, keyStoreType, keyAlias);
    PrivateKey               privateKey = keyPair.getPrivateKey();

    //SIGN DOCUMENT
    Document document = UtilXML.fileToDocument(fileXMLInput);
    UtilSignature.signDocument (document, privateKey, "Person", "#data", DigestMethod.SHA1, SignatureMethod.RSA_SHA1);
    UtilXML.documentToFile(fileXMLSigned, document);
  }

}
