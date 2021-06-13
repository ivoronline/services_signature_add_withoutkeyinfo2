import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Collections;

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
    KeyStore.PrivateKeyEntry keyPair = getKeyPair(keyStoreName, keyStorePassword, keyStoreType, keyAlias);
    PrivateKey               privateKey  = keyPair.getPrivateKey();

    //SIGN DOCUMENT
    Document      document = readXMLFromFile(fileXMLInput);
    signDocument (document, privateKey, "Person", "data", DigestMethod.SHA1, SignatureMethod.RSA_SHA1);
    saveXMLToFile(document, fileXMLSigned);
  }

  //================================================================================
  // READ XML FROM FILE
  //================================================================================
  // Document document = readXMLFromFile(fileXMLInput);
  private static Document readXMLFromFile(String fileName) throws Exception {
    DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
    documentFactory.setNamespaceAware(true);
    Document document = documentFactory.newDocumentBuilder().parse(new FileInputStream(fileName));
    return document;
  }

  //================================================================================
  // SAVE XML TO FILE
  //================================================================================
  private static void saveXMLToFile(Document document, String fileName) throws Exception {
    OutputStream       outputStream       = new FileOutputStream(fileName);
    TransformerFactory transformerFactory = TransformerFactory.newInstance();
    Transformer        transformer        = transformerFactory.newTransformer();
    transformer.transform(new DOMSource(document), new StreamResult(outputStream));
  }

  //================================================================================
  // SIGN DOCUMENT
  //================================================================================
  // <Person Id="data">
  public static void signDocument(
    Document   document,        //RETURN VALUE
    PrivateKey privateKey,
    String     elementName,     //"Person"      FIX
    String     referenceURI,    //"data"
    String     digestMethod,    //DigestMethod.SHA1
    String     signatureMethod  //SignatureMethod.RSA_SHA1
  ) throws Exception {

    //CREATE REFERENCE
    XMLSignatureFactory factory   = XMLSignatureFactory.getInstance("DOM");
    Reference           reference = factory.newReference(
      "#" + referenceURI,
      factory.newDigestMethod(digestMethod, null),
      Collections.singletonList(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
      null,
      null
    );

    //SPECIFY SIGNATURE TYPE
    SignedInfo signedInfo = factory.newSignedInfo(
      factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,(C14NMethodParameterSpec) null),
      factory.newSignatureMethod       (signatureMethod, null),Collections.singletonList(reference)
    );

    //SIGN DOCUMENT
    Element        element        = (Element) document.getElementsByTagName(elementName).item(0);  //FIX
    DOMSignContext domSignContext = new DOMSignContext(privateKey, document.getDocumentElement());
                   domSignContext.setIdAttributeNS(element, null, "Id");                           //FIX
    XMLSignature   signature      = factory.newXMLSignature(signedInfo, null);
                   signature.sign(domSignContext);

  }

  //================================================================================
  // GET KEY PAIR
  //================================================================================
  private static KeyStore.PrivateKeyEntry getKeyPair(
    String keyStoreName,        //"src/main/resources/ClientKeyStore.jks"
    String keyStorePassword,    //"mypassword";
    String keyStoreType,        //"JKS"
    String keyAlias             //"clientkeys1"
  ) throws Exception {

    //GET PRIVATE KEY
    char[]                      password    = keyStorePassword.toCharArray();    //For KeyStore & Private Key
    KeyStore                    keyStore    = KeyStore.getInstance(keyStoreType);
                                keyStore.load(new FileInputStream(keyStoreName), password);
    KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(   password);
    KeyStore.PrivateKeyEntry    keyPair = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias,keyPassword);

    //RETURN KEY PAIR
    return keyPair;

  }

}
