package xmlutil;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Reference;
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
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.util.Collections;

public class XMLUtil {

  //================================================================================
  // READ XML FROM FILE
  //================================================================================
  // Document document = readXMLFromFile(fileXMLInput);
  public static Document readXMLFromFile(String fileName) throws Exception {

    //READ DOCUMENT FROM FILE
    DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
                           documentFactory.setNamespaceAware(true);
    InputStream            inputStream     = XMLUtil.class.getResourceAsStream(fileName);
    Document               document        = documentFactory.newDocumentBuilder().parse(inputStream);

    //RETURN DOCUMENT
    return document;

  }

  //================================================================================
  // SAVE XML TO FILE
  //================================================================================
  public static void saveXMLToFile(Document document, String fileName) throws Exception {
    OutputStream       outputStream       = new FileOutputStream(fileName);
    TransformerFactory transformerFactory = TransformerFactory.newInstance();
    Transformer        transformer        = transformerFactory.newTransformer();
                       transformer.transform(new DOMSource(document), new StreamResult(outputStream));
  }

  //================================================================================
  // GET PRIVATE KEY PAIR
  //================================================================================
  public static KeyStore.PrivateKeyEntry getPrivateKeyPair(
    String keyStoreName,        //"/ClientKeyStore.jks"
    String keyStorePassword,    //"mypassword";
    String keyStoreType,        //"JKS"
    String keyAlias             //"clientkeys1"
  ) throws Exception {

    //GET PRIVATE KEY
    InputStream                 inputStream = XMLUtil.class.getResourceAsStream(keyStoreName);
    char[]                      password    = keyStorePassword.toCharArray();    //For KeyStore & Private Key
    KeyStore                    keyStore    = KeyStore.getInstance(keyStoreType);
                                keyStore.load(inputStream, password);
    KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(password);
    KeyStore.PrivateKeyEntry    keyPair =(KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias, keyPassword);

    //RETURN KEY PAIR
    return keyPair;

  }

  //================================================================================
  // SIGN DOCUMENT
  //================================================================================
  // XMLUtil.signDocument (document, key, "Person", "data", DigestMethod.SHA1, SignatureMethod.RSA_SHA1);
  // <Person Id="data">
  public static void signDocument (
    Document   document,        //RETURN VALUE
    Key        key,             //Key used to sign XML Element
    String     elementToSign,   //"Person"     Element to Sign
    String     referenceURI,    //"#data"
    String     digestMethod,    //DigestMethod.SHA1
    String     signatureMethod  //SignatureMethod.RSA_SHA1
  ) throws Exception {

    //CREATE REFERENCE
    XMLSignatureFactory factory   = XMLSignatureFactory.getInstance("DOM");
    Reference           reference = factory.newReference(
      referenceURI,
      factory.newDigestMethod(digestMethod, null),
      Collections.singletonList(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
      null,
      null
    );

    //SPECIFY SIGNATURE TYPE
    SignedInfo signedInfo = factory.newSignedInfo(
      factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,(C14NMethodParameterSpec) null),
      factory.newSignatureMethod(signatureMethod, null),Collections.singletonList(reference)
    );

    //PREPARE SIGN CONTEXT
    DOMSignContext domSignContext = new DOMSignContext(key, document.getElementsByTagName(elementToSign).item(0));

    //FIX IF referenceURI POINTS TO Id ATTRIBUTE
    if (!referenceURI.equals("") ) {
      Element element = (Element) document.getElementsByTagName(elementToSign).item(0);
      domSignContext.setIdAttributeNS(element, null, "Id");
    }

    //SIGN DOCUMENT
    XMLSignature signature = factory.newXMLSignature(signedInfo, null);
                 signature.sign(domSignContext);

  }

}
