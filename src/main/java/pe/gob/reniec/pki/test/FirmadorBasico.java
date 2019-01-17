/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pe.gob.reniec.pki.test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.MSCAPISignatureToken;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import java.awt.Color;
import java.awt.Font;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;

/**
 *
 * @author Administrador
 */
public class FirmadorBasico {

    private static String KEYSTORE_PATH = "D:\\Proyectos2019\\dfirma\\aga.p12";
    private static String DOC_PATH = "D:\\Proyectos2019\\dfirma\\document.pdf";
    private static String TARGET_PATH = "D:\\Proyectos2019\\dfirma\\document-f.pdf";
    
    public static void main(String[] args) throws IOException {

        MSCAPISignatureToken signingToken = new MSCAPISignatureToken();
        DSSPrivateKeyEntry privateKey = null;
        for (DSSPrivateKeyEntry key : signingToken.getKeys()) {
            if(key != null){
                System.out.println(key.getCertificate().getCertificate().getSubjectDN().getName());
                if(key.getCertificate().getCertificate().getSubjectDN().getName().contains("ALEJO HUARACHI Alain Melquiades FIR 42447799 hard")){
                    privateKey = key;
                    break;
                }
            }
        }
        
        //AbstractSignatureTokenConnection signingToken = new Pkcs12SignatureToken(KEYSTORE_PATH, new PasswordProtection("password".toCharArray()));
        //DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);
        
        DSSDocument toSignDocument = new FileDocument(DOC_PATH);
        
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        
        // We set the signing certificate
        parameters.setSigningCertificate(privateKey.getCertificate());
        // We set the certificate chain
        parameters.setCertificateChain(privateKey.getCertificateChain());
        
        //parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        // Initialize visual signature
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        // the origin is the left and top corner of the page
        imageParameters.setxAxis(200);
        imageParameters.setyAxis(500);

        // Initialize text to generate for visual signature
        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        textParameters.setFont(new Font("serif", Font.PLAIN, 14));
        textParameters.setTextColor(Color.BLUE);
        textParameters.setText("My visual signature");
        imageParameters.setTextParameters(textParameters);

        parameters.setSignatureImageParameters(imageParameters);

        // Create common certificate verifier
        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        // Create PAdESService for signature
        PAdESService service = new PAdESService(commonCertificateVerifier);

        // Get the SignedInfo segment that need to be signed.
        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

        // This function obtains the signature value for signed information using the
        // private key and specified algorithm
        DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
        SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

        // We invoke the xadesService to sign the document with the signature value obtained in
        // the previous step.
        DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);   
        signedDocument.save(TARGET_PATH);
    }
}
