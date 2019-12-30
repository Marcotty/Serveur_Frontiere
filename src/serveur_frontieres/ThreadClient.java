/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package serveur_frontieres;

import CONTROLID.ReponseCONTROLID;
import static CONTROLID.ReponseCONTROLID.ACK;
import static CONTROLID.ReponseCONTROLID.FAIL;
import CONTROLID.RequeteCONTROLID;
import static CONTROLID.RequeteCONTROLID.CHECK;
import static CONTROLID.RequeteCONTROLID.IDENTITE;
import static CONTROLID.RequeteCONTROLID.IDENTITE_INFOS;
import static CONTROLID.RequeteCONTROLID.LOGIN;
import static CONTROLID.RequeteCONTROLID.PERMIS;
import com.sun.xml.internal.messaging.saaj.util.Base64;
import database.MyInstruction;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;
import requetereponse.Requete;

/**
 *
 * @author fredm
 */
public class ThreadClient extends Thread{
    private Properties PropsServer;
    private Socket cSocket;
    private listSocket sList;
    private MyInstruction sgbd;
    public ThreadClient(Socket s, Properties props, listSocket list, MyInstruction sg)
    {
        System.out.println("Thread n° " + this.getId() + " created.");
        PropsServer = props;
        cSocket = s;
        sList = (listSocket) list;
        sgbd = sg;
    }
    public void run()
    {
        while(!isInterrupted())
        {
            Accept();
            
            while(!isInterrupted())
            {
                TraiteRequete();
            }
        }
    }

    private void TraiteRequete() {
        Requete req = null;
        
        req = RecvReq(cSocket);
        if(req != null)
        {
            System.out.println(req.CodeToString() + " received");
            switch(req.getCode())
            {
                case LOGIN :
                {
                    RequeteCONTROLID requete = (RequeteCONTROLID) req;
                    System.out.println("Login : " + requete.getChargeUtile());
                    if(LoginValide(requete.getChargeUtile()))
                        EnvoyerReponseCONTROLID(cSocket, ACK, "Login accepted !");
                    else
                        EnvoyerReponseCONTROLID(cSocket, FAIL, "Login denied !");
                    break;
                }
                case CHECK :
                {
                    ReponseCONTROLID rep = null;
                    RequeteCONTROLID requete = (RequeteCONTROLID) req;
                    System.out.println("Plaque : " + requete.getChargeUtile());
                    
                    if(PlaqueValide(requete.getChargeUtile()))
                        rep = EnvoyerReponseCONTROLID(cSocket, ACK, "Plaque accepted !");
                    else
                        rep = EnvoyerReponseCONTROLID(cSocket, FAIL, "Plaque denied !");
                        
                    if(rep != null)
                        EnvoyerSignatureReponse(cSocket, rep);
                    break;
                }
                case PERMIS :
                {
                    ReponseCONTROLID rep = null;
                    RequeteCONTROLID requete = (RequeteCONTROLID) req;
                    System.out.println("Permis de : " + requete.getChargeUtile());
                    
                    if(PermisValide((RequeteCONTROLID) req))
                        rep = EnvoyerReponseCONTROLID(cSocket, ACK, "Permis valid !");
                    else
                        rep = EnvoyerReponseCONTROLID(cSocket, FAIL, "Permis invalid !");
                    break;
                }
                case IDENTITE :
                {
                    ReponseCONTROLID rep = null;
                    RequeteCONTROLID requete = (RequeteCONTROLID) req;
                    System.out.println("Identite de : " + requete.getChargeUtile());
                    
                    if(IdentiteValide((RequeteCONTROLID) req))
                        rep = EnvoyerReponseCONTROLID(cSocket, ACK, "Carte d'identite valid !");
                    else
                        rep = EnvoyerReponseCONTROLID(cSocket, FAIL, "Carte d'identite invalid !");
                    
                    break;
                }
            }   
        }
        else
        {
            System.out.println("Thread n° " + this.getId() + " client is gone.");            
            Accept();
        }
    }
    private boolean PermisValide(RequeteCONTROLID req)
    {
        try {
            //Recuperer la longueur
            DataInputStream dis = new DataInputStream(new BufferedInputStream(cSocket.getInputStream()));
            int longueur = dis.readInt();
            //Recuperer le hmac
            byte[] hmac_remote = new byte[longueur];
            dis.readFully(hmac_remote);
            //recupérer la clé secrete K1 chifrée
            int longr = dis.readInt();
            byte[] cleCryptee = new byte[longr];
            dis.readFully(cleCryptee);
            System.out.println("Cle cryptee recuperee :" );
            System.out.println(Arrays.toString(cleCryptee));
            //Obtenir une clé privee depuis le keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream ("server_keystore.p12"), "azerty".toCharArray());
            PrivateKey privateKey = (PrivateKey) keyStore.getKey("serverKP", "azerty".toCharArray());
            
            Cipher chiffrement=Cipher.getInstance("RSA", "BC");
            chiffrement.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] cleSecrete_byte = chiffrement.doFinal(cleCryptee);
            System.out.println("Cle secrete dechifree :");
            System.out.println(Arrays.toString(cleSecrete_byte));
            
            SecretKey K1 = new SecretKeySpec(cleSecrete_byte, "DES");
            
            System.out.println("Cle secrete K1 recuperree");
            System.out.println(Arrays.toString(K1.getEncoded()));
            //Verifier 
            Mac hlocal = Mac.getInstance("HMAC-MD5", "BC");
            hlocal.init(K1);
            String temp = Integer.toString(req.getCode()) + req.getChargeUtile();
            byte[] message = temp.getBytes();
            hlocal.update(message);
            byte[] hlocalb = hlocal.doFinal();
            System.out.println("HMAC locac construit a partir de " +Integer.toString(req.getCode()) + req.getChargeUtile() + " hmac : "+ new String(hlocalb.toString()));
            
            System.out.println("HMAC remote " + hmac_remote.toString());
            if(MessageDigest.isEqual(hmac_remote, hlocalb))
            {
                System.out.println("HMAC verifié : OK");
                
                String permis ="";
                //DB permis
                sgbd.SelectionCond("personne", "plaque LIKE '" + req.getChargeUtile() + "'"); 
                //System.out.println("Check plaque " + req.getChargeUtile());
                if (sgbd.getResultat().next()) 
                {
                    if (sgbd.getResultat().getString("permis") != null)
                    {
                        permis = sgbd.getResultat().getString("permis"); 
                        //System.out.println("Check permis" + permis);
                        sgbd.SelectionCond("permis", "idPermis LIKE '" + permis + "'"); 
                        if (sgbd.getResultat().next()) 
                        {
                            if (sgbd.getResultat().getString("status") != null)
                            {
                                //System.out.println("Check validite");
                                if(sgbd.getResultat().getString("status").equals("valid"))
                                {
                                    System.out.println("Permis valid");
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            
        } catch (SQLException | IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | NoSuchPaddingException | KeyStoreException | CertificateException | UnrecoverableKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(ThreadClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.out.println("HMAC verifié : ERREUR");
        return false;
    }
    private boolean IdentiteValide(RequeteCONTROLID req)
    {
        String texteCrypte = "";
        RequeteCONTROLID reqCryptee = null;
        byte[] texteCrypteByte = null;
        try {
            //recuperer la requete chifrée grace a K2
            /*Requete reqChifree = null;
        
            reqChifree = RecvReqChifree(cSocket);
            if(reqChifree != null)
            {
               reqCryptee = (RequeteCONTROLID) reqChifree;
               if(reqCryptee.getCode() == IDENTITE_INFOS)
               {
                   texteCrypte = reqCryptee.getChargeUtile();
                   System.out.println("texte crypte recupere : " + texteCrypte.getBytes());
                   texteCrypteByte = new byte[texteCrypte.getBytes().length];
                   texteCrypteByte = texteCrypte.getBytes();
               }
            }*/
            
            DataInputStream dis = new DataInputStream(new BufferedInputStream(cSocket.getInputStream()));
            int lon = dis.readInt();
            byte[] textecrypte = new byte[lon];
            dis.readFully(textecrypte);
            //Recuperer la cle K2
            int longre = dis.readInt();
            byte[] cleCrypteeK2 = new byte[longre];
            dis.readFully(cleCrypteeK2);
            System.out.println("Cle cryptee recuperee :" );
            System.out.println(Arrays.toString(cleCrypteeK2));
            //Recuperer la longueur
            int longueur = dis.readInt();
            //Recuperer le hmac
            byte[] hmac_remote = new byte[longueur];
            dis.readFully(hmac_remote);
            //recupérer la clé secrete K1 chifrée
            int longr = dis.readInt();
            byte[] cleCryptee = new byte[longr];
            dis.readFully(cleCryptee);
            System.out.println("Cle cryptee recuperee :" );
            System.out.println(Arrays.toString(cleCryptee));
            //Obtenir une clé privee depuis le keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream ("server_keystore.p12"), "azerty".toCharArray());
            PrivateKey privateKey = (PrivateKey) keyStore.getKey("serverKP", "azerty".toCharArray());
            //Dechiffrer K2
            Cipher chif2 = Cipher.getInstance("RSA", "BC");
            chif2.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] cleK2_byte = chif2.doFinal(cleCrypteeK2);
            //Dechiffer K1
            Cipher chiffrement=Cipher.getInstance("RSA", "BC");
            chiffrement.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] cleSecrete_byte = chiffrement.doFinal(cleCryptee);
            
            SecretKey K1 = new SecretKeySpec(cleSecrete_byte, "DES");
            SecretKey K2 = new SecretKeySpec(cleK2_byte, "DES");
            System.out.println("Cle secrete K1 recuperee");
            System.out.println(Arrays.toString(K1.getEncoded()));
            System.out.println("Cle secrete K2 recuperee" + "longK2" + K2.getEncoded().length);
            System.out.println(Arrays.toString(K2.getEncoded()));
            //Verifier 
            Mac hlocal = Mac.getInstance("HMAC-MD5", "BC");
            hlocal.init(K1);
            String temp = Integer.toString(req.getCode()) + textecrypte.toString();
            byte[] message = temp.getBytes();
            hlocal.update(message);
            byte[] hlocalb = hlocal.doFinal();
            System.out.println("HMAC locac construit a partir de " +Integer.toString(req.getCode()) + textecrypte.toString() + " hmac : "+ new String(hlocalb.toString()));
            System.out.println("temp : " + temp);
            System.out.println("HMAC remote " + hmac_remote.toString());
            if(MessageDigest.isEqual(hmac_remote, hlocalb))
            {
                System.out.println("HMAC verifié : OK");
                
                //decrypter requete identite:
                Cipher Dchif = Cipher.getInstance("DES/ECB/PKCS5Padding", "BC");
                Dchif.init(Cipher.DECRYPT_MODE, K2);
                System.out.println("longueur texte : " + texteCrypte.length());
                
                byte[] reqClair = Dchif.doFinal(texteCrypteByte);
                System.out.println("Infos identite de : " + Arrays.toString(reqClair));
            }
            
        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | NoSuchPaddingException | KeyStoreException | CertificateException | UnrecoverableKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(ThreadClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.out.println("HMAC verifié : ERREUR");
        return false;
    }  
    private void EnvoyerSignatureReponse(Socket cSocket, ReponseCONTROLID rep)
    {
        try {
            //Obtenir une clé privee depuis le keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream ("server_keystore.p12"), "azerty".toCharArray());
            PrivateKey privateKey = (PrivateKey) keyStore.getKey("serverKP", "azerty".toCharArray());
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            System.out.println("req : " + rep.getChargeUtile());
            signature.update(rep.getChargeUtile().getBytes());
            byte[] digitalSignature = signature.sign();
            DataOutputStream dos = new DataOutputStream(cSocket.getOutputStream());
            dos.writeInt(digitalSignature.length);
            dos.write(digitalSignature);
            System.out.println("Signature envoyée : " + digitalSignature.toString());
            
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | IOException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(ThreadClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    private boolean PlaqueValide(String chargeUtile) {
        //Obtenir une clé publique depuis un certificat //auto signé
        boolean isCorrect = false;
        try {
            //recuperer la cle publique
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream ("cert_keystore.p12"), "azerty".toCharArray());
            Certificate certificate = keyStore.getCertificate("clientKP");
            PublicKey publicKey = certificate.getPublicKey();
            
            //System.out.println("Cle publique recuperee : " + publicKey.toString());
            //System.out.println("Depuis le certificat : " + certificate.toString());
            //recevoir la signature
            DataInputStream dis = new DataInputStream(new BufferedInputStream(cSocket.getInputStream()));
            int longueur = dis.readInt();
            byte[] signature_rem = new byte[longueur];
            dis.readFully(signature_rem);
            //Verifier la signature
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(chargeUtile.getBytes());
            isCorrect = signature.verify(signature_rem);
            
            if(isCorrect)
                System.out.println("Signature verifiee : OK");
            else
                System.out.println("Signature verifiee : ERREUR");
            
            
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | InvalidKeyException | SignatureException | IOException ex) {
            Logger.getLogger(ThreadClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        if(isCorrect)
        {
            System.out.println("Verification de la plaque : " + chargeUtile);
            String plaque = chargeUtile;
            try {
                sgbd.SelectionCond("vehicule", "plaque LIKE '" + plaque + "'"); //tous les résultats.
                if (sgbd.getResultat().next()) {
                    if (sgbd.getResultat().getString("plaque") != null) {
                        
                        System.out.println(sgbd.getResultat().getString("plaque"));
                        if(sgbd.getResultat().getString("statut").equals("authorized"))
                        System.out.println("Plaque acceptee");
                        return true;
                    }
                }
            }catch (SQLException e) {
            JOptionPane.showMessageDialog(null, "RegNat : erreur obtention infos carte", "Erreur", JOptionPane.ERROR_MESSAGE);
            System.out.println(e);
            }  
        }
        System.out.println("Plaque refusee");
        return false;
    }
    private boolean LoginValide(String chargeUtile) {
        
        String user = chargeUtile;
        String password ="";
        
        try
        {
            sgbd.SelectionCond("admin", "username LIKE '" + user + "'"); 
            if (sgbd.getResultat().next()) {
                if (sgbd.getResultat().getString("username") != null)
                    password = sgbd.getResultat().getString("password");
            }
            DataInputStream dis = new DataInputStream(new BufferedInputStream(cSocket.getInputStream()));
            double alea = dis.readDouble();
            //System.out.println("Alea : " + alea);
            int longueur = dis.readInt();
            //System.out.println("long : " + longueur);
            byte[] msgDigest = new byte[longueur];
            dis.readFully(msgDigest);
            
            MessageDigest md = MessageDigest.getInstance("SHA-1", "BC");
            md.update(password.getBytes());
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream bdos = new DataOutputStream(baos);
            bdos.writeDouble(alea);
            md.update(baos.toByteArray());
            byte[] msgDigestLocal = md.digest();
            
            if(MessageDigest.isEqual(msgDigest, msgDigestLocal))
                return true;
                    
        }
        catch(IOException | NoSuchAlgorithmException | NoSuchProviderException | SQLException e)
        {
            System.out.println("Erreur envoi digest : " + e.getClass() + e.getMessage());
        }
        
        return false;
    }
    private Requete RecvReqChifree(Socket cSocket) {
        Requete req = null;
        
        try
        {
            ObjectInputStream ois = new ObjectInputStream(cSocket.getInputStream());
            req = (Requete)ois.readObject();
        }
        catch (ClassNotFoundException e)
        { System.out.println("--- erreur sur la classe = " + e.getMessage()); }
        catch (IOException e)
        { System.out.println("--- erreur IO = " + e.getMessage()); }
        return req;
    }
    private Requete RecvReq(Socket cSocket) {
        Requete req = null;
        
        try
        {
            ObjectInputStream ois = new ObjectInputStream(cSocket.getInputStream());
            req = (Requete)ois.readObject();
        }
        catch (ClassNotFoundException e)
        { System.out.println("--- erreur sur la classe = " + e.getMessage()); }
        catch (IOException e)
        { System.out.println("--- erreur IO = " + e.getMessage()); }
        return req;
    }
    public ReponseCONTROLID EnvoyerReponseCONTROLID(Socket cliSocket, int code, String chargeUtile)
    {
        ObjectOutputStream oos;
        ReponseCONTROLID rep = null;
        rep = new ReponseCONTROLID(code, chargeUtile);
        try
        {
            oos = new ObjectOutputStream(cliSocket.getOutputStream());
            oos.writeObject(rep);
        }
        catch (IOException e)
        { System.err.println("Erreur réseau ? [" + e.getMessage() + "]"); }
        return rep;
    }
    /*public void EnvoyerReponseCONTROLID(Socket cliSocket, int code, String chargeUtile)
    {
        ObjectOutputStream oos;
        ReponseCONTROLID req = null;
        req = new ReponseCONTROLID(code, chargeUtile);
        try
        {
            oos = new ObjectOutputStream(cliSocket.getOutputStream());
            oos.writeObject(req);
        }
        catch (IOException e)
        { System.err.println("Erreur réseau ? [" + e.getMessage() + "]"); }
    }*/

    private void Accept() {
        try 
        {
            System.out.println("Thread n° " + this.getId() + " wait Socket.");
            cSocket = sList.getSocket();
            System.out.println("Thread n° " + this.getId() + " adresse client : " + cSocket.getInetAddress());
        } 
        catch (InterruptedException ex) 
        {
            System.out.println("Thread n° " + this.getId() + " ERROR GET SOCKET.");
        }
    }

    
}
