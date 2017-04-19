/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package RequestResponseKERBEROS;

import GestionSocket.GestionSocket;
import GestionSocket.ISocket;
import JavaLibrary.Crypto.Chiffrement;
import JavaLibrary.Crypto.Cle;
import JavaLibrary.Crypto.CryptoManager;
import static JavaLibrary.Crypto.DiffieHellman.DiffieHellman.ALGORITHM;
import JavaLibrary.Crypto.NoSuchChiffrementException;
import JavaLibrary.Crypto.NoSuchCleException;
import JavaLibrary.Crypto.SecurePassword.SecurePasswordSha256;
import JavaLibrary.Network.CipherGestionSocket;
import JavaLibrary.Network.NetworkPacket;
import JavaLibrary.Utils.ByteUtils;
import Kerberos.AuthenticatorCS;
import Kerberos.KS_CST;
import Kerberos.KTGS_CST;
import Kerberos.TicketTCS;
import Kerberos.TicketTGS;
import RequestResponse.ConsoleServeur;
import RequestResponse.IRequest;

import static RequestResponseKERBEROS.IKERBEROS.LOGOUT;
import Serializator.KeySerializator;

import UtilsKERBEROS.FichierConfig;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Bob
 */
public class RequestKERBEROS implements IRequest, IKERBEROS, Serializable
{

    private int type; // LOGIN,...
    private Object chargeUtile;
    private int codeRetour;
    private GestionSocket GSocketCo;
    private static final String DIRECTORY = System.getProperty("user.home") + System.getProperty("file.separator")
            + "kerberos_server" + System.getProperty("file.separator"),
            CONFIG_FILE = DIRECTORY + "config.properties", USERS_FILE = DIRECTORY + "users.properties", EXT = ".serverkey",
            SERVER_EXT = ".key",
            KEY_FILE = DIRECTORY + "ktgs" + EXT,
            SERVERKEY_FILE = DIRECTORY + "default_serverkey" + SERVER_EXT;

    private Properties config;
    public int port, version;
    public long validite;
    public String algorithm, name , encoding;

    private SecurePasswordSha256 sp;
    public Cle ktgs, kctgs, kcs, ks;
    public Chiffrement ch_ktgs, ch_ks, ch_kctgs,ch_kcs;
    // SI je veux extraire certaines variables membres du processus serializable, on peut utiliser le qualificaeur "transient"

    public int getCodeRetour()
    {
        return codeRetour;
    }

    public void setCodeRetour(int codeRetour)
    {
        this.codeRetour = codeRetour;
    }

    public RequestKERBEROS(int type, Object chargeUtile)
    {
        this.type = type;
        this.chargeUtile = chargeUtile; // set du vector
    }

    @Override
    public Object getChargeUtile()
    {
        return chargeUtile;
    }

    @Override
    public void setChargeUtile(Object chargeUtile)
    {
        this.chargeUtile = chargeUtile;
    }

    @Override
    public int getType()
    {
        return type;
    }

    @Override
    public void setType(int type)
    {
        this.type = type;
    }

    @Override
    public boolean executeRequest(ISocket Socket, ConsoleServeur guiApplication)
    {

        if (getType() == ACCESS_REQUEST_KERBEROS)
        {
            guiApplication.TraceEvenements("Réception de LOGIN_REQUEST");
            try
            {
                traiteRequeteLoginKERBEROS(Socket, guiApplication);
            }
            catch (Exception ex)
            {
                Logger.getLogger(RequestKERBEROS.class.getName()).log(Level.SEVERE, null, ex);
            }
            return false;
        }

        else if (getType() == LOGOUT)
        {
            guiApplication.TraceEvenements("Réception d'une requête de fermeture de connexion");
            traiteRequeteLogout(Socket, guiApplication);
            return true;
        }

        return false;
    }

    public void traiteRequeteLoginKERBEROS(ISocket Socket, ConsoleServeur guiApplication) throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        ResponseKERBEROS rep = new ResponseKERBEROS();
        // lire la clé local KTGS
        loadConfig();
        loadKeys();
        
        //Récupération des informations
        Vector vInfos = (Vector) getChargeUtile();
        //récupération du ticket (via le networkPacket)
        NetworkPacket np = (NetworkPacket) vInfos.get(0);
        //Déchiffrer le ticket chiffré avec KTGS pour extraire kcs, la clé de session client-ser

        CipherGestionSocket cgs = new CipherGestionSocket(null,ch_ks);
        TicketTCS ticketTCS = (TicketTCS) ByteUtils.toObject(cgs.decrypte(np.get(KS_CST.TICKET_SERVER)));
        
        // On a déchiffrer le ticket donc maintenant on peut vérifier sa validité.
        
        LocalDate now = LocalDate.now();

        if (ticketTCS.tv.compareTo(now.plusDays(validite)) > 0 || ticketTCS.tv.compareTo(now.minusDays(validite)) < 0)
        {
            throw new InvalidParameterException(KS_CST.DATETIME_FAILED);
        }

        //se tuttapposto -> on déchiffre l'acs + vérification
        kcs = ticketTCS.cleSession;
        ch_kcs = (Chiffrement) CryptoManager.newInstance(algorithm);
        ch_kcs.init(kcs);
        
        
        //récupérer l'authenticatorCS pour l'analyser
        np = (NetworkPacket) vInfos.get(1);
        cgs = new CipherGestionSocket(null, ch_kcs);
        AuthenticatorCS acs = (AuthenticatorCS) ByteUtils.toObject(cgs.decrypte((np.get(((KS_CST.ACS))))));

        //regarder si validité dépassée | si validité trop loin dans le passé
        if (acs.tv.compareTo(now.plusDays(validite)) > 0 || acs.tv.compareTo(now.minusDays(validite)) < 0)
        {
            rep.setCodeRetour(ACS_FAILED);
            throw new InvalidParameterException(KS_CST.DATETIME_FAILED);
        }
        else
        {
           
            rep.setCodeRetour(YES);
            System.out.println("Accès autorisé...");
        }
        
        
        Socket.Send(rep);
    }

    private void loadKeys() throws IOException, ClassNotFoundException,NoSuchChiffrementException, NoSuchCleException, NoSuchAlgorithmException,NoSuchProviderException
    {

        System.out.println("CONFIG FILE = " + getCONFIG_FILE());
        System.out.println("algo = " + algorithm);
        //récupère et crée si nécessaire la clé du serveur (pour la copier coller après :p)
        ks = KeySerializator.getKey(SERVERKEY_FILE, algorithm);


        ch_ks = (Chiffrement) CryptoManager.newInstance(algorithm);
        ch_ks.init(ks);
    }

    private void traiteRequeteLogout(ISocket Socket, ConsoleServeur guiApplicaiton)
    {
        Socket.Close();
    }
    private void loadConfig() throws IOException, NoSuchFieldException 
    {
        //Check if properties exists
        config=new Properties();

       
        
        getConfig().load(new FileInputStream(getCONFIG_FILE()));
       
        
        String s_port=getConfig().getProperty("port");
        System.out.println("getconfigFile = " + getCONFIG_FILE());
        String s_validite=getConfig().getProperty("validite");
        String s_version=getConfig().getProperty("version");
        algorithm=getConfig().getProperty("algorithm");
        encoding=getConfig().getProperty("encoding");
        
        if(getAlgorithm()==null || s_port==null || s_validite==null || s_version==null || encoding==null) {
            throw new NoSuchFieldException();
        }
        
        port=Integer.valueOf(s_port);
        version=Integer.valueOf(s_version);
        validite=Long.valueOf(s_validite);
    }
    public Properties getConfig() {
        return config;
    }
    public String getAlgorithm() {
        return algorithm;
    }

    public String getDIRECTORY() {
        return DIRECTORY;
    }

    public String getCONFIG_FILE() {
        return CONFIG_FILE;
    }

}
