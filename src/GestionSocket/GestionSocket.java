/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package GestionSocket;

import RequestResponseKERBEROS.RequestKERBEROS;
import java.io.*;
import java.net.*;
import javax.crypto.SecretKey;

/**
 *
 * @author Bob
 */
public class GestionSocket implements ISocket
{
    private Socket CSocket = null;
    private ObjectOutputStream oos = null; 
    private ObjectInputStream ois = null;

    public GestionSocket(){
        
    }

    public Socket getCSocket() {
        return CSocket;
    }
    
    public GestionSocket(Socket CSocket) {
        this.CSocket = CSocket;
        try{
            this.oos = new ObjectOutputStream(CSocket.getOutputStream());
            this.oos.flush();
            this.ois = new ObjectInputStream(CSocket.getInputStream());
         }
        catch (IOException ex) { System.err.println("Erreur ! Pas de connexion ? [" + ex + "]"); }
    }
    
    @Override
    public void ConnectServeur(String machine, int port){
        try{
            CSocket = new Socket(machine, port);   
            if(CSocket != null)
            {
                System.out.println(CSocket.getInetAddress().toString());
                this.oos = new ObjectOutputStream(CSocket.getOutputStream()); 
                oos.flush();
                this.ois = new ObjectInputStream(CSocket.getInputStream());           
                System.out.println("Connexion etablie!");
            }
        }
        catch (IOException ex) { System.err.println("Erreur ! Pas de connexion ? [" + ex + "]"); }
    }

    @Override
    public void Send(Object req)
    {
        try {
            oos.writeObject(req);
            oos.flush();
        } 
        catch (IOException ex) { System.err.println("Erreur d'I/O [ " + ex + "]"); }
    }
    
    @Override
    public Object Receive(){
        Object req = null;
        try{
            req = ois.readObject();
        }
        catch (IOException ex) { System.err.println("Erreur d'I/O [ " + ex + "]"); }
        catch (ClassNotFoundException ex) { System.err.println("Erreur ! Classe [" + ex + "] introuvable"); }
        
        return req;
    }
    
    @Override
    public void Close(){
        try {
            CSocket.close();
            oos.close();
            ois.close();
        } catch (IOException ex) { System.err.println("Erreur d'I/O [ " + ex + "]"); }
    }
}
