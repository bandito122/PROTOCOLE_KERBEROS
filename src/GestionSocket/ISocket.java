/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package GestionSocket;

import javax.crypto.SecretKey;

/**
 *
 * @author Bob
 */
public interface ISocket 
{
    
    public void ConnectServeur(String machine, int port);
    public void Send(Object req);       
    public Object Receive();
    public void Close();
}
