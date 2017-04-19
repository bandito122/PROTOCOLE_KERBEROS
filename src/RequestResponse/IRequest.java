/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package RequestResponse;

import GestionSocket.ISocket;

/**
 *
 * @author Bob
 */
public interface IRequest 
{
    
    public boolean executeRequest(ISocket Socket, ConsoleServeur guiApplicaiton);
    public int  getType();
    public void setType(int type);
    public Object getChargeUtile();
    public void setChargeUtile(Object obj);
}
