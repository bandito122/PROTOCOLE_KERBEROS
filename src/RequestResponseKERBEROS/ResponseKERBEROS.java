/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package RequestResponseKERBEROS;

import java.io.Serializable;

/**
 *
 * @author Bob
 */
public class ResponseKERBEROS implements IKERBEROS, Serializable{
    
    private int     codeRetour;
    private Object  chargeUtile;

    public ResponseKERBEROS() {
    }

    public ResponseKERBEROS(int codeRetour, Object chargeUtile) {
        this.codeRetour = codeRetour;
        this.chargeUtile = chargeUtile;
    }

    public Object getChargeUtile() {
        return chargeUtile;
    }

    public void setChargeUtile(Object chargeUtile) {
        this.chargeUtile = chargeUtile;
    }

    public int getCodeRetour() {
        return codeRetour;
    }

    public void setCodeRetour(int codeRetour) {
        this.codeRetour = codeRetour;
    }
}
