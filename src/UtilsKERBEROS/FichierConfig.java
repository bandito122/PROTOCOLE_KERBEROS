/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package UtilsKERBEROS;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

/**
 *
 * @author Bob
 */
public class FichierConfig {
    
    static Properties propConfig;

    static{
        propConfig = new Properties();
        try
        {
            propConfig.load(new FileInputStream(getNomFichierConfig()));
        }
        catch (FileNotFoundException e) { System.out.println("Fichier de propriétés non trouvé !");}
        catch (IOException e) { System.out.println("Aie : " + e.getMessage()); }
    }

    /**
     *
     * @param key
     * @return
     */
    public static String getProperty(String key){
        return propConfig.getProperty(key);
    }

    /**
     *
     * @return
     */
    public static String getUserdir()
    {
        return System.getProperty("user.dir") + System.getProperty("file.separator")
                + "src" + System.getProperty("file.separator")
                + "Utils" + System.getProperty("file.separator");
    }
    /**
     *
     * @return
     */
    public static String getNomFichierConfig()
    {
       String nomFichier = getUserdir()+ "config.properties";
        System.out.println("CHEMIN FICHIER = " + nomFichier);
       return nomFichier;
    }
}
