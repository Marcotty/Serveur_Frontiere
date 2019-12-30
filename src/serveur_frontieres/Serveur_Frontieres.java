/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package serveur_frontieres;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author fredm
 */
public class Serveur_Frontieres {

    /**
     * @param args the command line arguments
     */
    public Serveur_Frontieres()
    {
        ThreadServeur serv = new ThreadServeur();
        serv.start();
                
    }
    public static void main(String[] args) {
        // TODO code application logic here
        
        Serveur_Frontieres serveur = new Serveur_Frontieres();
        
        
    }
    
    
}
