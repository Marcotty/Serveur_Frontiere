/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package serveur_frontieres;

import database.MyInstruction;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.LinkedList;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;
/**
 *
 * @author fredm
 */
public class ThreadServeur extends Thread{
    private Properties PropsServer;
    private listSocket listSocket;
    private MyInstruction sgbd;
    public ThreadServeur()
    {
        
    }
    public void run()
    {
        if(LoadConfig())
        {
            System.out.println("SERVEUR_FRONTIERES | START");
            ConnexionDB_REGNAT();
            System.out.println(PropsServer);
            ServerSocket sSocket = null;
            Socket cSocket = null;
            try 
            {
                sSocket = new ServerSocket(Integer.parseInt(PropsServer.getProperty("PORT_FRONTIERES", "50051")));
            } 
            catch (IOException ex) 
            {
                System.out.println("SERVEUR_FRONTIERES | EXCEPTION CREATION SOCKET");
                ex.printStackTrace();
                System.exit(1);
            }
            listSocket = new listSocket();
            for(int i=0; i< Integer.parseInt(PropsServer.getProperty("MAX_CLIENTS", "3")); i++)
            {
                ThreadClient client = new ThreadClient(cSocket, PropsServer, listSocket, sgbd);
                client.start();
            }
            System.out.println("SERVEUR_FRONTIERES | WAIT CLIENT");
            while(!isInterrupted())
            {
                try 
                {
                    cSocket = sSocket.accept();
                    listSocket.setSocket(cSocket);
                    
                } catch (IOException ex) {
                    System.out.println("SERVEUR_FRONTIERES | EXCEPTION ACCEPT SOCKET");
                    ex.printStackTrace();
                }
            }
        }
    }
    private void ConnexionDB_REGNAT() {
        boolean erreur = false;
        sgbd = new MyInstruction();
        try {
            Class.forName("com.mysql.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            System.out.println(e);
            JOptionPane.showMessageDialog(null, "DB_REGNAT : driver introuvable", "Erreur", JOptionPane.ERROR_MESSAGE);
            erreur = true;
        }

        if (!erreur) {
            System.out.println("SERVEUR_FRONTIERES | DB_REGNAT OK");
            sgbd.setAdresse("jdbc:mysql://localhost:3306/bd_regnat");
            sgbd.setLogin("root");
            sgbd.setPassword("root");
            try {
                sgbd.Connexion();
            } catch (SQLException e) {
                JOptionPane.showMessageDialog(null, "Serveur_Card : connexion à la BD impossible", "Erreur", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    private Boolean LoadConfig() {
        System.out.println("SERVEUR_FRONTIERES | LOAD CONFIG:");
        try
        {
            InputStream input = new FileInputStream("config.properties");
            PropsServer = new Properties();
            
            PropsServer.load(input);
            
            return true;
        }
        catch(IOException e)
        {
            System.out.println(e);
        }
        return false;
    }
}
