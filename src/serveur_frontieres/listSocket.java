/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package serveur_frontieres;

import java.net.Socket;
import java.util.LinkedList;

/**
 *
 * @author fredm
 */
public class listSocket {
    private LinkedList socketList;
    
    public listSocket()
    {
        socketList = new LinkedList();
    }
    public synchronized void setSocket(Socket s)
    {
        socketList.addLast(s);
        notify();
    }
    public synchronized Socket getSocket() throws InterruptedException
    {
        
        while(isEmpty())
        {
            wait();
        }
        return (Socket) socketList.remove();
    }
    public synchronized Boolean isEmpty()
    {
        if(socketList.isEmpty())
        {
            return true;
        }
        return false;
    }
}
