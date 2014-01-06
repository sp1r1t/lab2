package util;

import java.io.*;

public class TCPChannel implements Channel {
    protected ObjectInputStream ois;
    protected ObjectOutputStream oos;

    public TCPChannel(ObjectInputStream ois, ObjectOutputStream oos) {
        System.out.println("creating channel"); 
        this.ois = ois;
        this.oos = oos;
    }

    public Object read() throws IOException, ClassNotFoundException {
        return ois.readObject();
    }

    public void write(Object o) throws IOException {
        oos.writeObject(o);
    }

    public Channel degrade() {
        return this;
    }

}