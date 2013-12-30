package util;

import java.io.*;

public interface Channel {
    public Object read() throws IOException, ClassNotFoundException;
    public void write(Object o) throws IOException;
}