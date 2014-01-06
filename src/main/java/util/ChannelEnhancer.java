package util;

import java.io.*;

abstract class ChannelEnhancer implements Channel {
    protected Channel Channel;
    
    public ChannelEnhancer(Channel Channel) {
        this.Channel = Channel;
    }

    public Object read() throws IOException, ClassNotFoundException {
        return Channel.read();
    }

    public void write(Object o) throws IOException {
        Channel.write(o);
    }

    public Channel degrade() {
        return Channel;
    }
}