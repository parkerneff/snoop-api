package com.parkerneff.snoopapi;

import lombok.Getter;


public class Greeting {

    @Getter  private final long id;
    @Getter  private final String content;

    public Greeting(long id, String content) {
        this.id = id;
        this.content = content;
    }


}
